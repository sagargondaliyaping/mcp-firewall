"""Shared multi-MCP daemon/connect transport."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console

from ..dashboard.app import state as dashboard_state
from ..dashboard.events import build_dashboard_event
from ..models import Action, GatewayConfig, ToolCallRequest, ToolCallResponse
from ..pipeline.runner import PipelineRunner


def build_connect_handshake(server_id: str, server_command: list[str]) -> dict[str, Any]:
    """Build handshake payload for daemon connector sessions."""
    return {
        "type": "connect",
        "server_id": server_id,
        "server_command": server_command,
    }


def parse_host_port(value: str) -> tuple[str, int]:
    host, sep, port_s = value.rpartition(":")
    if not sep:
        raise ValueError(f"Invalid host:port value: {value}")
    return host or "127.0.0.1", int(port_s)


@dataclass
class _SessionContext:
    server_id: str
    server_command: list[str]
    request_tools: dict[str, str]


class _SharedProxySession:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        pipeline: PipelineRunner,
        console: Console,
        context: _SessionContext,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.pipeline = pipeline
        self.console = console
        self.context = context
        self._server_proc: asyncio.subprocess.Process | None = None

    async def run(self) -> None:
        self._server_proc = await asyncio.create_subprocess_exec(
            *self.context.server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        tasks = [
            asyncio.create_task(self._proxy_client_to_server()),
            asyncio.create_task(self._proxy_server_to_client()),
            asyncio.create_task(self._forward_server_stderr()),
        ]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                _ = task.result()
        finally:
            await self._shutdown()

    async def _shutdown(self) -> None:
        if self._server_proc and self._server_proc.returncode is None:
            self._server_proc.terminate()
            await self._server_proc.wait()
        if not self.writer.is_closing():
            self.writer.close()
            await self.writer.wait_closed()

    async def _proxy_client_to_server(self) -> None:
        assert self._server_proc and self._server_proc.stdin
        buffer = b""
        while True:
            chunk = await self.reader.read(8192)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                forwarded = await self._intercept_request(line)
                if forwarded is not None:
                    self._server_proc.stdin.write(forwarded + b"\n")
                    await self._server_proc.stdin.drain()

    async def _proxy_server_to_client(self) -> None:
        assert self._server_proc and self._server_proc.stdout
        buffer = b""
        while True:
            chunk = await self._server_proc.stdout.read(8192)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                message = await self._intercept_response(line)
                self.writer.write(message + b"\n")
                await self.writer.drain()

    async def _forward_server_stderr(self) -> None:
        assert self._server_proc and self._server_proc.stderr
        while True:
            line = await self._server_proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    async def _intercept_request(self, raw: bytes) -> bytes | None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return raw

        if msg.get("method") != "tools/call":
            return raw

        params = msg.get("params", {})
        request_id = str(msg.get("id", ""))
        request = ToolCallRequest(
            id=request_id,
            tool_name=params.get("name", ""),
            arguments=params.get("arguments", {}),
            agent_id=self.context.server_id,
        )
        self.context.request_tools[request_id] = request.tool_name

        decision = self.pipeline.evaluate_inbound(request)
        if decision and decision.action == Action.DENY:
            dashboard_state.add_event(
                build_dashboard_event(
                    action="deny",
                    tool=request.tool_name,
                    agent=request.agent_id,
                    reason=decision.reason,
                    severity=decision.severity.value,
                    stage=decision.stage.value if decision.stage else None,
                    timestamp=request.timestamp,
                    findings=self.pipeline.decision_findings(decision),
                    correlation_id=request.id,
                    target_hostname=str((decision.details or {}).get("host", "")),
                    server_id=self.context.server_id,
                )
            )
            blocked = {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "result": {
                    "content": [{"type": "text", "text": f"[mcp-firewall] Blocked: {decision.reason}"}],
                    "isError": True,
                },
            }
            self.writer.write(json.dumps(blocked).encode() + b"\n")
            await self.writer.drain()
            return None

        if decision and decision.action == Action.PROMPT:
            dashboard_state.add_event(
                build_dashboard_event(
                    action="prompt",
                    tool=request.tool_name,
                    agent=request.agent_id,
                    reason=decision.reason,
                    severity=decision.severity.value,
                    stage=decision.stage.value if decision.stage else None,
                    timestamp=request.timestamp,
                    findings=self.pipeline.decision_findings(decision),
                    correlation_id=request.id,
                    server_id=self.context.server_id,
                )
            )

        dashboard_state.add_event(
            build_dashboard_event(
                action="allow",
                tool=request.tool_name,
                agent=request.agent_id,
                reason="",
                severity="info",
                timestamp=request.timestamp,
                correlation_id=request.id,
                server_id=self.context.server_id,
            )
        )
        return raw

    async def _intercept_response(self, raw: bytes) -> bytes:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return raw

        result = msg.get("result")
        if not result or "content" not in result:
            return raw

        request_id = str(msg.get("id", ""))
        tool_name = self.context.request_tools.get(request_id, "(response scan)")
        response = ToolCallResponse(
            request_id=request_id,
            content=result.get("content", []),
            is_error=result.get("isError", False),
        )
        dummy_request = ToolCallRequest(id=request_id, tool_name=tool_name, agent_id=self.context.server_id)
        response, decisions = self.pipeline.scan_outbound(dummy_request, response)

        for decision in decisions:
            dashboard_state.add_event(
                build_dashboard_event(
                    action=decision.action.value,
                    tool=dummy_request.tool_name,
                    agent=dummy_request.agent_id,
                    reason=decision.reason,
                    severity=decision.severity.value,
                    stage=decision.stage.value if decision.stage else None,
                    timestamp=response.timestamp,
                    findings=self.pipeline.decision_findings(decision),
                    correlation_id=dummy_request.id,
                    server_id=self.context.server_id,
                )
            )
            if decision.action == Action.DENY:
                msg["result"]["content"] = [
                    {"type": "text", "text": f"[mcp-firewall] Response blocked: {decision.reason}"}
                ]
                msg["result"]["isError"] = True
                return json.dumps(msg).encode()
            if decision.action == Action.REDACT:
                msg["result"]["content"] = response.content
                return json.dumps(msg).encode()

        return raw


class SharedFirewallDaemon:
    """Central daemon to host shared firewall state for multiple MCP backends."""

    def __init__(self, config: GatewayConfig, console: Console | None = None) -> None:
        self.config = config
        self.console = console or Console(stderr=True)
        self.pipeline = PipelineRunner(config)
        self._servers: list[asyncio.AbstractServer] = []

    async def run(self, listen_unix: str | None, listen_tcp: str | None) -> None:
        if not listen_unix and not listen_tcp:
            raise ValueError("At least one listener must be provided.")

        if listen_unix:
            unix_path = Path(listen_unix).expanduser()
            unix_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.unlink(unix_path)
            except FileNotFoundError:
                pass
            self._servers.append(await asyncio.start_unix_server(self._handle_client, path=str(unix_path)))
            self.console.print(f"[green]daemon unix:[/green] {unix_path}")

        if listen_tcp:
            host, port = parse_host_port(listen_tcp)
            self._servers.append(await asyncio.start_server(self._handle_client, host=host, port=port))
            self.console.print(f"[green]daemon tcp:[/green] {host}:{port}")

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)

        await stop.wait()
        await self.stop()

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = await reader.readline()
        if not line:
            writer.close()
            await writer.wait_closed()
            return
        try:
            handshake = json.loads(line.decode().strip())
        except json.JSONDecodeError:
            writer.close()
            await writer.wait_closed()
            return

        if handshake.get("type") != "connect":
            writer.close()
            await writer.wait_closed()
            return

        server_id = str(handshake.get("server_id", "default"))
        server_command = [str(x) for x in handshake.get("server_command", [])]
        if not server_command:
            writer.close()
            await writer.wait_closed()
            return

        session = _SharedProxySession(
            reader=reader,
            writer=writer,
            pipeline=self.pipeline,
            console=self.console,
            context=_SessionContext(server_id=server_id, server_command=server_command, request_tools={}),
        )
        await session.run()


async def run_connector(
    *,
    server_id: str,
    server_command: list[str],
    daemon_unix: str | None = None,
    daemon_tcp: str | None = None,
) -> int:
    """Connect current stdio MCP session to shared daemon."""
    if daemon_unix:
        reader, writer = await asyncio.open_unix_connection(path=str(Path(daemon_unix).expanduser()))
    elif daemon_tcp:
        host, port = parse_host_port(daemon_tcp)
        reader, writer = await asyncio.open_connection(host, port)
    else:
        raise ValueError("Provide daemon_unix or daemon_tcp.")

    writer.write((json.dumps(build_connect_handshake(server_id, server_command)) + "\n").encode())
    await writer.drain()

    stdin_reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(stdin_reader)
    await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    async def stdin_to_daemon() -> None:
        while True:
            chunk = await stdin_reader.read(8192)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
        writer.write_eof()

    async def daemon_to_stdout() -> None:
        stdout = sys.stdout.buffer
        while True:
            chunk = await reader.read(8192)
            if not chunk:
                break
            stdout.write(chunk)
            stdout.flush()

    t1 = asyncio.create_task(stdin_to_daemon())
    t2 = asyncio.create_task(daemon_to_stdout())
    done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    for task in done:
        _ = task.result()
    writer.close()
    await writer.wait_closed()
    return 0
