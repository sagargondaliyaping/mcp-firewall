"""Bearer token validation helpers for HTTP transport."""

from __future__ import annotations

import base64
import json
from typing import Any


class TokenValidationError(ValueError):
    """Raised when a bearer token fails validation."""


def validate_bearer_token(
    authorization: str | None,
    *,
    allowed_audiences: list[str],
    required_issuer: str | None = None,
) -> dict[str, Any]:
    """Validate a bearer token and return decoded claims."""
    if not authorization:
        raise TokenValidationError("missing bearer token")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise TokenValidationError("invalid authorization header")

    claims = decode_jwt_payload(token)
    audience = claims.get("aud")
    if isinstance(audience, str):
        audiences = [audience]
    elif isinstance(audience, list):
        audiences = [str(a) for a in audience]
    else:
        audiences = []

    if not any(aud in allowed_audiences for aud in audiences):
        raise TokenValidationError("invalid audience")

    if required_issuer and claims.get("iss") != required_issuer:
        raise TokenValidationError("invalid issuer")

    return claims


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode a JWT payload without signature verification."""
    parts = token.split(".")
    if len(parts) < 2:
        raise TokenValidationError("malformed token")

    payload = parts[1]
    padded = payload + "=" * ((4 - len(payload) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode())
        data = json.loads(decoded)
    except Exception as exc:  # pragma: no cover - defensive
        raise TokenValidationError("malformed token") from exc

    if not isinstance(data, dict):
        raise TokenValidationError("malformed token")
    return data
