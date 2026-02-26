"""JWKS cache scaffold for future signature-verified token validation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class JWKSCache:
    """In-memory JWKS cache placeholder."""

    ttl_seconds: int = 300
    _jwks: dict[str, Any] = field(default_factory=dict)
    _updated_at: float = 0.0

    def get(self) -> dict[str, Any] | None:
        if not self._jwks:
            return None
        if (time.time() - self._updated_at) > self.ttl_seconds:
            return None
        return self._jwks

    def set(self, jwks: dict[str, Any]) -> None:
        self._jwks = jwks
        self._updated_at = time.time()
