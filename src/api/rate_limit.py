"""
Token-Bucket Rate Limiter and constant-time API Key authentication for CodeSentinel FastAPI.

Protects public scan endpoints from abuse with per-client token buckets
and standard HTTP 429 / Retry-After responses.
"""

from __future__ import annotations

import hmac
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from fastapi import Header, HTTPException, Request, status


@dataclass
class _BucketState:
    tokens: float
    last_refill: float


class TokenBucketLimiter:
    """Thread-safe in-memory per-client token-bucket rate limiter."""

    def __init__(self, capacity: int = 30, refill_per_sec: float = 0.5) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._buckets: Dict[str, _BucketState] = {}

    def allow(self, client_key: str, cost: float = 1.0, now: Optional[float] = None) -> Tuple[bool, int, float]:
        """
        Consume `cost` tokens for `client_key`.
        Returns (allowed, remaining_int, retry_after_seconds).
        """
        ts = time.monotonic() if now is None else now
        state = self._buckets.get(client_key)
        if state is None:
            state = _BucketState(tokens=self.capacity, last_refill=ts)
            self._buckets[client_key] = state
        else:
            elapsed = max(0.0, ts - state.last_refill)
            state.tokens = min(self.capacity, state.tokens + elapsed * self.refill_per_sec)
            state.last_refill = ts

        if state.tokens >= cost:
            state.tokens -= cost
            return True, int(state.tokens), 0.0

        deficit = cost - state.tokens
        retry_after = round(deficit / max(self.refill_per_sec, 1e-6), 2)
        return False, 0, retry_after

    def reset(self) -> None:
        self._buckets.clear()


default_rate_limiter = TokenBucketLimiter(capacity=30, refill_per_sec=0.5)


async def enforce_rate_limit(request: Request) -> None:
    """FastAPI dependency enforcing token-bucket quotas per client IP or API key."""
    client_key = request.headers.get("X-API-Key") or (request.client.host if request.client else "anonymous")
    allowed, _remaining, retry_after = default_rate_limiter.allow(client_key)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )


async def verify_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> None:
    """
    FastAPI dependency verifying X-API-Key when CODESENTINEL_API_KEY is configured.
    Uses constant-time hmac.compare_digest to prevent timing attacks.
    """
    expected = os.getenv("CODESENTINEL_API_KEY", "").strip()
    if not expected:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key.strip(), expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )
