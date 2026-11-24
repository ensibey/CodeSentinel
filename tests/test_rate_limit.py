"""Tests for Token-Bucket Rate Limiter and X-API-Key authentication."""

import pytest
from fastapi import HTTPException

from src.api.rate_limit import TokenBucketLimiter, verify_api_key


def test_token_bucket_allows_burst_then_throttles_and_refills():
    limiter = TokenBucketLimiter(capacity=3, refill_per_sec=1.0)

    assert limiter.allow("client-a", now=0.0)[0] is True
    assert limiter.allow("client-a", now=0.0)[0] is True
    assert limiter.allow("client-a", now=0.0)[0] is True

    allowed, remaining, retry_after = limiter.allow("client-a", now=0.0)
    assert allowed is False
    assert remaining == 0
    assert retry_after == 1.0

    # After 1.5 seconds, 1.5 tokens refilled -> allowed again
    assert limiter.allow("client-a", now=1.5)[0] is True


@pytest.mark.asyncio
async def test_verify_api_key_enforces_env_secret(monkeypatch):
    monkeypatch.setenv("CODESENTINEL_API_KEY", "prod-secret-token")

    await verify_api_key(x_api_key="prod-secret-token")

    with pytest.raises(HTTPException) as exc:
        await verify_api_key(x_api_key="wrong-key")
    assert exc.value.status_code == 401
