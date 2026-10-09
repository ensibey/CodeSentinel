"""
Unit and integration tests for GitHub Webhook listener and signature verification.
"""

from __future__ import annotations
import json
import pytest
from httpx import AsyncClient

from src.api.webhooks import verify_github_signature


def test_verify_github_signature_valid(test_secret: str, make_signature):
    """Test HMAC validation passes for correctly signed payload."""
    payload = b'{"hello": "world"}'
    sig = make_signature(payload, test_secret)
    assert verify_github_signature(payload, sig, test_secret) is True


def test_verify_github_signature_invalid(test_secret: str, make_signature):
    """Test HMAC validation rejects tampered signature."""
    payload = b'{"hello": "world"}'
    tampered_sig = "sha256=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    assert verify_github_signature(payload, tampered_sig, test_secret) is False


def test_verify_github_signature_missing_header(test_secret: str):
    """Test HMAC validation rejects missing signature header."""
    payload = b'{"hello": "world"}'
    assert verify_github_signature(payload, None, test_secret) is False
    assert verify_github_signature(payload, "", test_secret) is False


def test_verify_github_signature_empty_secret():
    """Test HMAC validation allows requests in dev mode if secret is blank."""
    payload = b'{"hello": "world"}'
    assert verify_github_signature(payload, None, "") is True


@pytest.mark.asyncio
async def test_webhook_ping_event(async_client: AsyncClient, test_secret: str, make_signature):
    """GitHub webhook 'ping' event should respond with 200 and pong."""
    payload = json.dumps({"zen": "Favor focus over features.", "hook_id": 123}).encode("utf-8")
    signature = make_signature(payload, test_secret)

    response = await async_client.post(
        "/webhook/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": signature,
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "delivery-ping-uuid-1",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pong"


@pytest.mark.asyncio
async def test_webhook_invalid_signature_rejected(async_client: AsyncClient, sample_pr_payload: dict):
    """Requests with forged or incorrect HMAC signatures should be rejected with 401."""
    payload = json.dumps(sample_pr_payload).encode("utf-8")
    invalid_sig = "sha256=wrongsignaturewrongsignaturewrongsignaturewrongsignaturewrong"

    response = await async_client.post(
        "/webhook/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": invalid_sig,
            "X-GitHub-Event": "pull_request",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 401
    assert "Invalid HMAC SHA-256 signature" in response.json()["detail"]


@pytest.mark.asyncio
async def test_webhook_non_pr_event_ignored(async_client: AsyncClient, test_secret: str, make_signature):
    """Non-PR GitHub events (e.g. issues, push) should be acknowledged and cleanly ignored."""
    payload = json.dumps({"action": "created", "issue": {"number": 1}}).encode("utf-8")
    signature = make_signature(payload, test_secret)

    response = await async_client.post(
        "/webhook/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": signature,
            "X-GitHub-Event": "issues",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ignored"
    assert "Only 'pull_request' events are monitored" in data["reason"]


@pytest.mark.asyncio
async def test_webhook_unmonitored_pr_action_ignored(
    async_client: AsyncClient,
    sample_pr_payload: dict,
    test_secret: str,
    make_signature,
):
    """PR actions that don't change code (e.g., closed, labeled) should be ignored."""
    sample_pr_payload["action"] = "closed"
    payload = json.dumps(sample_pr_payload).encode("utf-8")
    signature = make_signature(payload, test_secret)

    response = await async_client.post(
        "/webhook/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": signature,
            "X-GitHub-Event": "pull_request",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ignored"
    assert data["action"] == "closed"


@pytest.mark.asyncio
async def test_webhook_pr_opened_queued_successfully(
    async_client: AsyncClient,
    sample_pr_payload: dict,
    test_secret: str,
    make_signature,
    mock_arq_pool,
):
    """PR 'opened' event with valid HMAC should be queued into Redis and return 202 Accepted."""
    payload = json.dumps(sample_pr_payload).encode("utf-8")
    signature = make_signature(payload, test_secret)

    response = await async_client.post(
        "/webhook/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": signature,
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-pr-opened-123",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "queued"
    assert data["job_id"] == "mock-arq-job-12345"
    assert data["repository"] == "octocat/Hello-World"
    assert data["pr_number"] == 42
    assert data["action"] == "opened"

    mock_arq_pool.enqueue_job.assert_awaited_once()


@pytest.mark.asyncio
async def test_webhook_pr_synchronize_queued(
    async_client: AsyncClient,
    sample_pr_payload: dict,
    test_secret: str,
    make_signature,
    mock_arq_pool,
):
    """PR 'synchronize' event (new commit pushed) should be queued for re-analysis."""
    sample_pr_payload["action"] = "synchronize"
    payload = json.dumps(sample_pr_payload).encode("utf-8")
    signature = make_signature(payload, test_secret)

    response = await async_client.post(
        "/webhook/github",
        content=payload,
        headers={
            "X-Hub-Signature-256": signature,
            "X-GitHub-Event": "pull_request",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "queued"
    assert data["action"] == "synchronize"


@pytest.mark.asyncio
async def test_webhook_malformed_json_returns_400(
    async_client: AsyncClient,
    test_secret: str,
    make_signature,
):
    """Corrupted/invalid JSON payload should return 400 Bad Request."""
    bad_payload = b"this is not valid json {"
    signature = make_signature(bad_payload, test_secret)

    response = await async_client.post(
        "/webhook/github",
        content=bad_payload,
        headers={
            "X-Hub-Signature-256": signature,
            "X-GitHub-Event": "pull_request",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400
    assert "Malformed JSON" in response.json()["detail"]


@pytest.mark.asyncio
async def test_health_and_root(async_client: AsyncClient):
    """Root and health endpoints should return operational status."""
    root_res = await async_client.get("/")
    assert root_res.status_code == 200
    assert root_res.json()["name"] == "CodeSentinel"

    health_res = await async_client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "healthy"
    assert health_res.json()["redis_connected"] is True
