"""
GitHub Webhook receiver endpoint.
Validates HMAC SHA-256 signatures and enqueues PR analysis tasks to Redis/ARQ.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from src.config import get_settings

logger = logging.getLogger("codesentinel.api.webhooks")
router = APIRouter(prefix="/webhook", tags=["Webhooks"])


class WebhookResponse(BaseModel):
    status: str = Field(..., description="Status of the webhook request (queued, pong, ignored)")
    job_id: Optional[str] = Field(default=None, description="Enqueued background job ID if applicable")
    repository: Optional[str] = Field(default=None, description="Full repository name (owner/repo)")
    pr_number: Optional[int] = Field(default=None, description="Pull Request number")
    action: Optional[str] = Field(default=None, description="Triggered PR action")
    reason: Optional[str] = Field(default=None, description="Explanation when an event is ignored")


def verify_github_signature(payload_body: bytes, signature_header: Optional[str], secret: str) -> bool:
    """
    Validates HMAC SHA-256 signature from GitHub 'X-Hub-Signature-256' header.
    Uses constant-time comparison to protect against timing attacks.
    """
    if not secret:
        # In development if no secret is set, log warning and allow
        logger.warning("GITHUB_WEBHOOK_SECRET is not configured. Skipping signature verification.")
        return True

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_sig = signature_header[7:]
    computed_sig = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload_body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(computed_sig, expected_sig)


@router.post(
    "/github",
    response_model=WebhookResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="GitHub Webhook Listener",
    description="Receives GitHub webhook events, verifies HMAC signature, and pushes PR events to Redis queue.",
)
async def github_webhook_endpoint(
    request: Request,
    response: Response,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_github_delivery: Optional[str] = Header(None, alias="X-GitHub-Delivery"),
) -> WebhookResponse:
    settings = get_settings()

    # Step 1: Read raw body bytes for cryptographic HMAC verification
    body_bytes = await request.body()

    if not verify_github_signature(body_bytes, x_hub_signature_256, settings.GITHUB_WEBHOOK_SECRET):
        logger.error("Unauthorized webhook delivery: invalid HMAC SHA-256 signature (delivery: %s)", x_github_delivery)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid HMAC SHA-256 signature in X-Hub-Signature-256 header",
        )

    # Step 2: Handle GitHub ping event
    if x_github_event == "ping":
        logger.info("Received GitHub ping event (delivery: %s)", x_github_delivery)
        response.status_code = status.HTTP_200_OK
        return WebhookResponse(
            status="pong",
            reason="GitHub webhook connection verified successfully",
        )

    # Step 3: Filter non-PR events
    if x_github_event != "pull_request":
        logger.info("Ignored non-PR event '%s' (delivery: %s)", x_github_event, x_github_delivery)
        response.status_code = status.HTTP_200_OK
        return WebhookResponse(
            status="ignored",
            reason=f"Event '{x_github_event}' is ignored. Only 'pull_request' events are monitored.",
        )

    # Step 4: Parse JSON payload
    try:
        payload: Dict[str, Any] = json.loads(body_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        logger.error("Malformed JSON payload received: %s", exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed JSON payload")

    action = payload.get("action")
    supported_actions = {"opened", "synchronize", "reopened"}

    if action not in supported_actions:
        logger.info("Ignored unmonitored PR action '%s'", action)
        response.status_code = status.HTTP_200_OK
        return WebhookResponse(
            status="ignored",
            action=action,
            reason=f"PR action '{action}' is not monitored. Only {sorted(supported_actions)} are audited.",
        )

    # Step 5: Extract PR metadata
    repo_data = payload.get("repository", {})
    pr_data = payload.get("pull_request", {})
    repo_full_name = repo_data.get("full_name", "")
    pr_number = pr_data.get("number", 0)
    pr_title = pr_data.get("title", "")
    head_sha = pr_data.get("head", {}).get("sha", "")
    base_sha = pr_data.get("base", {}).get("sha", "")
    sender = payload.get("sender", {}).get("login", "")

    task_payload = {
        "repo_name": repo_full_name,
        "pr_number": pr_number,
        "pr_title": pr_title,
        "action": action,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "sender": sender,
        "delivery_id": x_github_delivery,
    }

    # Step 6: Enqueue to Redis queue via ARQ pool
    arq_pool = getattr(request.app.state, "arq_pool", None)
    job_id: Optional[str] = None

    if arq_pool is not None:
        try:
            job = await arq_pool.enqueue_job("analyze_pr_task", task_payload)
            job_id = job.job_id if job else None
            logger.info("Enqueued PR analysis job %s for %s #%d", job_id, repo_full_name, pr_number)
        except Exception as exc:
            logger.error("Failed to enqueue job into Redis: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Redis queue temporarily unavailable: {exc}",
            )
    else:
        logger.warning("No active ARQ Redis pool attached to application state. Running in decoupled mode.")
        job_id = "local-simulated-job"

    return WebhookResponse(
        status="queued",
        job_id=job_id,
        repository=repo_full_name,
        pr_number=pr_number,
        action=action,
    )
