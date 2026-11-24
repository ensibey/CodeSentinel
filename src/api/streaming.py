"""
Async Server-Sent Events (SSE) streaming security audit endpoint for CodeSentinel.

Streams real-time vulnerability findings and OpenTelemetry-compatible trace spans
over `text/event-stream` with Token-Bucket rate limiting and X-API-Key authentication.
"""

from __future__ import annotations

import json
from typing import AsyncGenerator

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from src.agents.ast_scanner import ASTScanner
from src.agents.rule_registry import resolve_rule_for_category
from src.api.rate_limit import enforce_rate_limit, verify_api_key
from src.observability.tracer import TraceContext

router = APIRouter(prefix="/api/v1", tags=["Streaming Security Audit"])


class ScanStreamRequest(BaseModel):
    file_path: str = Field(default="snippet.py", description="Logical file name for reporting")
    source_code: str = Field(..., min_length=1, description="Python source code to audit")


def _sse_frame(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


@router.post(
    "/scan/stream",
    summary="Stream AST security findings and trace telemetry via SSE",
    dependencies=[Depends(verify_api_key), Depends(enforce_rate_limit)],
)
async def stream_security_scan(body: ScanStreamRequest) -> StreamingResponse:
    async def _event_generator() -> AsyncGenerator[str, None]:
        tracer = TraceContext()
        yield _sse_frame("trace_start", {"trace_id": tracer.trace_id, "file_path": body.file_path})

        with tracer.span("ast_scan", file_path=body.file_path) as span_attrs:
            findings = ASTScanner.scan_code(body.source_code, file_path=body.file_path)
            span_attrs["finding_count"] = len(findings)

        for idx, vuln in enumerate(findings, start=1):
            rule = resolve_rule_for_category(vuln.category)
            yield _sse_frame(
                "finding",
                {
                    "index": idx,
                    "rule_id": rule.rule_id if rule else "CS000",
                    "owasp_2021": rule.owasp_2021 if rule else "",
                    **vuln.model_dump(),
                },
            )

        yield _sse_frame(
            "summary",
            {
                "total_findings": len(findings),
                "trace": tracer.summary(),
            },
        )

    return StreamingResponse(_event_generator(), media_type="text/event-stream")
