"""
Lightweight OpenTelemetry-compatible structured span tracer for CodeSentinel.

Records per-stage latency, token counts, and metadata across AST scanning,
LangGraph agent nodes, and API requests. Emits structured JSONL trace logs
for ingestion into Phoenix, LangSmith, or Grafana Loki without requiring
external SaaS keys during local/CI execution.
"""

from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


@dataclass
class SpanRecord:
    trace_id: str
    span_id: str
    name: str
    started_at: float
    duration_ms: float
    status: str = "ok"
    attributes: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class TraceContext:
    """Collects timed spans for a single scan or multi-agent workflow execution."""

    def __init__(self, trace_id: Optional[str] = None, jsonl_path: Optional[Path] = None) -> None:
        self.trace_id = trace_id or uuid.uuid4().hex[:16]
        self.jsonl_path = jsonl_path
        self.spans: List[SpanRecord] = []

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[Dict[str, Any]]:
        span_id = uuid.uuid4().hex[:12]
        start_wall = time.time()
        t0 = time.perf_counter()
        attrs: Dict[str, Any] = dict(attributes)
        status = "ok"
        err_msg: Optional[str] = None
        try:
            yield attrs
        except Exception as exc:
            status = "error"
            err_msg = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            rec = SpanRecord(
                trace_id=self.trace_id,
                span_id=span_id,
                name=name,
                started_at=round(start_wall, 3),
                duration_ms=elapsed_ms,
                status=status,
                attributes=attrs,
                error=err_msg,
            )
            self.spans.append(rec)
            if self.jsonl_path is not None:
                self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
                with self.jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(asdict(rec)) + "\n")

    def summary(self) -> Dict[str, Any]:
        total_ms = round(sum(s.duration_ms for s in self.spans), 3)
        return {
            "trace_id": self.trace_id,
            "span_count": len(self.spans),
            "total_duration_ms": total_ms,
            "errors": sum(1 for s in self.spans if s.status == "error"),
            "spans": [asdict(s) for s in self.spans],
        }
