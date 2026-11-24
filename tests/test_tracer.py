"""Tests for structured SpanTracer and JSONL trace export."""

import json
from pathlib import Path

import pytest

from src.observability.tracer import TraceContext


def test_trace_context_records_spans_and_exports_jsonl(tmp_path: Path):
    trace_file = tmp_path / "traces.jsonl"
    tracer = TraceContext(trace_id="trace-demo-01", jsonl_path=trace_file)

    with tracer.span("ast_scan", file="app.py") as attrs:
        attrs["findings"] = 2

    with pytest.raises(RuntimeError):
        with tracer.span("llm_judge"):
            raise RuntimeError("mock timeout")

    summary = tracer.summary()
    assert summary["trace_id"] == "trace-demo-01"
    assert summary["span_count"] == 2
    assert summary["errors"] == 1
    assert summary["spans"][0]["attributes"]["findings"] == 2
    assert summary["spans"][1]["status"] == "error"

    lines = [json.loads(line) for line in trace_file.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2
    assert lines[0]["name"] == "ast_scan"
