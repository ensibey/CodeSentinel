"""Tests for FastAPI SSE streaming scan endpoint with rate limiting and API key auth."""

from fastapi.testclient import TestClient

from src.api.main import create_app
from src.api.rate_limit import default_rate_limiter


def test_sse_stream_emits_findings_and_trace_summary(monkeypatch):
    default_rate_limiter.reset()
    monkeypatch.setenv("CODESENTINEL_API_KEY", "test-stream-key")

    app = create_app()
    client = TestClient(app)

    # Missing key -> 401
    unauth = client.post("/api/v1/scan/stream", json={"file_path": "a.py", "source_code": "eval(x)"})
    assert unauth.status_code == 401

    # Valid key -> SSE stream with trace_start, finding, and summary events
    resp = client.post(
        "/api/v1/scan/stream",
        headers={"X-API-Key": "test-stream-key"},
        json={"file_path": "vuln.py", "source_code": "eval(user_input)\n"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    body = resp.text
    assert "event: trace_start" in body
    assert "event: finding" in body
    assert "CS003" in body
    assert "event: summary" in body
    assert "total_duration_ms" in body
