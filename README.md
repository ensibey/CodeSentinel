# CodeSentinel

[![CI](https://github.com/ensibey/CodeSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/ensibey/CodeSentinel/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Automated Pull Request security review engine combining deterministic Python AST taint/sink analysis with a cyclical **LangGraph** multi-agent pipeline (`security_scanner` -> `test_generator` -> `patch_creator` -> `judge`).

Designed to run either as a standalone local CLI scanner (`python -m src.cli`) or as an event-driven GitHub Webhook service backed by **FastAPI**, **Celery**, and **Redis**.

---

## Architecture

```text
GitHub Webhook (POST /webhooks/github)           Local CLI (python -m src.cli)
        │                                                      │
        ▼ (HMAC-SHA256 verified, <15ms ACK)                    │
Redis Broker & Celery Worker                                   │
        │                                                      │
        └──────────────────────┬───────────────────────────────┘
                               ▼
            ┌─────────────────────────────────────┐
            │     LangGraph StateGraph Engine     │
            │                                     │
            │  1. security_scanner                │
            │     ├── PythonASTScanner (CWE rules)│
            │     └── LLM diff context analysis   │
            │              │                      │
            │              ▼                      │
            │  2. test_generator                  │
            │     └── Synthesizes pytest cases    │
            │              │                      │
            │              ▼                      │
            │  3. patch_creator  ◄──────────┐     │
            │     └── Unified git diff fix  │     │
            │              │                │     │
            │              ▼                │     │
            │  4. judge                     │     │
            │     └── Checks regressions ───┘     │
            │         (retries up to 3x)          │
            └──────────────────┬──────────────────┘
                               ▼
              GitHubReviewPublisher (PR API)
```

### Why Hybrid AST + LLM Scanning?
Pure LLM code reviewers hallucinate line numbers on large unified diffs and burn tokens on obvious anti-patterns. `PythonASTScanner` (`src/agents/ast_scanner.py`) parses added lines into an Abstract Syntax Tree first and deterministically flags:
- `CWE-78`: `eval()`, `exec()`, `os.system()`, and `subprocess.*(..., shell=True)`
- `CWE-89`: SQL string interpolation (`f"SELECT ... {user}"`, `.format()`, `%`) passed to `.execute()`
- `CWE-502`: Unsafe `pickle.loads()` / `yaml.load()` without `SafeLoader`
- `CWE-327`: Weak cryptographic hashes (`hashlib.md5`, `hashlib.sha1`)
- `CWE-798`: Hardcoded API tokens, private keys, and plaintext passwords

Findings from the AST pass are merged and deduplicated with the LLM's contextual analysis before entering the remediation loop.

### Diff Hunk Boundary Validation (`src/github_client/publisher.py`)
GitHub's Pull Request Review API returns `HTTP 422 Unprocessable Entity` if an inline review comment targets a line number outside the modified diff hunk. `GitHubReviewPublisher` validates every inline comment against parsed hunk coordinates (`GitDiffParser`) and automatically diverts out-of-hunk findings into the main PR review body so no alerts are dropped.

---

## Quickstart

### 1. Local Installation

```bash
git clone https://github.com/ensibey/CodeSentinel.git
cd CodeSentinel
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Scan a Local File or Diff via CLI

You can run the deterministic AST scanner or the full LangGraph pipeline directly from your terminal without configuring Redis or GitHub Webhooks:

```bash
# Fast AST scan on a Python file (zero LLM calls, exits non-zero on findings)
python -m src.cli src/api/webhooks.py

# Emit structured JSON findings
python -m src.cli path/to/suspect_module.py --json

# Run the full 4-agent LangGraph remediation workflow on a file or .diff
python -m src.cli path/to/changes.diff --full-graph
```

Example CLI output on a vulnerable file:

```text
auth_service.py:14: [CRITICAL] CWE-798: Hardcoded Credentials - Hardcoded secret or credential assigned to variable 'jwt_secret'.
auth_service.py:29: [CRITICAL] CWE-89: SQL Injection - SQL query constructed via dynamic string interpolation (f-string / .format / %).
auth_service.py:44: [CRITICAL] CWE-78: OS Command Injection - Subprocess invoked with 'shell=True', enabling shell command injection.
```

### 3. Run the Webhook API & Celery Worker (Docker Compose)

```bash
cp .env.example .env
# Set GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET, and LLM_PROVIDER in .env
docker-compose up --build -d
```

- **FastAPI Health & Metrics:** `http://localhost:8000/health`
- **OpenAPI Spec:** `http://localhost:8000/docs`

---

## Testing

The test suite (42 unit and integration tests) runs entirely offline using a deterministic mock LLM fallback when no external API key is set:

```bash
pytest -v --cov=src tests/
```

---

## Repository Structure

```text
CodeSentinel/
├── src/
│   ├── cli.py                   # Standalone command-line scanner
│   ├── api/                     # FastAPI application & HMAC-SHA256 webhook router
│   ├── agents/                  # LangGraph state, AST scanner, and 4 agent nodes
│   ├── core/                    # Pydantic settings & structured JSON logging
│   ├── github_client/           # Unified diff parser, httpx client, & review publisher
│   └── worker/                  # Celery async task queue & Redis broker config
├── tests/                       # 42 pytest unit & integration tests
├── Dockerfile                   # Multi-stage non-root container build
└── docker-compose.yml           # FastAPI + Celery Worker + Redis 7 stack
```

## License

MIT License. See [LICENSE](LICENSE).
