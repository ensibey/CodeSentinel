# CodeSentinel

[![CodeSentinel CI](https://github.com/ensibey/CodeSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/ensibey/CodeSentinel/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-10B981)
![Tests: 75 passing](https://img.shields.io/badge/tests-75%20passing-10B981)

Hybrid **Python AST Static Security Scanner (SAST)** and **LangGraph Multi-Agent Pull Request Reviewer**.

CodeSentinel combines deterministic, sub-millisecond AST analysis (12 OWASP Top 10 / CWE rules + Shannon entropy secret detection) with a 4-agent LangGraph remediation workflow (`security_scanner` → `test_generator` → `patch_creator` → `judge`). Unlike LLM-only reviewers, the Judge node re-runs the deterministic AST scanner on every proposed patch diff to guarantee zero residual CWE patterns before approving.

---

## Architecture

```text
GitHub PR Webhook (FastAPI + HMAC) ──► Redis / ARQ Worker ──► GitDiffParser (+ lines)
                                                                       │
Local CLI (`codesentinel src/`) ───────────────────────────────────────┤
                                                                       ▼
                                                     [1] Deterministic AST Scanner
                                                         12 OWASP/CWE Rules (CS001-CS012)
                                                         Shannon Entropy + Inline Ignore
                                                                       │
                                         ┌─────────────────────────────┴────────────────────────────┐
                                         ▼ (Local / CI Mode)                                        ▼ (--full-graph / PR Mode)
                           Text / JSON / Markdown / SARIF 2.1.0                       LangGraph Multi-Agent Pipeline
                           (GitHub Code Scanning compatible)                          security_scanner ─► test_generator
                                                                                                               │
                                                                                      judge (AST patch gate) ◄─┴─ patch_creator
                                                                                                 │
                                                                                                 ▼
                                                                                      GitHub Inline PR Review
```

---

## Security Rule Coverage (`CS001` – `CS012`)

| Rule ID | CWE | OWASP 2021 Category | Detection Scope | Severity |
| :--- | :--- | :--- | :--- | :--- |
| `CS001` | CWE-798 | A07 Identification & Auth | Hardcoded credentials, AWS/GitHub/OpenAI/Stripe/PEM tokens, Shannon entropy (`H ≥ 4.4`) | CRITICAL / HIGH |
| `CS002` | CWE-89 | A03 Injection | Dynamic SQL string interpolation (f-strings, `%`, `+`, `.format()`) | CRITICAL |
| `CS003` | CWE-95 | A03 Injection | Direct `eval()` / `exec()` invocation | CRITICAL |
| `CS004` | CWE-502 | A08 Data Integrity | `pickle.loads()` and `yaml.load()` without `SafeLoader` | CRITICAL |
| `CS005` | CWE-78 | A03 Injection | `os.system()` and `subprocess.*(..., shell=True)` | HIGH |
| `CS006` | CWE-327 | A02 Crypto Failures | `hashlib.md5` / `hashlib.sha1` (skips `usedforsecurity=False`) | MEDIUM |
| `CS007` | CWE-330 | A02 Crypto Failures | Predictable `random.*` used for tokens, OTPs, keys, or secrets | HIGH |
| `CS008` | CWE-295 | A07 Identification & Auth | `verify=False` in HTTP clients and `ssl._create_unverified_context()` | HIGH |
| `CS009` | CWE-918 | A10 SSRF | Dynamic URL construction in `requests`, `httpx`, and `urlopen` | HIGH |
| `CS010` | CWE-22 | A01 Broken Access Control | Dynamic file paths or `..` traversal in `open()` | HIGH |
| `CS011` | CWE-611 | A05 Misconfiguration | Unsafe stdlib XML parsers (`ElementTree`, `minidom`, `sax`) | MEDIUM |
| `CS012` | CWE-489 / 605 | A05 Misconfiguration | `app.run(debug=True)` and wildcard `host="0.0.0.0"` binding | MEDIUM / LOW |

---

## Reproducible OWASP Benchmark

Measured on the 16-case labeled OWASP/CWE corpus (`benchmarks/dataset/cases.py` — 10 vulnerable cases spanning 14 CWE targets + 6 clean negative controls):

```bash
python benchmarks/run_benchmark.py
```

| Metric | Result |
| :--- | :--- |
| **Total Benchmark Cases** | `16` (10 vulnerable, 6 clean controls) |
| **TP / FP / FN** | `14 / 0 / 0` |
| **Precision** | `100.0%` |
| **Recall** | `100.0%` |
| **F1-Score** | `100.0%` |
| **False Positive Rate** | `0.0%` |
| **Mean / P95 Latency** | `0.087 ms / 0.343 ms` per file |

---

## Quick Start

### 1. Local CLI Scanning (Zero API Keys Required)

```bash
pip install -e .

# Scan a single file or recursively scan a directory
codesentinel examples/vulnerable_api.py
codesentinel src/ --fail-on HIGH

# Export SARIF 2.1.0 for GitHub Code Scanning or Markdown for PR summaries
codesentinel src/ --format sarif --output codesentinel.sarif
codesentinel examples/vulnerable_api.py --format markdown
```

Example terminal output on `examples/vulnerable_api.py`:

```text
examples/vulnerable_api.py:15: [CRITICAL] (CS001) CWE-798: Hardcoded Credentials - Detected hardcoded AWS Access Key ID assigned to 'AWS_ACCESS_KEY'.
examples/vulnerable_api.py:19: [CRITICAL] (CS002) CWE-89: SQL Injection - Dynamic string interpolation (Formatted f-string query) in database call 'execute'.
examples/vulnerable_api.py:23: [CRITICAL] (CS004) CWE-502: Unsafe YAML Deserialization - Calling yaml.load() without SafeLoader can instantiate arbitrary Python objects.
examples/vulnerable_api.py:31: [CRITICAL] (CS003) CWE-95: Dynamic Code Execution - Direct invocation of 'eval()' enables Remote Code Execution (RCE).
...
Summary: 14 finding(s) across 1 file(s) in 0.9 ms (CRITICAL=5, HIGH=5, MEDIUM=3, LOW=1)
```

### 2. Inline Suppression & Project Config (`.codesentinel.toml`)

Suppress intentional fixtures inline:

```python
test_key = "intentional_fixture_token"  # codesentinel: ignore[CWE-798]
```

Or configure project-wide policies in `.codesentinel.toml` (or `[tool.codesentinel]` in `pyproject.toml`):

```toml
min_severity = "MEDIUM"
disabled_rules = ["CWE-605"]
exclude = ["migrations", "*_generated.py"]
```

### 3. Reusable GitHub Action

Drop CodeSentinel into any repository workflow:

```yaml
- name: Run CodeSentinel Security Audit
  uses: ensibey/CodeSentinel@main
  with:
    target: src/
    format: sarif
    fail-on: HIGH
    output: codesentinel.sarif
```

### 4. Full Multi-Agent PR Mode (FastAPI + Redis + LangGraph)

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
```

Run the full test suite:

```bash
pytest -q
```

---

## License

MIT
