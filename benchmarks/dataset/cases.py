"""
Labeled OWASP / CWE benchmark corpus for evaluating CodeSentinel AST precision,
recall, F1-score, false positive rate, and per-file scan latency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Set


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    description: str
    expected_cwes: Set[str]  # empty set means clean/safe code (must yield 0 findings)
    source: str


BENCHMARK_CASES: List[BenchmarkCase] = [
    BenchmarkCase(
        case_id="vuln_sqli_fstring",
        description="SQL injection via f-string in cursor.execute",
        expected_cwes={"CWE-89"},
        source='def get_user(cur, uid):\n    return cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n',
    ),
    BenchmarkCase(
        case_id="vuln_sqli_percent",
        description="SQL injection via % operator formatting",
        expected_cwes={"CWE-89"},
        source='def delete_item(cur, item):\n    cur.execute("DELETE FROM items WHERE name = %s" % item)\n',
    ),
    BenchmarkCase(
        case_id="vuln_hardcoded_aws",
        description="Hardcoded AWS access key literal",
        expected_cwes={"CWE-798"},
        source='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    ),
    BenchmarkCase(
        case_id="vuln_high_entropy_secret",
        description="High-entropy secret token assigned to generic variable",
        expected_cwes={"CWE-798"},
        source='signing_val = "aB9kL2mN5pQ8rS1tU4vW7xY0zC3dE6fG"\n',
    ),
    BenchmarkCase(
        case_id="vuln_rce_eval",
        description="Arbitrary code execution via eval()",
        expected_cwes={"CWE-95"},
        source="def calc(expr):\n    return eval(expr)\n",
    ),
    BenchmarkCase(
        case_id="vuln_pickle_yaml",
        description="Insecure deserialization via pickle.loads and yaml.load",
        expected_cwes={"CWE-502"},
        source="import pickle, yaml\npickle.loads(b)\nyaml.load(s, Loader=yaml.Loader)\n",
    ),
    BenchmarkCase(
        case_id="vuln_cmd_injection",
        description="OS command injection via subprocess shell=True and os.system",
        expected_cwes={"CWE-78"},
        source='import os, subprocess\nos.system("rm -rf /tmp/x")\nsubprocess.run("ls " + arg, shell=True)\n',
    ),
    BenchmarkCase(
        case_id="vuln_weak_crypto_random",
        description="Weak MD5 hash and predictable random token",
        expected_cwes={"CWE-327", "CWE-330"},
        source='import hashlib, random\nh = hashlib.md5(b"pw")\napi_token = random.randint(1, 999999)\n',
    ),
    BenchmarkCase(
        case_id="vuln_tls_ssrf",
        description="Disabled TLS verification and dynamic SSRF URL",
        expected_cwes={"CWE-295", "CWE-918"},
        source='import requests\nrequests.get(f"https://{host}/meta", verify=False)\n',
    ),
    BenchmarkCase(
        case_id="vuln_path_xxe_debug",
        description="Path traversal, unsafe XML import, and debug=True",
        expected_cwes={"CWE-22", "CWE-611", "CWE-489"},
        source='import xml.etree.ElementTree as ET\nopen(f"/data/{name}")\napp.run(debug=True)\n',
    ),
    # --- Clean / Safe Negative Controls (must produce 0 false positives) ---
    BenchmarkCase(
        case_id="safe_parameterized_sql",
        description="Parameterized SQL query using placeholders",
        expected_cwes=set(),
        source='def get_user(cur, uid):\n    return cur.execute("SELECT * FROM users WHERE id = ?", (uid,))\n',
    ),
    BenchmarkCase(
        case_id="safe_env_secrets_and_urls",
        description="Environment variable loading and public API URLs",
        expected_cwes=set(),
        source='import os\napi_key = os.getenv("API_KEY", "")\nendpoint = "https://api.example.com/v1/health"\n',
    ),
    BenchmarkCase(
        case_id="safe_yaml_and_json",
        description="Safe YAML loading and JSON parsing",
        expected_cwes=set(),
        source="import json, yaml\na = yaml.safe_load(raw)\nb = yaml.load(raw, Loader=yaml.SafeLoader)\nc = json.loads(raw)\n",
    ),
    BenchmarkCase(
        case_id="safe_crypto_and_secrets",
        description="SHA-256 hashing, non-security MD5 checksum, and secrets module",
        expected_cwes=set(),
        source='import hashlib, secrets\nh1 = hashlib.sha256(b"data")\nh2 = hashlib.md5(b"etag", usedforsecurity=False)\ntoken = secrets.token_urlsafe(32)\n',
    ),
    BenchmarkCase(
        case_id="safe_subprocess_and_http",
        description="Subprocess with list args (shell=False) and static HTTPS call",
        expected_cwes=set(),
        source='import requests, subprocess\nsubprocess.run(["echo", "ok"], shell=False)\nrequests.get("https://api.github.com/zen", timeout=5)\n',
    ),
    BenchmarkCase(
        case_id="safe_inline_suppressed",
        description="Explicitly suppressed finding via inline comment",
        expected_cwes=set(),
        source='test_secret = "my_intentional_fixture_secret"  # codesentinel: ignore[CWE-798]\n',
    ),
]
