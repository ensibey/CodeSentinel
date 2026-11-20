"""
Hardened sample service demonstrating secure Python patterns.
CodeSentinel should report 0 vulnerabilities (zero false positives) on this file.
"""

import ast
import hashlib
import json
import os
import secrets
import subprocess
from pathlib import Path
import requests
import yaml

BASE_REPORTS_DIR = Path("/var/reports").resolve()
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "")


def fetch_user(cursor, username: str):
    return cursor.execute("SELECT id, email FROM users WHERE username = ?", (username,))


def load_config(raw_yaml: str):
    return yaml.safe_load(raw_yaml)


def deserialize_session(payload: str):
    return json.loads(payload)


def evaluate_literal(expr: str):
    return ast.literal_eval(expr)


def run_diagnostics(host: str):
    return subprocess.run(["ping", "-c", "1", host], shell=False, check=True)


def hash_identifier(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)


def check_health():
    return requests.get("https://api.github.com/zen", timeout=5)


def read_report(filename: str) -> str:
    candidate = (BASE_REPORTS_DIR / filename).resolve()
    if not candidate.is_relative_to(BASE_REPORTS_DIR):
        raise ValueError("Invalid report path")
    return candidate.read_text(encoding="utf-8")
