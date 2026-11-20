"""
Intentionally vulnerable sample service for demonstrating CodeSentinel AST auditing.
DO NOT deploy or copy patterns from this file into production.
"""

import hashlib
import os
import pickle
import random
import subprocess
import xml.etree.ElementTree as ET
import requests
import yaml

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"


def fetch_user(cursor, username: str):
    return cursor.execute(f"SELECT id, email FROM users WHERE username = '{username}'")


def load_config(raw_yaml: str):
    return yaml.load(raw_yaml, Loader=yaml.Loader)


def deserialize_session(payload: bytes):
    return pickle.loads(payload)


def evaluate_expression(expr: str):
    return eval(expr)


def run_diagnostics(host: str):
    return subprocess.run(f"ping -c 1 {host}", shell=True)


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def generate_reset_token() -> int:
    session_token = random.randint(100000, 999999)
    return session_token


def proxy_request(target_host: str):
    return requests.get(f"https://{target_host}/status", verify=False)


def read_report(filename: str) -> str:
    with open(f"/var/reports/{filename}", "r", encoding="utf-8") as fh:
        return fh.read()


def parse_xml_payload(xml_text: str):
    return ET.fromstring(xml_text)


def start_server(app):
    app.run(host="0.0.0.0", port=8000, debug=True)
