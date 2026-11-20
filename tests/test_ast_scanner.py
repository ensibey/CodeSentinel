"""
Tests for Abstract Syntax Tree (AST) static security scanner.
"""

from __future__ import annotations
from src.agents.ast_scanner import ASTScanner


def test_ast_detects_hardcoded_secrets():
    code = """
api_key = "sk_live_998877665544332211"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET"
safe_var = "hello world"
"""
    vulns = ASTScanner.scan_code(code, "config.py")
    assert len(vulns) >= 2
    categories = [v.category for v in vulns]
    assert all("CWE-798" in cat for cat in categories)
    assert any("api_key" in v.description for v in vulns)


def test_ast_detects_sql_injection():
    code = """
def get_user(cursor, username):
    # Vulnerable f-string SQL query
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    # Vulnerable string formatting
    cursor.query("SELECT id FROM accounts WHERE owner = %s" % username)
"""
    vulns = ASTScanner.scan_code(code, "db.py")
    assert len(vulns) >= 1
    assert any("CWE-89" in v.category for v in vulns)


def test_ast_detects_rce_and_pickle():
    code = """
import pickle

def run_user_code(user_input):
    eval(user_input)
    data = pickle.loads(user_input)
"""
    vulns = ASTScanner.scan_code(code, "unsafe.py")
    assert len(vulns) == 2
    categories = [v.category for v in vulns]
    assert any("CWE-95" in cat for cat in categories)  # eval
    assert any("CWE-502" in cat for cat in categories)  # pickle


def test_ast_detects_command_injection():
    code = """
import os
import subprocess

def run_cmd(param):
    os.system("ping " + param)
    subprocess.run("ls " + param, shell=True)
"""
    vulns = ASTScanner.scan_code(code, "cmd.py")
    assert len(vulns) == 2
    assert all("CWE-78" in v.category for v in vulns)


def test_ast_clean_code_has_no_issues():
    clean_code = """
import os

def calculate(x: int, y: int) -> int:
    return x + y

def fetch_user(cursor, user_id: int):
    # Parameterized query is safe
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    vulns = ASTScanner.scan_code(clean_code, "safe.py")
    assert len(vulns) == 0


def test_ast_syntax_error_handled_gracefully():
    invalid_code = "this is not valid python code @@ !!"
    vulns = ASTScanner.scan_code(invalid_code, "invalid.py")
    assert vulns == []


def test_inline_ignore_wildcard():
    code = """
    api_key = "super_secret_token_999999"  # codesentinel: ignore
    eval(user_input)
    """
    vulns = ASTScanner.scan_code(code, "suppressed.py")
    assert len(vulns) == 1
    assert "CWE-95" in vulns[0].category


def test_inline_ignore_targeted_cwe():
    code = """
    api_key = "super_secret_token_999999"  # codesentinel: ignore[CWE-798]
    eval(user_input)  # codesentinel: ignore[CWE-798]
    """
    vulns = ASTScanner.scan_code(code, "targeted.py")
    assert len(vulns) == 1
    assert "CWE-95" in vulns[0].category


def test_scan_code_respects_scan_config():
    from src.rules_config import ScanConfig

    code = """
    import os
    os.system("ls")
    eval(user_input)
    """
    cfg = ScanConfig(disabled_rules=["CWE-95"], min_severity="HIGH")
    vulns = ASTScanner.scan_code(code, "cfg_test.py", config=cfg)
    assert len(vulns) == 1
    assert "CWE-78" in vulns[0].category


def test_detects_provider_secrets_and_high_entropy():
    code = """
    cloud_id = "AKIAIOSFODNN7EXAMPLE"
    random_blob = "aB9kL2mN5pQ8rS1tU4vW7xY0zC3dE6fG"
    normal_url = "https://api.example.com/v1/items/list"
    """
    vulns = ASTScanner.scan_code(code, "secrets.py")
    assert len(vulns) == 2
    assert any("AWS Access Key" in v.description for v in vulns)
    assert any("High-Entropy" in v.category for v in vulns)


def test_detects_unsafe_yaml_and_allows_safe_loader():
    code = """
    import yaml
    a = yaml.load(raw_data, Loader=yaml.Loader)
    b = yaml.unsafe_load(raw_data)
    c = yaml.load(raw_data, Loader=yaml.SafeLoader)
    d = yaml.safe_load(raw_data)
    """
    vulns = ASTScanner.scan_code(code, "yaml_check.py")
    assert len(vulns) == 2
    assert all("CWE-502" in v.category for v in vulns)


def test_detects_weak_crypto_and_insecure_random():
    code = """
    import hashlib
    import random
    digest = hashlib.md5(b"password").hexdigest()
    checksum = hashlib.md5(b"file", usedforsecurity=False).hexdigest()
    session_token = random.randint(100000, 999999)
    """
    vulns = ASTScanner.scan_code(code, "crypto.py")
    assert len(vulns) == 2
    assert any("CWE-327" in v.category for v in vulns)
    assert any("CWE-330" in v.category for v in vulns)




