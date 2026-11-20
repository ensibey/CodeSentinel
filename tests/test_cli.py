"""Tests for CodeSentinel CLI recursive directory scanning and exclusions."""

import json
from pathlib import Path

from src.cli import main


def test_cli_recursive_directory_scan_respects_excludes(tmp_path: Path, capsys):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "vuln.py").write_text("eval(user_input)\n", encoding="utf-8")
    (tmp_path / "src" / "clean.py").write_text("x = 1 + 2\n", encoding="utf-8")

    # Should be excluded automatically
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.py").write_text("eval(should_not_scan)\n", encoding="utf-8")

    rc = main([str(tmp_path), "--json"])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["files_scanned"] == 2
    assert len(out["findings"]) == 1
    assert "CWE-95" in out["findings"][0]["category"]


def test_cli_clean_directory_returns_zero(tmp_path: Path, capsys):
    (tmp_path / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    rc = main([str(tmp_path)])
    assert rc == 0
    assert "clean" in capsys.readouterr().out.lower()


def test_cli_fail_on_severity_policy(tmp_path: Path, capsys):
    # hashlib.md5 is MEDIUM severity
    (tmp_path / "hash.py").write_text("import hashlib\nh = hashlib.md5(b'abc')\n", encoding="utf-8")

    assert main([str(tmp_path), "--fail-on", "HIGH"]) == 0
    capsys.readouterr()
    assert main([str(tmp_path), "--fail-on", "MEDIUM"]) == 1
    capsys.readouterr()
    assert main([str(tmp_path), "--min-severity", "HIGH", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["findings"] == []

