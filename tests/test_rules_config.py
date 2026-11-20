"""Tests for .codesentinel.toml and pyproject.toml configuration loading."""

from pathlib import Path

from src.rules_config import DEFAULT_EXCLUDES, ScanConfig


def test_default_scan_config():
    cfg = ScanConfig()
    assert cfg.normalized_min_severity() == "LOW"
    assert cfg.is_rule_enabled("CS001", "CWE-798: Hardcoded Credentials")
    assert cfg.is_path_excluded(Path(".venv/lib/python.py"))
    assert not cfg.is_path_excluded(Path("src/app.py"))


def test_discover_codesentinel_toml(tmp_path: Path):
    toml_file = tmp_path / ".codesentinel.toml"
    toml_file.write_text(
        'min_severity = "HIGH"\n'
        'disabled_rules = ["CWE-327", "CS010"]\n'
        'exclude = ["migrations", "*_generated.py"]\n',
        encoding="utf-8",
    )

    cfg = ScanConfig.discover(tmp_path)
    assert cfg.normalized_min_severity() == "HIGH"
    assert not cfg.meets_severity("MEDIUM")
    assert cfg.meets_severity("HIGH")
    assert cfg.meets_severity("CRITICAL")

    assert not cfg.is_rule_enabled("CS010", "CWE-611: XXE")
    assert not cfg.is_rule_enabled("CS006", "CWE-327: Weak Cryptography")
    assert cfg.is_rule_enabled("CS001", "CWE-89: SQL Injection")

    assert cfg.is_path_excluded(Path("migrations/0001_init.py"))
    assert cfg.is_path_excluded(Path("src/schema_generated.py"))
    assert ".venv" in cfg.exclude
    for d in DEFAULT_EXCLUDES:
        assert d in cfg.exclude


def test_discover_pyproject_tool_section(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\n"
        'name = "demo"\n\n'
        "[tool.codesentinel]\n"
        'min_severity = "CRITICAL"\n'
        'disabled_rules = ["CWE-489"]\n',
        encoding="utf-8",
    )

    cfg = ScanConfig.discover(tmp_path)
    assert cfg.normalized_min_severity() == "CRITICAL"
    assert not cfg.meets_severity("HIGH")
    assert not cfg.is_rule_enabled(category="CWE-489: Debug Mode Enabled")
