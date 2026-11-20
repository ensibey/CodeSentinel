"""Tests for the canonical OWASP / CWE security rule registry."""

from src.agents.rule_registry import RULE_REGISTRY, resolve_rule_for_category


def test_registry_has_12_unique_rules():
    assert len(RULE_REGISTRY) == 12
    ids = {r.rule_id for r in RULE_REGISTRY.values()}
    assert len(ids) == 12
    for rule in RULE_REGISTRY.values():
        assert rule.help_uri.startswith("https://cwe.mitre.org/")
        assert "2021" in rule.owasp_2021


def test_resolve_rule_for_category():
    assert resolve_rule_for_category("CWE-89: SQL Injection").rule_id == "CS002"
    assert resolve_rule_for_category("CWE-798: Hardcoded Credentials").rule_id == "CS001"
    assert resolve_rule_for_category("CWE-605: Binding to All Network Interfaces").rule_id == "CS012"
    assert resolve_rule_for_category("Unknown Category") is None
