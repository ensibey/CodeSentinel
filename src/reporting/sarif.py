"""
SARIF 2.1.0 exporter for GitHub Code Scanning and CI security integrations.

Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from src.agents.rule_registry import RULE_REGISTRY, resolve_rule_for_category
from src.agents.state import SecurityVulnerability

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

SEVERITY_TO_SCORE = {
    "CRITICAL": "9.0",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
}


def export_sarif(
    findings: Iterable[SecurityVulnerability],
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """Convert SecurityVulnerability findings into a SARIF 2.1.0 report dictionary."""
    rules_payload: List[Dict[str, Any]] = []
    for rule in RULE_REGISTRY.values():
        rules_payload.append(
            {
                "id": rule.rule_id,
                "name": rule.name.replace(" ", ""),
                "shortDescription": {"text": rule.name},
                "helpUri": rule.help_uri,
                "properties": {
                    "tags": ["security", rule.cwe, rule.owasp_2021],
                    "security-severity": SEVERITY_TO_SCORE.get(rule.default_severity, "5.0"),
                },
            }
        )

    results_payload: List[Dict[str, Any]] = []
    for vuln in findings:
        rule = resolve_rule_for_category(vuln.category)
        rule_id = rule.rule_id if rule else "CS000"
        level = SEVERITY_TO_SARIF_LEVEL.get(vuln.severity.upper(), "warning")
        results_payload.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"{vuln.description} Remediation: {vuln.remediation}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": vuln.file_path.replace("\\", "/")},
                            "region": {
                                "startLine": max(1, int(vuln.line_number)),
                            },
                        }
                    }
                ],
                "properties": {
                    "category": vuln.category,
                    "severity": vuln.severity,
                    "code_snippet": vuln.code_snippet,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeSentinel",
                        "version": tool_version,
                        "informationUri": "https://github.com/ensibey/CodeSentinel",
                        "rules": rules_payload,
                    }
                },
                "results": results_payload,
            }
        ],
    }
