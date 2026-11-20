"""
Canonical security rule registry for CodeSentinel AST checks.

Maps each CWE detection category to a stable Rule ID (CS001-CS012),
OWASP Top 10 (2021) classification, default severity, and MITRE CWE reference URI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class SecurityRule:
    rule_id: str
    cwe: str
    name: str
    owasp_2021: str
    default_severity: str
    help_uri: str


RULE_REGISTRY: Dict[str, SecurityRule] = {
    "CS001": SecurityRule(
        rule_id="CS001",
        cwe="CWE-798",
        name="Hardcoded Credentials & High-Entropy Secrets",
        owasp_2021="A07:2021-Identification and Authentication Failures",
        default_severity="CRITICAL",
        help_uri="https://cwe.mitre.org/data/definitions/798.html",
    ),
    "CS002": SecurityRule(
        rule_id="CS002",
        cwe="CWE-89",
        name="SQL Injection",
        owasp_2021="A03:2021-Injection",
        default_severity="CRITICAL",
        help_uri="https://cwe.mitre.org/data/definitions/89.html",
    ),
    "CS003": SecurityRule(
        rule_id="CS003",
        cwe="CWE-95",
        name="Dynamic Code Execution (eval / exec)",
        owasp_2021="A03:2021-Injection",
        default_severity="CRITICAL",
        help_uri="https://cwe.mitre.org/data/definitions/95.html",
    ),
    "CS004": SecurityRule(
        rule_id="CS004",
        cwe="CWE-502",
        name="Insecure Deserialization (pickle / unsafe YAML)",
        owasp_2021="A08:2021-Software and Data Integrity Failures",
        default_severity="CRITICAL",
        help_uri="https://cwe.mitre.org/data/definitions/502.html",
    ),
    "CS005": SecurityRule(
        rule_id="CS005",
        cwe="CWE-78",
        name="OS Command Injection",
        owasp_2021="A03:2021-Injection",
        default_severity="HIGH",
        help_uri="https://cwe.mitre.org/data/definitions/78.html",
    ),
    "CS006": SecurityRule(
        rule_id="CS006",
        cwe="CWE-327",
        name="Weak Cryptographic Hash Algorithm",
        owasp_2021="A02:2021-Cryptographic Failures",
        default_severity="MEDIUM",
        help_uri="https://cwe.mitre.org/data/definitions/327.html",
    ),
    "CS007": SecurityRule(
        rule_id="CS007",
        cwe="CWE-330",
        name="Insecure Randomness for Security Values",
        owasp_2021="A02:2021-Cryptographic Failures",
        default_severity="HIGH",
        help_uri="https://cwe.mitre.org/data/definitions/330.html",
    ),
    "CS008": SecurityRule(
        rule_id="CS008",
        cwe="CWE-295",
        name="Disabled TLS/SSL Certificate Verification",
        owasp_2021="A07:2021-Identification and Authentication Failures",
        default_severity="HIGH",
        help_uri="https://cwe.mitre.org/data/definitions/295.html",
    ),
    "CS009": SecurityRule(
        rule_id="CS009",
        cwe="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        owasp_2021="A10:2021-Server-Side Request Forgery",
        default_severity="HIGH",
        help_uri="https://cwe.mitre.org/data/definitions/918.html",
    ),
    "CS010": SecurityRule(
        rule_id="CS010",
        cwe="CWE-22",
        name="Path Traversal",
        owasp_2021="A01:2021-Broken Access Control",
        default_severity="HIGH",
        help_uri="https://cwe.mitre.org/data/definitions/22.html",
    ),
    "CS011": SecurityRule(
        rule_id="CS011",
        cwe="CWE-611",
        name="XML External Entity (XXE) / Unsafe XML Parser",
        owasp_2021="A05:2021-Security Misconfiguration",
        default_severity="MEDIUM",
        help_uri="https://cwe.mitre.org/data/definitions/611.html",
    ),
    "CS012": SecurityRule(
        rule_id="CS012",
        cwe="CWE-489",
        name="Active Debug Mode / Wildcard Interface Binding",
        owasp_2021="A05:2021-Security Misconfiguration",
        default_severity="MEDIUM",
        help_uri="https://cwe.mitre.org/data/definitions/489.html",
    ),
}

CWE_TO_RULE: Dict[str, SecurityRule] = {rule.cwe: rule for rule in RULE_REGISTRY.values()}
CWE_TO_RULE["CWE-605"] = RULE_REGISTRY["CS012"]


def resolve_rule_for_category(category: str) -> Optional[SecurityRule]:
    """Resolve a canonical SecurityRule from a vulnerability category string."""
    upper = (category or "").upper()
    for cwe, rule in CWE_TO_RULE.items():
        if cwe in upper:
            return rule
    return None
