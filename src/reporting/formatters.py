"""Text and Markdown report formatters for CodeSentinel CLI scans."""

from __future__ import annotations

from collections import Counter
from typing import Iterable, List

from src.agents.rule_registry import resolve_rule_for_category
from src.agents.state import SecurityVulnerability


def _severity_summary(findings: List[SecurityVulnerability]) -> Counter:
    return Counter(f.severity.upper() for f in findings)


def format_text_report(
    findings: Iterable[SecurityVulnerability],
    files_scanned: int,
    elapsed_ms: float,
) -> str:
    items = list(findings)
    counts = _severity_summary(items)
    lines: List[str] = []

    if not items:
        lines.append(
            f"CodeSentinel: clean ({files_scanned} file(s) scanned in {elapsed_ms:.1f} ms, 0 vulnerabilities)"
        )
        return "\n".join(lines)

    for f in items:
        rule = resolve_rule_for_category(f.category)
        code = rule.rule_id if rule else "CS000"
        lines.append(
            f"{f.file_path}:{f.line_number}: [{f.severity}] ({code}) {f.category} - {f.description}"
        )

    lines.append("")
    lines.append(
        f"Summary: {len(items)} finding(s) across {files_scanned} file(s) in {elapsed_ms:.1f} ms "
        f"(CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']})"
    )
    return "\n".join(lines)


def format_markdown_report(
    findings: Iterable[SecurityVulnerability],
    files_scanned: int,
    elapsed_ms: float,
) -> str:
    items = list(findings)
    counts = _severity_summary(items)
    lines: List[str] = [
        "## CodeSentinel Security Audit Report",
        "",
        f"- **Files scanned:** {files_scanned}",
        f"- **Scan duration:** {elapsed_ms:.1f} ms",
        f"- **Findings:** {len(items)} "
        f"(CRITICAL: {counts['CRITICAL']}, HIGH: {counts['HIGH']}, MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']})",
        "",
    ]

    if not items:
        lines.append("No vulnerabilities detected.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Rule | Location | Category | Description |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for f in items:
        rule = resolve_rule_for_category(f.category)
        code = rule.rule_id if rule else "CS000"
        loc = f"`{f.file_path}:{f.line_number}`"
        desc = f.description.replace("|", "\\|")
        lines.append(f"| **{f.severity}** | `{code}` | {loc} | {f.category} | {desc} |")

    return "\n".join(lines)
