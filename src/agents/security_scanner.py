"""
Security Scanner Agent Node.
Combines deterministic Python AST taint/sink analysis with LLM contextual audit
to identify OWASP/CWE vulnerabilities and generate inline PR comments.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List

from src.agents.ast_scanner import ASTScanner
from src.agents.llm import get_chat_model
from src.agents.state import AgentState, ReviewComment, SecurityVulnerability
from src.github_client.parser import GitDiffParser

logger = logging.getLogger("codesentinel.agents.security_scanner")

SECURITY_SCANNER_SYSTEM_PROMPT = """You are an application security engineer reviewing a GitHub Pull Request diff.
Identify concrete security vulnerabilities in the modified code:
1. OWASP Top 10 (SQL Injection, Command Injection, SSRF, XSS, Broken Access Control, Deserialization).
2. CWE Top 25 (CWE-89, CWE-78, CWE-798 Hardcoded Credentials, CWE-22 Path Traversal).
3. Algorithmic denial-of-service or resource leaks (unclosed file/socket handles, unbounded recursion).

Return ONLY a JSON array of findings. If none exist, return `[]`.
[
  {
    "file_path": "src/auth.py",
    "line_number": 12,
    "category": "CWE-798: Hardcoded Credentials",
    "severity": "CRITICAL",
    "description": "Plaintext API secret assigned in source code.",
    "remediation": "Read secret from environment variables via os.environ."
  }
]
"""


def parse_llm_json_array(text: str) -> List[Dict[str, Any]]:
    """Extract JSON array from raw or fenced LLM output."""
    match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    bracket_match = re.search(r"(\[.*\])", text, re.DOTALL)
    if bracket_match:
        try:
            return json.loads(bracket_match.group(1))
        except json.JSONDecodeError:
            pass

    return []


async def security_scanner_node(state: AgentState) -> Dict[str, Any]:
    """Run hybrid AST + LLM security scan over the PR diff."""
    pr_num = state.get("pr_number", 0)
    git_diff = state.get("git_diff", "")
    logger.info("[security_scanner] scanning PR #%d", pr_num)

    vulnerabilities: List[Dict[str, Any]] = []
    review_comments: List[Dict[str, Any]] = list(state.get("review_comments", []))

    parsed_files = GitDiffParser.parse(git_diff)
    ast_findings: List[Dict[str, Any]] = []

    for df in parsed_files:
        if df.file_path.endswith(".py"):
            added_lines: List[str] = []
            line_map: Dict[int, int] = {}
            for hunk in df.hunks:
                for line in hunk.lines:
                    if line.type == "+":
                        added_lines.append(line.content)
                        line_map[len(added_lines)] = line.new_line_no or 1

            if added_lines:
                snippet = "\n".join(added_lines)
                hits = ASTScanner.scan_code(snippet, file_path=df.file_path)
                for hit in hits:
                    hit_dict = hit.model_dump() if isinstance(hit, SecurityVulnerability) else dict(hit)
                    raw_line = hit_dict.get("line_number") or 1
                    hit_dict["line_number"] = line_map.get(raw_line, raw_line)
                    ast_findings.append(hit_dict)
                    logger.info(
                        "[ast_scanner] %s in %s:%s",
                        hit_dict.get("category"),
                        hit_dict.get("file_path"),
                        hit_dict.get("line_number"),
                    )

    formatted_diff = GitDiffParser.get_summary_text(parsed_files) if parsed_files else git_diff
    llm = get_chat_model(temperature=0.0)

    user_prompt = (
        f"Pull Request #{pr_num}: {state.get('pr_title', '')}\n\n"
        f"Unified Diff with Line Numbers:\n{formatted_diff}\n\n"
        "Identify all security vulnerabilities and output the JSON array."
    )

    llm_findings: List[Dict[str, Any]] = []
    try:
        messages = [
            {"role": "system", "content": SECURITY_SCANNER_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        response = await llm.ainvoke(messages)
        llm_findings = parse_llm_json_array(response.content)
    except Exception as exc:
        logger.error("[security_scanner] LLM scan failed (%s), using AST findings only", exc)

    seen_keys = set()
    for v in ast_findings:
        key = (v.get("file_path"), v.get("line_number"), v.get("category", "")[:7])
        seen_keys.add(key)
        vulnerabilities.append(v)

    for item in llm_findings:
        vuln_dict: Dict[str, Any] = {
            "file_path": item.get("file_path", "unknown"),
            "line_number": int(item.get("line_number", 1)),
            "category": item.get("category", "Security Vulnerability"),
            "severity": item.get("severity", "HIGH"),
            "description": item.get("description", ""),
            "remediation": item.get("remediation", ""),
        }
        key = (vuln_dict["file_path"], vuln_dict["line_number"], vuln_dict["category"][:7])
        if key not in seen_keys:
            seen_keys.add(key)
            vulnerabilities.append(vuln_dict)

    for vuln in vulnerabilities:
        comment_body = (
            f"### CodeSentinel Security Alert: {vuln['category']}\n"
            f"**Severity:** `{vuln['severity']}`\n\n"
            f"**Finding:** {vuln['description']}\n\n"
            f"**Remediation:** {vuln['remediation']}"
        )
        comment = ReviewComment(
            path=vuln["file_path"],
            line=int(vuln.get("line_number") or 1),
            body=comment_body,
            side="RIGHT",
        )
        review_comments.append(comment.model_dump())

    logger.info(
        "[security_scanner] completed for PR #%d: %d finding(s)",
        pr_num,
        len(vulnerabilities),
    )

    return {
        "security_vulnerabilities": vulnerabilities,
        "review_comments": review_comments,
    }
