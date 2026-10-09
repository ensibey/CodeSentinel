"""
Agent 1: Security Scanner Node.
Performs dual-layer security auditing:
1. Static Abstract Syntax Tree (AST) analysis for deterministic vulnerability discovery.
2. LLM-based semantic reasoning for complex architectural and logic flaws (OWASP Top 10).
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

SECURITY_SCANNER_SYSTEM_PROMPT = """You are an elite Senior Application Security Engineer and Principal Code Reviewer.
Your role is to perform an exhaustive, high-precision security audit of GitHub Pull Request diffs.

Focus Areas (OWASP Top 10 & CWE):
- Hardcoded Secrets, API keys, credentials, JWT tokens
- SQL Injection (raw queries, string interpolation in ORM/DB drivers)
- Command Injection (eval, exec, os.system, unsanitized subprocess)
- Path Traversal & Arbitrary File Access
- Insecure Deserialization (pickle, unsafe yaml)
- Cross-Site Scripting (XSS) & Server-Side Request Forgery (SSRF)

You must output ONLY a valid JSON object matching this schema:
{
  "vulnerabilities": [
    {
      "file_path": "string",
      "line_number": 10,
      "category": "CWE-89: SQL Injection",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "description": "Clear explanation of the flaw and exploit scenario",
      "remediation": "Actionable, production-ready remediation advice",
      "code_snippet": "vulnerable snippet"
    }
  ]
}
If no vulnerabilities exist, return: {"vulnerabilities": []}
"""


def extract_json_from_llm_response(text: str) -> Dict[str, Any]:
    """Helper to extract JSON dictionary from raw LLM output."""
    # Match markdown code block ```json ... ```
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Match first '{' to last '}'
    brace_match = re.search(r"(\{.*\})", text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(1))
        except json.JSONDecodeError:
            pass

    return {"vulnerabilities": []}


async def security_scanner_node(state: AgentState) -> Dict[str, Any]:
    """
    Security Scanner Agent Node.
    Analyzes PR diff using AST and LLM reasoning.
    """
    repo = state.get("repo_name", "")
    pr_num = state.get("pr_number", 0)
    git_diff = state.get("git_diff", "")
    logger.info("🔍 [Security Scanner] Auditing PR %s #%d...", repo, pr_num)

    all_vulnerabilities: List[Dict[str, Any]] = []
    seen_keys = set()

    # Layer 1: AST Static Analysis
    diff_files = GitDiffParser.parse(git_diff)
    for df in diff_files:
        if df.file_path.endswith(".py"):
            # Construct snippet of added lines for AST analysis
            added_code = "\n".join(line.content for line in df.added_lines)
            ast_vulns = ASTScanner.scan_code(added_code, file_path=df.file_path)
            for v in ast_vulns:
                key = (v.file_path, v.line_number, v.category)
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_vulnerabilities.append(v.model_dump())
                    logger.info("⚡ AST Hit: %s at %s:%s", v.category, v.file_path, v.line_number)

    # Layer 2: LLM Semantic Analysis
    llm = get_chat_model(temperature=0.0)
    user_prompt = f"Repository: {repo}\nPR Number: #{pr_num}\n\nGit Diff:\n{git_diff}\n\nPlease audit for security vulnerabilities."

    try:
        messages = [
            {"role": "system", "content": SECURITY_SCANNER_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        response = await llm.ainvoke(messages)
        parsed = extract_json_from_llm_response(response.content)

        for item in parsed.get("vulnerabilities", []):
            try:
                v = SecurityVulnerability(**item)
                key = (v.file_path, v.line_number, v.category)
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_vulnerabilities.append(v.model_dump())
                    logger.info("🧠 LLM Hit: %s at %s:%s", v.category, v.file_path, v.line_number)
            except Exception as parse_err:
                logger.warning("Error parsing vulnerability item: %s", parse_err)
    except Exception as exc:
        logger.error("LLM audit failed (%s). Continuing with AST findings.", exc)

    # Layer 3: Convert vulnerabilities to inline review comments
    review_comments: List[Dict[str, Any]] = []
    for vuln in all_vulnerabilities:
        line_no = vuln.get("line_number") or 1
        path = vuln.get("file_path", "")
        body = (
            f"### 🛡️ CodeSentinel Security Alert: `{vuln.get('category')}`\n"
            f"**Severity:** `{vuln.get('severity')}`\n\n"
            f"**Finding:** {vuln.get('description')}\n\n"
            f"> [!WARNING]\n"
            f"> **Remediation Recommendation:**\n"
            f"> {vuln.get('remediation')}\n"
        )
        review_comments.append(
            ReviewComment(
                path=path,
                line=line_no,
                body=body,
                side="RIGHT",
            ).model_dump()
        )

    logger.info(
        "✅ [Security Scanner] Completed: %d vulnerabilities detected on PR #%d",
        len(all_vulnerabilities),
        pr_num,
    )

    return {
        "security_vulnerabilities": all_vulnerabilities,
        "review_comments": review_comments,
    }
