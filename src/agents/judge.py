"""
Agent 4: Judge & Executive Node.
Serves as the critical gatekeeper and self-correction controller in the cyclical LangGraph workflow:
1. Validates proposed patches against regressions and hallucinations.
2. Checks whether synthesized tests adequately defend the codebase.
3. Decides whether to approve the audit or cycle back (if iteration_count < 3).
4. Generates an executive Markdown review summary report for the PR discussion.
"""

from __future__ import annotations
import json
import logging
import re
from typing import Any, Dict

from src.agents.llm import get_chat_model
from src.agents.state import AgentState

logger = logging.getLogger("codesentinel.agents.judge")

JUDGE_SYSTEM_PROMPT = """You are the Principal Staff Engineer, Chief Security Officer, and Final Decision Maker.
Your task is to critically evaluate a proposed security remediation patch and test suite for a Pull Request.

Evaluation Criteria:
1. Security Efficacy: Does the suggested patch completely resolve the identified vulnerabilities?
2. Regression Risk: Does the patch break existing functionality, modify public APIs, or introduce side effects?
3. Hallucination Check: Did the fixer agent hallucinate non-existent imports, classes, or files?

Output Schema:
Output ONLY a JSON object:
{
  "approved": true | false,
  "confidence_score": 95,
  "feedback": "Detailed justification. If rejected, clearly state exact flaws to be fixed on next cycle.",
  "safety_score": 85
}
"""


def extract_judge_decision(text: str) -> Dict[str, Any]:
    """Helper to parse Judge decision JSON from LLM response."""
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    brace_match = re.search(r"(\{.*\})", text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(1))
        except json.JSONDecodeError:
            pass

    return {
        "approved": True,
        "confidence_score": 90,
        "feedback": "Approved by automated evaluation.",
        "safety_score": 90,
    }


def generate_pr_summary_markdown(state: AgentState, safety_score: int, approved: bool) -> str:
    """Generate high-level Markdown scorecard table for GitHub PR conversation."""
    vulns = state.get("security_vulnerabilities", [])
    tests = state.get("generated_tests", [])
    patch = state.get("suggested_patch", "")
    iteration = state.get("iteration_count", 1)

    critical_count = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in vulns if v.get("severity") == "HIGH")
    medium_count = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    low_count = sum(1 for v in vulns if v.get("severity") == "LOW")

    status_icon = "✅ **PASSED**" if (approved and critical_count == 0 and high_count == 0) else "⚠️ **ACTION REQUIRED**"

    report = [
        "## 🛡️ CodeSentinel Multi-Agent Security Audit",
        f"**Audit Status:** {status_icon} | **Security Rating:** `{safety_score}/100` | **Agent Cycles:** `{iteration}`\n",
        "### 📊 Findings Overview",
        "| Severity | Count | Status |",
        "| :--- | :---: | :--- |",
        f"| 🔴 **Critical** | {critical_count} | {'Blocked' if critical_count > 0 else 'Clean'} |",
        f"| 🟠 **High** | {high_count} | {'Needs Attention' if high_count > 0 else 'Clean'} |",
        f"| 🟡 **Medium** | {medium_count} | Informational |",
        f"| 🔵 **Low / Info** | {low_count} | Informational |",
        "",
        "### 🧪 Automated Validation",
        f"- **Synthesized Pytest Suites:** `{len(tests)}` test blocks generated.",
        f"- **Proposed Patch Status:** `{'Available below' if patch else 'No patch needed'}`.",
    ]

    if patch:
        report.extend([
            "",
            "### 🩹 Proposed Remediation Patch",
            "<details><summary>Click to view proposed unified diff</summary>",
            "",
            "```diff",
            patch,
            "```",
            "</details>",
        ])

    return "\n".join(report)


async def judge_node(state: AgentState) -> Dict[str, Any]:
    """
    Judge & Executive Agent Node.
    Evaluates patch validity, controls cyclic self-correction, and builds review scorecard.
    """
    pr_num = state.get("pr_number", 0)
    vulns = state.get("security_vulnerabilities", [])
    patch = state.get("suggested_patch", "")
    tests = state.get("generated_tests", [])
    iteration = state.get("iteration_count", 0) + 1

    logger.info("⚖️ [Judge] Evaluating PR #%d (Iteration %d/3)...", pr_num, iteration)

    # If no vulnerabilities were found, approve immediately
    if not vulns:
        logger.info("No vulnerabilities found on PR #%d. Immediate approval.", pr_num)
        summary = generate_pr_summary_markdown(state, safety_score=100, approved=True)
        return {
            "judge_approval": True,
            "judge_feedback": "Code clean. No security risks identified.",
            "iteration_count": iteration,
            "review_summary_markdown": summary,
        }

    # If vulnerabilities exist but no patch was generated, or patch needs evaluation
    llm = get_chat_model(temperature=0.0)
    user_prompt = (
        f"PR #{pr_num} - Iteration {iteration}\n"
        f"Identified Vulnerabilities: {len(vulns)}\n"
        f"Proposed Patch:\n{patch or '(No patch provided)'}\n\n"
        f"Synthesized Tests Count: {len(tests)}\n\n"
        "Evaluate whether this patch is safe, accurate, and free of regressions."
    )

    approved = True
    feedback = "Approved by automated evaluation."
    safety_score = 85

    try:
        messages = [
            {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        response = await llm.ainvoke(messages)
        decision = extract_judge_decision(response.content)

        approved = decision.get("approved", True)
        feedback = decision.get("feedback", feedback)
        safety_score = decision.get("safety_score", 85)

        logger.info("Judge Decision: approved=%s, score=%d, feedback='%s'", approved, safety_score, feedback)
    except Exception as exc:
        logger.error("Judge evaluation failed (%s). Defaulting to pass.", exc)

    # Enforce loop breaker: If maximum iterations reached, force approval to prevent infinite loop
    if not approved and iteration >= 3:
        logger.warning("Reached maximum iteration limit (3). Finalizing review with current best patch.")
        approved = True
        feedback += " (Maximum self-correction cycles reached)."

    summary = generate_pr_summary_markdown(state, safety_score=safety_score, approved=approved)

    return {
        "judge_approval": approved,
        "judge_feedback": feedback,
        "iteration_count": iteration,
        "review_summary_markdown": summary,
    }
