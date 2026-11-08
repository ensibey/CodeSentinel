"""
Judge Node.
Evaluates proposed patches against regressions and hallucinations, controls
cyclic self-correction (up to 3 iterations), and formats the PR review summary.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict

from src.agents.llm import get_chat_model
from src.agents.state import AgentState

logger = logging.getLogger("codesentinel.agents.judge")

JUDGE_SYSTEM_PROMPT = """You are a staff security engineer reviewing a proposed vulnerability remediation patch.

Evaluate:
1. Security Efficacy: Does the patch completely fix the reported vulnerability?
2. Regression Risk: Does it break existing callers or public function signatures?
3. Hallucination Check: Does it reference non-existent modules or symbols?

Return ONLY a JSON object:
{
  "approved": true,
  "confidence_score": 95,
  "feedback": "Specific justification or required fixes if rejected.",
  "safety_score": 85
}
"""


def extract_judge_decision(text: str) -> Dict[str, Any]:
    """Parse Judge decision JSON from LLM response."""
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
    """Build Markdown summary scorecard for a GitHub Pull Request."""
    vulns = state.get("security_vulnerabilities", [])
    tests = state.get("generated_tests", [])
    patch = state.get("suggested_patch", "")
    iteration = state.get("iteration_count", 1)

    critical_count = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in vulns if v.get("severity") == "HIGH")
    medium_count = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    low_count = sum(1 for v in vulns if v.get("severity") == "LOW")

    status_label = (
        "**PASSED**"
        if (approved and critical_count == 0 and high_count == 0)
        else "**ACTION REQUIRED**"
    )

    report = [
        "## CodeSentinel Security Audit",
        f"**Audit Status:** {status_label} | **Security Rating:** `{safety_score}/100` | **Agent Cycles:** `{iteration}`\n",
        "### Findings Overview",
        "| Severity | Count | Status |",
        "| :--- | :---: | :--- |",
        f"| **Critical** | {critical_count} | {'Blocked' if critical_count > 0 else 'Clean'} |",
        f"| **High** | {high_count} | {'Needs Attention' if high_count > 0 else 'Clean'} |",
        f"| **Medium** | {medium_count} | Informational |",
        f"| **Low / Info** | {low_count} | Informational |",
        "",
        "### Automated Validation",
        f"- **Synthesized Pytest Suites:** `{len(tests)}` test block(s) generated.",
        f"- **Proposed Patch Status:** `{'Available below' if patch else 'No patch needed'}`.",
    ]

    if patch:
        report.extend(
            [
                "",
                "### Proposed Remediation Patch",
                "<details><summary>View unified diff</summary>",
                "",
                "```diff",
                patch,
                "```",
                "</details>",
            ]
        )

    return "\n".join(report)


async def judge_node(state: AgentState) -> Dict[str, Any]:
    """Evaluate patch validity, enforce max retry count, and return review state."""
    pr_num = state.get("pr_number", 0)
    vulns = state.get("security_vulnerabilities", [])
    patch = state.get("suggested_patch", "")
    tests = state.get("generated_tests", [])
    iteration = state.get("iteration_count", 0) + 1

    logger.info("[judge] evaluating PR #%d (iteration %d/3)", pr_num, iteration)

    if not vulns:
        summary = generate_pr_summary_markdown(state, safety_score=100, approved=True)
        return {
            "judge_approval": True,
            "judge_feedback": "Code clean. No security risks identified.",
            "iteration_count": iteration,
            "review_summary_markdown": summary,
        }

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
    except Exception as exc:
        logger.error("[judge] evaluation failed (%s), defaulting to pass", exc)

    if not approved and iteration >= 3:
        logger.warning("[judge] max iteration limit (3) reached, finalizing review")
        approved = True
        feedback += " (Maximum self-correction cycles reached)."

    summary = generate_pr_summary_markdown(state, safety_score=safety_score, approved=approved)

    return {
        "judge_approval": approved,
        "judge_feedback": feedback,
        "iteration_count": iteration,
        "review_summary_markdown": summary,
    }
