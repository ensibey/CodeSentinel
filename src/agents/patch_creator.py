"""
Agent 3: Patch / Fixer Node.
Generates unified git diff patches that resolve confirmed security vulnerabilities,
respect existing architectural patterns, and incorporate corrective feedback from the Judge.
"""

from __future__ import annotations
import logging
import re
from typing import Any, Dict

from src.agents.llm import get_chat_model
from src.agents.state import AgentState

logger = logging.getLogger("codesentinel.agents.patch_creator")

PATCH_CREATOR_SYSTEM_PROMPT = """You are a Principal Software Architect and Lead Security Remediation Engineer.
Your task is to synthesize a clean, minimal, unified git diff patch that fixes reported vulnerabilities.

Rules:
1. Generate valid unified diff syntax (starting with `--- a/<file>` and `+++ b/<file>`).
2. Fix ONLY the security flaws. Do NOT refactor working code or change public function signatures.
3. Preserve existing coding conventions, type annotations, and comments.
4. If corrective feedback from the Judge Agent is provided, you MUST address every single critique.

Output Format:
Output ONLY the unified diff patch inside a markdown diff block:
```diff
--- a/src/example.py
+++ b/src/example.py
@@ -10,3 +10,3 @@
-    vulnerable_call()
+    secure_call()
```
"""


def extract_unified_patch(text: str) -> str:
    """Extract unified diff patch from LLM output."""
    match = re.search(r"```(?:diff)?\s*(--- a/.*?)\s*```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    if text.startswith("--- a/") or "@@ -" in text:
        return text.strip()
    return ""


async def patch_creator_node(state: AgentState) -> Dict[str, Any]:
    """
    Patch Creator Agent Node.
    Produces git diff patches remediating identified vulnerabilities.
    """
    pr_num = state.get("pr_number", 0)
    git_diff = state.get("git_diff", "")
    vulns = state.get("security_vulnerabilities", [])
    judge_feedback = state.get("judge_feedback", "")
    iteration = state.get("iteration_count", 0)

    logger.info("🩹 [Patch Creator] Synthesizing remediation patch for PR #%d (Iteration: %d)...", pr_num, iteration)

    if not vulns:
        logger.info("No vulnerabilities detected on PR #%d. Skipping patch creation.", pr_num)
        return {"suggested_patch": ""}

    llm = get_chat_model(temperature=0.0)

    vuln_text = "\n".join(
        f"- {v.get('category')} ({v.get('severity')}) at {v.get('file_path')}:{v.get('line_number')}\n"
        f"  Description: {v.get('description')}\n"
        f"  Remediation: {v.get('remediation')}"
        for v in vulns
    )

    feedback_section = ""
    if judge_feedback and judge_feedback != "Approved by initial pass.":
        feedback_section = f"\n\nCRITICAL JUDGE FEEDBACK FROM PREVIOUS ATTEMPT:\n{judge_feedback}\nPlease correct these flaws.\n"

    user_prompt = (
        f"PR #{pr_num}\n"
        f"Original Diff:\n{git_diff}\n\n"
        f"Vulnerabilities to Remediate:\n{vuln_text}"
        f"{feedback_section}\n\n"
        "Generate a clean unified git diff patch fixing these vulnerabilities."
    )

    suggested_patch = ""
    try:
        messages = [
            {"role": "system", "content": PATCH_CREATOR_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        response = await llm.ainvoke(messages)
        suggested_patch = extract_unified_patch(response.content)
        logger.info("Synthesized patch length: %d chars", len(suggested_patch))
    except Exception as exc:
        logger.error("Patch creation failed (%s).", exc)
        suggested_patch = ""

    return {
        "suggested_patch": suggested_patch,
    }
