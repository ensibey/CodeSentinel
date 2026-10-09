"""
Tests for full LangGraph cyclical multi-agent StateGraph execution.
"""

from __future__ import annotations
import pytest
from src.agents.graph import build_code_sentinel_graph, run_code_sentinel_workflow
from src.agents.state import AgentState


def test_build_code_sentinel_graph():
    """Graph compilation must succeed without graph errors."""
    graph = build_code_sentinel_graph()
    assert graph is not None


@pytest.mark.asyncio
async def test_full_graph_execution_with_vulnerable_pr(sample_git_diff: str):
    """End-to-end execution of LangGraph workflow on a PR containing hardcoded credentials."""
    initial_state: AgentState = {
        "repo_name": "octocat/Hello-World",
        "pr_number": 42,
        "pr_title": "feat: add user auth",
        "git_diff": sample_git_diff,
        "changed_files": [
            {"file_path": "src/auth.py", "status": "modified", "added_lines_count": 4},
            {"file_path": "tests/test_auth.py", "status": "added", "added_lines_count": 4},
        ],
        "security_vulnerabilities": [],
        "generated_tests": [],
        "suggested_patch": "",
        "judge_approval": False,
        "judge_feedback": "",
        "review_comments": [],
        "iteration_count": 0,
    }

    final_state = await run_code_sentinel_workflow(initial_state)

    # Verify that all 4 nodes executed and updated the state:
    # 1. Scanner found the vulnerability
    assert len(final_state["security_vulnerabilities"]) > 0
    # 2. Test generator synthesized tests
    assert len(final_state["generated_tests"]) > 0
    # 3. Patch creator suggested a fix
    assert len(final_state["suggested_patch"]) > 0
    # 4. Judge evaluated and approved the final result
    assert final_state["judge_approval"] is True
    assert final_state["iteration_count"] >= 1
    assert "review_summary_markdown" in final_state
    # 5. Inline comments generated
    assert len(final_state["review_comments"]) > 0
