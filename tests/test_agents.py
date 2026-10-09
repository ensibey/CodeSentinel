"""
Tests for individual LangGraph agent nodes:
Security Scanner, Test Generator, Patch Creator, Judge, and conditional cycle edge.
"""

from __future__ import annotations
import pytest
from src.agents.judge import judge_node
from src.agents.graph import should_continue_review
from src.agents.patch_creator import patch_creator_node
from src.agents.security_scanner import security_scanner_node
from src.agents.state import AgentState
from src.agents.test_generator import test_generator_node
from langgraph.graph import END


@pytest.fixture
def base_state(sample_git_diff: str) -> AgentState:
    return {
        "repo_name": "octocat/Hello-World",
        "pr_number": 42,
        "pr_title": "feat: authentication",
        "git_diff": sample_git_diff,
        "changed_files": [{"file_path": "src/auth.py", "status": "modified"}],
        "security_vulnerabilities": [],
        "generated_tests": [],
        "suggested_patch": "",
        "judge_approval": False,
        "judge_feedback": "",
        "review_comments": [],
        "iteration_count": 0,
    }


@pytest.mark.asyncio
async def test_security_scanner_node(base_state: AgentState):
    """Security Scanner should detect vulnerabilities and generate inline comments."""
    result = await security_scanner_node(base_state)
    vulns = result["security_vulnerabilities"]
    comments = result["review_comments"]

    assert len(vulns) > 0
    assert any("Hardcoded" in v["category"] or "CWE-798" in v["category"] for v in vulns)
    assert len(comments) == len(vulns)
    assert any("CodeSentinel Security Alert" in c["body"] for c in comments)


@pytest.mark.asyncio
async def test_test_generator_node(base_state: AgentState):
    """Test Generator should produce pytest code blocks."""
    base_state["security_vulnerabilities"] = [
        {"category": "CWE-798: Hardcoded Credentials", "severity": "CRITICAL", "file_path": "src/auth.py", "line_number": 12}
    ]
    result = await test_generator_node(base_state)
    tests = result["generated_tests"]

    assert len(tests) > 0
    assert any("pytest" in t or "def test_" in t for t in tests)


@pytest.mark.asyncio
async def test_patch_creator_node(base_state: AgentState):
    """Patch Creator should generate unified diff patch when vulnerabilities exist."""
    base_state["security_vulnerabilities"] = [
        {"category": "CWE-798: Hardcoded Credentials", "severity": "CRITICAL", "file_path": "src/auth.py", "line_number": 12}
    ]
    result = await patch_creator_node(base_state)
    patch = result["suggested_patch"]

    assert len(patch) > 0
    assert "--- a/" in patch or "@@ -" in patch


@pytest.mark.asyncio
async def test_judge_node_clean_pr(base_state: AgentState):
    """Judge should immediately approve PR with no vulnerabilities."""
    base_state["security_vulnerabilities"] = []
    result = await judge_node(base_state)

    assert result["judge_approval"] is True
    assert result["iteration_count"] == 1
    assert "review_summary_markdown" in result
    assert "Findings Overview" in result["review_summary_markdown"]


def test_should_continue_review_logic():
    """Verify cyclic loop control in conditional edge."""
    # 1. Unapproved and iteration < 3 -> should loop back to patch_creator
    state_loop: AgentState = {
        "judge_approval": False,
        "iteration_count": 1,
    }  # type: ignore
    assert should_continue_review(state_loop) == "patch_creator"

    # 2. Approved -> should terminate to END
    state_approved: AgentState = {
        "judge_approval": True,
        "iteration_count": 1,
    }  # type: ignore
    assert should_continue_review(state_approved) == END

    # 3. Unapproved but reached iteration 3 -> should terminate to END (breaker)
    state_max: AgentState = {
        "judge_approval": False,
        "iteration_count": 3,
    }  # type: ignore
    assert should_continue_review(state_max) == END
