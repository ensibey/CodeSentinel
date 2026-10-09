"""
Tests for ARQ background worker and PR analysis task.
"""

from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock
from src.queue.worker import analyze_pr_task


@pytest.mark.asyncio
async def test_analyze_pr_task_execution(sample_git_diff: str):
    mock_client = MagicMock()
    mock_client.get_pr_diff = AsyncMock(return_value=sample_git_diff)

    ctx = {"github_client": mock_client}
    payload = {
        "repo_name": "octocat/Hello-World",
        "pr_number": 42,
        "action": "opened",
        "head_sha": "a1b2c3d4",
        "pr_title": "Test PR",
    }

    result = await analyze_pr_task(ctx, payload)

    assert result["status"] == "completed"
    assert result["repo_name"] == "octocat/Hello-World"
    assert result["pr_number"] == 42
    assert result["files_changed_count"] == 2
    assert result["stage"] == "phase_2_langgraph_complete"
    assert result["vulnerabilities_found"] > 0
    assert result["tests_generated"] > 0
    assert result["judge_approval"] is True
    mock_client.get_pr_diff.assert_awaited_once_with("octocat/Hello-World", 42)
