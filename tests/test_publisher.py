"""
Tests for GitHub Review Publisher and PR comment engine.
"""

from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.agents.state import AgentState
from src.github_client.client import GitHubClient
from src.github_client.publisher import GitHubReviewPublisher


@pytest.fixture
def mock_state_with_critical() -> AgentState:
    return {
        "repo_name": "octocat/Hello-World",
        "pr_number": 42,
        "pr_title": "feat: test",
        "git_diff": "diff --git a/src/auth.py b/src/auth.py\n@@ -10,2 +10,2 @@\n def login():\n+    secret = '123456789'\n",
        "changed_files": [{"file_path": "src/auth.py", "status": "modified"}],
        "security_vulnerabilities": [
            {
                "file_path": "src/auth.py",
                "line_number": 11,
                "category": "CWE-798: Hardcoded Credentials",
                "severity": "CRITICAL",
                "description": "Hardcoded secret exposed.",
                "remediation": "Move to env.",
            }
        ],
        "generated_tests": ["def test_dummy(): assert True"],
        "suggested_patch": "--- a/src/auth.py\n+++ b/src/auth.py\n",
        "judge_approval": True,
        "judge_feedback": "Approved.",
        "review_comments": [
            {
                "path": "src/auth.py",
                "line": 11,
                "body": "### 🛡️ CodeSentinel Alert: Hardcoded Secret",
                "side": "RIGHT",
            }
        ],
        "iteration_count": 1,
        "review_summary_markdown": "## 🛡️ Summary Table\nCritical: 1",
    }


def test_determine_review_event():
    publisher = GitHubReviewPublisher(client=GitHubClient(token="token"))

    # 1. Critical flaw -> REQUEST_CHANGES
    state_crit = {"security_vulnerabilities": [{"severity": "CRITICAL"}]}
    assert publisher.determine_review_event(state_crit) == "REQUEST_CHANGES"  # type: ignore

    # 2. Medium flaw -> COMMENT
    state_med = {"security_vulnerabilities": [{"severity": "MEDIUM"}]}
    assert publisher.determine_review_event(state_med) == "COMMENT"  # type: ignore

    # 3. Clean -> APPROVE
    state_clean = {"security_vulnerabilities": []}
    assert publisher.determine_review_event(state_clean) == "APPROVE"  # type: ignore


@pytest.mark.asyncio
async def test_publish_review_dry_run(mock_state_with_critical: AgentState):
    """When no GitHub token is configured, publisher simulates dry run cleanly."""
    mock_client = GitHubClient(token="")
    publisher = GitHubReviewPublisher(client=mock_client)

    result = await publisher.publish_review(
        repo_name="octocat/Hello-World",
        pr_number=42,
        head_sha="a1b2c3d4",
        state=mock_state_with_critical,
    )

    assert result["status"] == "dry_run"
    assert result["event"] == "REQUEST_CHANGES"
    assert result["inline_comments_count"] == 1


@pytest.mark.asyncio
async def test_publish_review_full_pr_review_success(mock_state_with_critical: AgentState):
    """Successful submission via submit_pull_request_review."""
    mock_client = MagicMock()
    mock_client.token = "valid_pat_token"
    mock_client.submit_pull_request_review = AsyncMock(return_value={"id": 999, "state": "CHANGES_REQUESTED"})

    publisher = GitHubReviewPublisher(client=mock_client)
    result = await publisher.publish_review(
        repo_name="octocat/Hello-World",
        pr_number=42,
        head_sha="a1b2c3d4",
        state=mock_state_with_critical,
    )

    assert result["status"] == "published"
    assert result["method"] == "pull_request_review"
    assert result["review_id"] == 999
    assert result["event"] == "REQUEST_CHANGES"
    assert result["inline_comments_posted"] == 1
    mock_client.submit_pull_request_review.assert_awaited_once()


@pytest.mark.asyncio
async def test_publish_review_fallback_on_error(mock_state_with_critical: AgentState):
    """When full PR review API fails (e.g. self-review or permissions), fallback to issue + individual comments."""
    mock_client = MagicMock()
    mock_client.token = "valid_pat_token"
    mock_client.submit_pull_request_review = AsyncMock(side_effect=Exception("422 Unprocessable Entity"))
    mock_client.post_issue_comment = AsyncMock(return_value={"id": 1001})
    mock_client.post_review_comment = AsyncMock(return_value={"id": 2001})

    publisher = GitHubReviewPublisher(client=mock_client)
    result = await publisher.publish_review(
        repo_name="octocat/Hello-World",
        pr_number=42,
        head_sha="a1b2c3d4",
        state=mock_state_with_critical,
    )

    assert result["status"] == "partial_published"
    assert result["method"] == "fallback_issue_comment"
    assert result["issue_comment_id"] == 1001
    assert result["individual_comments_posted"] == 1
    mock_client.post_issue_comment.assert_awaited_once()
    mock_client.post_review_comment.assert_awaited_once()


@pytest.mark.asyncio
async def test_overflow_comments_outside_diff(mock_state_with_critical: AgentState):
    """Comments on lines outside the diff hunk should be appended to summary body instead of sent inline."""
    # Comment is on line 999, which is not in the diff (diff only has line 10-11)
    mock_state_with_critical["review_comments"] = [
        {"path": "src/auth.py", "line": 999, "body": "Alert on untouched line", "side": "RIGHT"}
    ]

    mock_client = MagicMock()
    mock_client.token = "valid_pat_token"
    mock_client.submit_pull_request_review = AsyncMock(return_value={"id": 999})

    publisher = GitHubReviewPublisher(client=mock_client)
    result = await publisher.publish_review(
        repo_name="octocat/Hello-World",
        pr_number=42,
        head_sha="a1b2c3d4",
        state=mock_state_with_critical,
    )

    assert result["status"] == "published"
    assert result["inline_comments_posted"] == 0  # Line 999 was diverted to summary
    # Check that body includes the overflow note
    call_kwargs = mock_client.submit_pull_request_review.await_args.kwargs
    assert "Additional File Annotations" in call_kwargs["body"]
    assert "Line 999" in call_kwargs["body"]
