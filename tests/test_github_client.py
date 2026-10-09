"""
Tests for GitHub API client wrapper.
"""

from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock
from src.github_client.client import GitHubClient


def test_github_client_init():
    client = GitHubClient(token="test_token_123")
    assert client.token == "test_token_123"
    assert client.headers["Authorization"] == "Bearer test_token_123"
    assert "CodeSentinel" in client.headers["User-Agent"]


@pytest.mark.asyncio
async def test_get_pull_request():
    client = GitHubClient(token="test_token_123")
    mock_response = MagicMock()
    mock_response.json.return_value = {"id": 1, "title": "Test PR", "number": 10}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", return_value=mock_response) as mock_get:
        data = await client.get_pull_request("octocat/repo", 10)
        assert data["number"] == 10
        assert data["title"] == "Test PR"
        mock_get.assert_called_once()


@pytest.mark.asyncio
async def test_get_pr_diff():
    client = GitHubClient(token="test_token_123")
    mock_response = MagicMock()
    mock_response.text = "diff --git a/test.py b/test.py\n+print('hello')"
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.get", return_value=mock_response) as mock_get:
        diff = await client.get_pr_diff("octocat/repo", 10)
        assert "diff --git" in diff
        mock_get.assert_called_once()


@pytest.mark.asyncio
async def test_post_issue_comment():
    client = GitHubClient(token="test_token_123")
    mock_response = MagicMock()
    mock_response.json.return_value = {"id": 100, "body": "Audit Complete"}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
        res = await client.post_issue_comment("octocat/repo", 10, "Audit Complete")
        assert res["id"] == 100
        mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_post_review_comment():
    client = GitHubClient(token="test_token_123")
    mock_response = MagicMock()
    mock_response.json.return_value = {"id": 200, "line": 15, "path": "app.py"}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
        res = await client.post_review_comment(
            repo_full_name="octocat/repo",
            pr_number=10,
            body="Potential SQL injection detected here.",
            commit_id="sha123",
            path="app.py",
            line=15,
        )
        assert res["id"] == 200
        mock_post.assert_called_once()
