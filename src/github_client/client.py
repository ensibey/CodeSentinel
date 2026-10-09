"""
GitHub API client for CodeSentinel.
Interacts with GitHub REST API to fetch PR diffs, file trees, and publish review comments.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
import httpx

from src.config import get_settings

logger = logging.getLogger("codesentinel.github_client")


class GitHubClient:
    """
    Asynchronous and synchronous GitHub API Client wrapper.
    Supports GitHub PAT or GitHub App installation tokens.
    """

    BASE_URL = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        settings = get_settings()
        self.token = token or settings.GITHUB_TOKEN
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CodeSentinel-Bot/0.1.0",
        }
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    def _get_auth_headers(self) -> Dict[str, str]:
        headers = dict(self.headers)
        return headers

    async def get_pull_request(self, repo_full_name: str, pr_number: int) -> Dict[str, Any]:
        """
        Fetch PR metadata (title, body, author, branches, shas).
        """
        url = f"{self.BASE_URL}/repos/{repo_full_name}/pulls/{pr_number}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._get_auth_headers())
            resp.raise_for_status()
            return resp.json()

    async def get_pr_diff(self, repo_full_name: str, pr_number: int) -> str:
        """
        Fetch the unified git diff of the PR using GitHub's diff media type.
        """
        url = f"{self.BASE_URL}/repos/{repo_full_name}/pulls/{pr_number}"
        headers = dict(self._get_auth_headers())
        headers["Accept"] = "application/vnd.github.v3.diff"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.text

    async def get_pr_files(self, repo_full_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """
        Fetch list of changed files with patch snippets.
        """
        url = f"{self.BASE_URL}/repos/{repo_full_name}/pulls/{pr_number}/files"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._get_auth_headers())
            resp.raise_for_status()
            return resp.json()

    async def post_issue_comment(self, repo_full_name: str, pr_number: int, body: str) -> Dict[str, Any]:
        """
        Post a general comment on the PR (Issue comment).
        """
        url = f"{self.BASE_URL}/repos/{repo_full_name}/issues/{pr_number}/comments"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=self._get_auth_headers(), json={"body": body})
            resp.raise_for_status()
            return resp.json()

    async def post_review_comment(
        self,
        repo_full_name: str,
        pr_number: int,
        body: str,
        commit_id: str,
        path: str,
        line: int,
        side: str = "RIGHT",
    ) -> Dict[str, Any]:
        """
        Post an inline review comment on a specific line of code.
        """
        url = f"{self.BASE_URL}/repos/{repo_full_name}/pulls/{pr_number}/comments"
        payload = {
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line,
            "side": side,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=self._get_auth_headers(), json=payload)
            resp.raise_for_status()
            return resp.json()

    async def submit_pull_request_review(
        self,
        repo_full_name: str,
        pr_number: int,
        commit_id: str,
        body: str,
        event: str = "COMMENT",  # 'APPROVE', 'REQUEST_CHANGES', 'COMMENT'
        comments: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Submit a complete PR review with summary and optional inline comments.
        """
        url = f"{self.BASE_URL}/repos/{repo_full_name}/pulls/{pr_number}/reviews"
        payload: Dict[str, Any] = {
            "commit_id": commit_id,
            "body": body,
            "event": event,
        }
        if comments:
            payload["comments"] = comments

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=self._get_auth_headers(), json=payload)
            resp.raise_for_status()
            return resp.json()
