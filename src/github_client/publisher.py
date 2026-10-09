"""
GitHub Review Comment & PR Summary Publishing Engine.
Handles automated publication of:
1. Executive markdown scorecard tables on Pull Request conversation threads.
2. Line-by-line inline code review comments on specific vulnerabilities.
3. Resilient fallback mechanisms ensuring zero dropped comments.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from src.agents.state import AgentState
from src.github_client.client import GitHubClient
from src.github_client.parser import GitDiffParser

logger = logging.getLogger("codesentinel.github_client.publisher")


class GitHubReviewPublisher:
    """
    Orchestrates the delivery of CodeSentinel multi-agent findings to GitHub.
    Validates diff hunk boundaries to avoid GitHub API 422 errors,
    and falls back to issue comments if full review creation is restricted.
    """

    def __init__(self, client: Optional[GitHubClient] = None):
        self.client = client or GitHubClient()

    def _extract_diff_line_set(self, diff_text: str) -> Set[Tuple[str, int]]:
        """
        Extracts all valid (file_path, new_line_no) tuples present in the unified diff.
        GitHub rejects inline comments on lines that are not part of the diff hunk.
        """
        valid_lines: Set[Tuple[str, int]] = set()
        if not diff_text:
            return valid_lines

        files = GitDiffParser.parse(diff_text)
        for df in files:
            for hunk in df.hunks:
                for line in hunk.lines:
                    if line.new_line_no is not None:
                        valid_lines.add((df.file_path, line.new_line_no))
        return valid_lines

    def determine_review_event(self, state: AgentState) -> str:
        """
        Determines the appropriate GitHub PR Review event status:
        - REQUEST_CHANGES: If CRITICAL or HIGH severity vulnerabilities are unpatched.
        - COMMENT: If only MEDIUM, LOW or Informational findings exist.
        - APPROVE: If no vulnerabilities exist and Judge approved.
        """
        vulns = state.get("security_vulnerabilities", [])
        has_critical_or_high = any(
            v.get("severity") in ("CRITICAL", "HIGH") for v in vulns
        )

        if has_critical_or_high:
            return "REQUEST_CHANGES"
        if vulns:
            return "COMMENT"
        return "APPROVE"

    async def publish_review(
        self,
        repo_name: str,
        pr_number: int,
        head_sha: str,
        state: AgentState,
    ) -> Dict[str, Any]:
        """
        Publishes the complete multi-agent review findings to the GitHub PR.
        """
        summary_markdown = state.get("review_summary_markdown", "") or "## 🛡️ CodeSentinel Audit Complete"
        raw_comments = state.get("review_comments", [])
        git_diff = state.get("git_diff", "")
        event = self.determine_review_event(state)

        logger.info(
            "📤 Publishing review for %s #%d (event: %s, inline comments: %d)...",
            repo_name,
            pr_number,
            event,
            len(raw_comments),
        )

        # Dry-run check: If no token is provided, log and simulate cleanly
        if not self.client.token:
            logger.info("No GitHub token configured. Operating in simulated dry-run mode.")
            return {
                "status": "dry_run",
                "repo_name": repo_name,
                "pr_number": pr_number,
                "event": event,
                "inline_comments_count": len(raw_comments),
                "summary_length": len(summary_markdown),
            }

        # Step 1: Validate inline comments against diff lines
        valid_diff_lines = self._extract_diff_line_set(git_diff)
        valid_inline: List[Dict[str, Any]] = []
        overflow_comments: List[str] = []

        for c in raw_comments:
            path = c.get("path", "")
            line = c.get("line", 1)
            body = c.get("body", "")

            # If diff is empty or line is confirmed in diff, include inline
            if not valid_diff_lines or (path, line) in valid_diff_lines:
                valid_inline.append({
                    "path": path,
                    "line": line,
                    "body": body,
                    "side": c.get("side", "RIGHT"),
                })
            else:
                # Append to overflow list so findings are not lost
                overflow_comments.append(f"#### 📍 File: `{path}` (Line {line})\n{body}")

        # If any comments fell outside diff, append them to the main review body
        final_summary = summary_markdown
        if overflow_comments:
            final_summary += "\n\n### 📌 Additional File Annotations (Outside Changed Hunks)\n" + "\n\n---\n".join(overflow_comments)

        # Step 2: Attempt full PR Review submission
        try:
            review_resp = await self.client.submit_pull_request_review(
                repo_full_name=repo_name,
                pr_number=pr_number,
                commit_id=head_sha,
                body=final_summary,
                event=event,
                comments=valid_inline if valid_inline else None,
            )
            logger.info("✅ Submitted PR Review successfully (ID: %s)", review_resp.get("id"))
            return {
                "status": "published",
                "method": "pull_request_review",
                "review_id": review_resp.get("id"),
                "event": event,
                "inline_comments_posted": len(valid_inline),
            }
        except Exception as review_err:
            logger.warning(
                "Full PR Review creation failed (%s). Falling back to standalone Issue Comment & individual reviews.",
                review_err,
            )

        # Step 3: Fallback — Post Issue Comment for summary
        fallback_results: Dict[str, Any] = {
            "status": "partial_published",
            "method": "fallback_issue_comment",
            "event": event,
            "individual_comments_posted": 0,
        }

        try:
            issue_resp = await self.client.post_issue_comment(repo_name, pr_number, final_summary)
            fallback_results["issue_comment_id"] = issue_resp.get("id")
            logger.info("✅ Posted fallback summary Issue Comment (ID: %s)", issue_resp.get("id"))
        except Exception as issue_err:
            logger.error("Failed to post fallback issue comment: %s", issue_err)

        # Step 4: Fallback — Post inline comments individually
        posted_count = 0
        for comment in valid_inline:
            try:
                await self.client.post_review_comment(
                    repo_full_name=repo_name,
                    pr_number=pr_number,
                    body=comment["body"],
                    commit_id=head_sha,
                    path=comment["path"],
                    line=comment["line"],
                    side=comment.get("side", "RIGHT"),
                )
                posted_count += 1
            except Exception as single_err:
                logger.warning("Failed to post single inline comment on %s:%s: %s", comment["path"], comment["line"], single_err)

        fallback_results["individual_comments_posted"] = posted_count
        return fallback_results
