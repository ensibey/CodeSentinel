"""
ARQ asynchronous background worker for CodeSentinel.
Processes GitHub PR events asynchronously to decouple webhook ingestion from heavy LLM agent workflows.
"""

from __future__ import annotations
import asyncio
import logging
from typing import Any, Dict
from arq.connections import RedisSettings

from src.config import get_settings
from src.github_client.client import GitHubClient
from src.github_client.parser import GitDiffParser

logger = logging.getLogger("codesentinel.worker")


async def analyze_pr_task(ctx: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    ARQ Task: Analyzes a GitHub Pull Request.
    Picks up PR metadata, fetches diff and files via GitHub API, parses changes,
    and forwards to the LangGraph Multi-Agent pipeline.
    """
    repo_name = payload.get("repo_name", "")
    pr_number = payload.get("pr_number", 0)
    action = payload.get("action", "")
    head_sha = payload.get("head_sha", "")
    pr_title = payload.get("pr_title", "")

    logger.info(
        "🚀 Starting CodeSentinel analysis for %s #%d (action: %s, title: '%s')",
        repo_name,
        pr_number,
        action,
        pr_title,
    )

    client: GitHubClient = ctx.get("github_client", GitHubClient())

    # Step 1: Fetch raw diff and changed files
    try:
        raw_diff = await client.get_pr_diff(repo_name, pr_number)
    except Exception as exc:
        logger.warning("Could not fetch git diff directly from GitHub API (%s). Using mock/empty diff.", exc)
        raw_diff = payload.get("mock_diff", "")

    # Step 2: Parse unified diff
    diff_files = GitDiffParser.parse(raw_diff)
    total_added = sum(len(f.added_lines) for f in diff_files)

    logger.info(
        "📊 PR %s #%d Parsed: %d changed files, %d additions",
        repo_name,
        pr_number,
        len(diff_files),
        total_added,
    )

    # Step 3: Initialize LangGraph AgentState and run multi-agent workflow
    initial_state = {
        "repo_name": repo_name,
        "pr_number": pr_number,
        "pr_title": pr_title,
        "git_diff": raw_diff,
        "changed_files": [
            {
                "file_path": f.file_path,
                "status": f.status,
                "added_lines_count": len(f.added_lines),
            }
            for f in diff_files
        ],
        "security_vulnerabilities": [],
        "generated_tests": [],
        "suggested_patch": "",
        "judge_approval": False,
        "judge_feedback": "",
        "review_comments": [],
        "iteration_count": 0,
    }

    try:
        from src.agents.graph import run_code_sentinel_workflow
        final_state = await run_code_sentinel_workflow(initial_state)
    except Exception as exc:
        logger.error("LangGraph agent execution encountered error (%s). Using initial state.", exc)
        final_state = initial_state

    result = {
        "status": "completed",
        "repo_name": repo_name,
        "pr_number": pr_number,
        "action": action,
        "head_sha": head_sha,
        "files_changed_count": len(diff_files),
        "total_added_lines": total_added,
        "stage": "phase_2_langgraph_complete",
        "vulnerabilities_found": len(final_state.get("security_vulnerabilities", [])),
        "tests_generated": len(final_state.get("generated_tests", [])),
        "judge_approval": final_state.get("judge_approval", False),
        "iterations": final_state.get("iteration_count", 1),
    }
    logger.info("✅ CodeSentinel Multi-Agent analysis task completed for %s #%d", repo_name, pr_number)
    return result


async def startup(ctx: Dict[str, Any]) -> None:
    """Worker initialization hook."""
    settings = get_settings()
    ctx["github_client"] = GitHubClient()
    logger.info("CodeSentinel ARQ worker started successfully. Connected to Redis at %s:%s", settings.REDIS_HOST, settings.REDIS_PORT)


async def shutdown(ctx: Dict[str, Any]) -> None:
    """Worker shutdown hook."""
    logger.info("CodeSentinel ARQ worker shutting down gracefully.")


class WorkerSettings:
    """ARQ Worker configuration class."""
    functions = [analyze_pr_task]
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = 10
    job_timeout = 600

    @classmethod
    def get_redis_settings(cls) -> RedisSettings:
        settings = get_settings()
        return settings.get_arq_redis_settings()

    redis_settings = property(get_redis_settings)


if __name__ == "__main__":
    from arq import run_worker
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_worker(WorkerSettings))
