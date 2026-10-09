"""
CodeSentinel Live Demo & Local PR Event Simulator.
Simulates a real GitHub Pull Request webhook event locally,
routes it through HMAC validation, ARQ worker, AST scanner,
LangGraph multi-agent decision loop, and outputs the final GitHub review.
"""

from __future__ import annotations
import asyncio
import json
import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from src.agents.graph import run_code_sentinel_workflow
from src.agents.state import AgentState
from src.github_client.parser import GitDiffParser
from src.github_client.publisher import GitHubReviewPublisher
from src.github_client.client import GitHubClient

console = Console()

SAMPLE_VULNERABLE_DIFF = """diff --git a/src/auth.py b/src/auth.py
index e69de29..4959473 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,6 +10,8 @@ def authenticate(username, password):
     user = db.query(f"SELECT * FROM users WHERE name = '{username}'")
-    return False
+    # Hardcoded bypass key
+    if password == "SUPER_SECRET_MASTER_KEY_2026":
+        return True
+    return user is not None
"""


async def main():
    console.print(Panel.fit(
        "[bold cyan]🛡️ CodeSentinel — Autonomous Multi-Agent GitHub Reviewer[/bold cyan]\n"
        "[italic green]Simulating Incoming PR Event: #42 'feat: database & auth updates'[/italic green]",
        border_style="cyan"
    ))

    # Step 1: Parse Git Diff
    console.print("\n[bold yellow]1. Ingesting & Parsing Git Diff...[/bold yellow]")
    files = GitDiffParser.parse(SAMPLE_VULNERABLE_DIFF)
    console.print(f"   ✓ Identified [bold]{len(files)}[/bold] changed files with line-accurate AST mapping.")

    # Step 2: Initialize Agent State
    initial_state: AgentState = {
        "repo_name": "acme-corp/payment-service",
        "pr_number": 42,
        "pr_title": "feat: database & auth updates",
        "git_diff": SAMPLE_VULNERABLE_DIFF,
        "changed_files": [{"file_path": f.file_path, "status": f.status} for f in files],
        "security_vulnerabilities": [],
        "generated_tests": [],
        "suggested_patch": "",
        "judge_approval": False,
        "judge_feedback": "",
        "review_comments": [],
        "iteration_count": 0,
        "review_summary_markdown": None,
    }

    # Step 3: Execute LangGraph Multi-Agent Team
    console.print("\n[bold magenta]2. Launching LangGraph Cyclical Multi-Agent Graph...[/bold magenta]")
    console.print("   [dim]Security Scanner ➔ Test Generator ➔ Patch Creator ➔ Judge & Executive[/dim]")
    final_state = await run_code_sentinel_workflow(initial_state)

    # Step 4: Display Results Table
    vulns = final_state.get("security_vulnerabilities", [])
    tests = final_state.get("generated_tests", [])
    patch = final_state.get("suggested_patch", "")
    cycles = final_state.get("iteration_count", 1)

    table = Table(title="Audit Metrics Summary", border_style="bright_blue")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    table.add_row("Vulnerabilities Identified", f"[bold red]{len(vulns)}[/bold red]")
    table.add_row("Synthesized PyTests", f"[bold green]{len(tests)}[/bold green]")
    table.add_row("Self-Correction Cycles", f"[bold yellow]{cycles}[/bold yellow]")
    table.add_row("Remediation Patch Ready", "[bold green]YES (Unified Diff)[/bold green]" if patch else "NO")
    table.add_row("Judge Verdict", "[bold green]APPROVED[/bold green]" if final_state.get("judge_approval") else "[bold red]REJECTED[/bold red]")
    console.print(table)

    # Step 5: Render Markdown Review Scorecard
    summary_md = final_state.get("review_summary_markdown", "")
    if summary_md:
        console.print("\n[bold blue]3. Generated PR Review Markdown Scorecard:[/bold blue]")
        console.print(Panel(Markdown(summary_md), border_style="green", title="GitHub PR Review Comment"))

    # Step 6: Render Inline Review Comments
    comments = final_state.get("review_comments", [])
    if comments:
        console.print("\n[bold red]4. Generated Line-by-Line Inline Comments:[/bold red]")
        for idx, c in enumerate(comments, 1):
            console.print(Panel(
                Markdown(c["body"]),
                title=f"Inline Comment #{idx} on `{c['path']}:{c['line']}`",
                border_style="red",
            ))

    # Step 7: Publisher Dispatch (Simulated)
    publisher = GitHubReviewPublisher(client=GitHubClient(token=""))
    pub_result = await publisher.publish_review(
        repo_name="acme-corp/payment-service",
        pr_number=42,
        head_sha="a1b2c3d4",
        state=final_state,
    )
    console.print(f"\n[bold green]✓ Delivery Status:[/bold green] [bold cyan]{pub_result['status'].upper()}[/bold cyan] ([dim]Event: {pub_result.get('event')}[/dim])")
    console.print("[bold green]✨ All systems operational. Ready for Y Combinator demonstration![/bold green]\n")


if __name__ == "__main__":
    asyncio.run(main())
