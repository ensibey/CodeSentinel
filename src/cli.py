"""
Standalone CLI for running CodeSentinel static + multi-agent audits on local Python files or diffs.

Usage:
    python -m src.cli path/to/file.py
    python -m src.cli path/to/changes.diff --full-graph
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

from src.agents.ast_scanner import ASTScanner
from src.agents.graph import run_code_sentinel_workflow
from src.agents.state import AgentState


def _build_synthetic_diff(file_path: str, source: str) -> str:
    lines = source.splitlines()
    added = "\n".join(f"+{line}" for line in lines)
    return (
        f"diff --git a/{file_path} b/{file_path}\n"
        f"--- a/{file_path}\n"
        f"+++ b/{file_path}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        f"{added}\n"
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="codesentinel",
        description="Run deterministic AST security checks or full LangGraph review on a local file/diff.",
    )
    parser.add_argument("target", help="Path to a Python (.py) file or unified diff (.diff/.patch)")
    parser.add_argument(
        "--full-graph",
        action="store_true",
        help="Run the full LangGraph pipeline (Scanner -> Test Gen -> Patch Creator -> Judge)",
    )
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON")
    args = parser.parse_args(argv)

    path = Path(args.target)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2

    content = path.read_text(encoding="utf-8")

    if not args.full_graph and path.suffix.lower() == ".py":
        findings = ASTScanner.scan_code(content, file_path=str(path.as_posix()))
        if args.json:
            print(json.dumps(findings, indent=2))
        else:
            if not findings:
                print(f"{path}: clean (0 vulnerabilities detected)")
            else:
                for f in findings:
                    print(
                        f"{f['file_path']}:{f['line_number']}: [{f['severity']}] {f['category']} - {f['description']}"
                    )
        return 1 if findings else 0

    diff_text = content if path.suffix.lower() in (".diff", ".patch") else _build_synthetic_diff(path.name, content)
    initial_state: AgentState = {
        "repo_name": "local/workspace",
        "pr_number": 1,
        "pr_title": f"Local audit: {path.name}",
        "git_diff": diff_text,
        "changed_files": [{"file_path": path.name, "status": "modified"}],
        "security_vulnerabilities": [],
        "generated_tests": [],
        "suggested_patch": "",
        "judge_approval": False,
        "judge_feedback": "",
        "review_comments": [],
        "iteration_count": 0,
    }

    final_state = asyncio.run(run_code_sentinel_workflow(initial_state))
    vulns = final_state.get("security_vulnerabilities", [])

    if args.json:
        print(
            json.dumps(
                {
                    "vulnerabilities": vulns,
                    "suggested_patch": final_state.get("suggested_patch", ""),
                    "judge_approval": final_state.get("judge_approval", False),
                    "iterations": final_state.get("iteration_count", 0),
                },
                indent=2,
            )
        )
    else:
        print(final_state.get("review_summary_markdown", ""))

    return 1 if vulns else 0


if __name__ == "__main__":
    sys.exit(main())
