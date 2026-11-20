"""
Standalone CLI for running CodeSentinel static + multi-agent audits on local Python files, directories, or diffs.

Usage:
    python -m src.cli path/to/file.py
    python -m src.cli src/ --fail-on HIGH
    python -m src.cli path/to/changes.diff --full-graph
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from src.agents.ast_scanner import ASTScanner
from src.agents.graph import run_code_sentinel_workflow
from src.agents.state import AgentState, SecurityVulnerability
from src.rules_config import SEVERITY_ORDER, ScanConfig


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


def collect_python_files(target: Path, config: ScanConfig) -> List[Path]:
    """Collect Python files from a file or directory while respecting ScanConfig exclusions."""
    if target.is_file():
        return [target] if target.suffix.lower() == ".py" else []

    collected: List[Path] = []
    for path in sorted(target.rglob("*.py")):
        rel = path.relative_to(target)
        if config.is_path_excluded(rel) or config.is_path_excluded(path):
            continue
        collected.append(path)
    return collected


def scan_target_static(target: Path, config: ScanConfig) -> Tuple[List[SecurityVulnerability], int]:
    """Run deterministic AST scans on a single Python file or recursively across a directory."""
    files = collect_python_files(target, config)
    all_findings: List[SecurityVulnerability] = []
    for py_file in files:
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        display_path = str(py_file.as_posix())
        all_findings.extend(ASTScanner.scan_code(source, file_path=display_path, config=config))
    return all_findings, len(files)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="codesentinel",
        description="Run deterministic AST security checks or full LangGraph review on local files, directories, or diffs.",
    )
    parser.add_argument("target", help="Path to a Python (.py) file, directory, or unified diff (.diff/.patch)")
    parser.add_argument(
        "--full-graph",
        action="store_true",
        help="Run the full LangGraph pipeline (Scanner -> Test Gen -> Patch Creator -> Judge)",
    )
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON")
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Minimum severity level to report (overrides .codesentinel.toml)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"],
        default="LOW",
        help="Exit with code 1 if any finding meets or exceeds this severity (default: LOW)",
    )
    args = parser.parse_args(argv)

    path = Path(args.target)
    if not path.exists():
        print(f"error: target not found: {path}", file=sys.stderr)
        return 2

    config = ScanConfig.discover(path)
    if args.min_severity:
        config.min_severity = args.min_severity

    def _should_fail(items: List[dict]) -> bool:
        if args.fail_on == "NONE" or not items:
            return False
        threshold = SEVERITY_ORDER.get(args.fail_on, 1)
        return any(SEVERITY_ORDER.get(str(i.get("severity", "LOW")).upper(), 1) >= threshold for i in items)

    if not args.full_graph and (path.is_dir() or path.suffix.lower() == ".py"):
        raw_findings, files_scanned = scan_target_static(path, config)
        findings = [f.model_dump() for f in raw_findings]
        if args.json:
            print(json.dumps({"files_scanned": files_scanned, "findings": findings}, indent=2))
        else:
            if not findings:
                print(f"{path}: clean ({files_scanned} file(s) scanned, 0 vulnerabilities detected)")
            else:
                for f in findings:
                    print(
                        f"{f['file_path']}:{f['line_number']}: [{f['severity']}] {f['category']} - {f['description']}"
                    )
        return 1 if _should_fail(findings) else 0

    if path.is_dir():
        print("error: --full-graph requires a single .py or .diff/.patch file", file=sys.stderr)
        return 2

    content = path.read_text(encoding="utf-8")
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
        "review_summary_markdown": None,
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
