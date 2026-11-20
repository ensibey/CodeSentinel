"""
Reproducible AST security benchmark runner for CodeSentinel.

Measures Precision, Recall, F1-Score, False Positive Rate, and scan latency (ms)
across the labeled OWASP/CWE corpus in `benchmarks/dataset/cases.py`.

Usage:
    python benchmarks/run_benchmark.py
    python benchmarks/run_benchmark.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set

# Ensure project root is importable when executed directly as a script
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from benchmarks.dataset.cases import BENCHMARK_CASES
from src.agents.ast_scanner import ASTScanner
from src.agents.rule_registry import resolve_rule_for_category


def _extract_cwes(categories: List[str]) -> Set[str]:
    found: Set[str] = set()
    for cat in categories:
        rule = resolve_rule_for_category(cat)
        if rule:
            found.add(rule.cwe)
    return found


def run_benchmark() -> Dict[str, Any]:
    tp = 0
    fp = 0
    fn = 0
    clean_total = 0
    clean_fp = 0
    latencies_ms: List[float] = []
    case_results: List[Dict[str, Any]] = []

    for case in BENCHMARK_CASES:
        t0 = time.perf_counter()
        vulns = ASTScanner.scan_code(case.source, file_path=f"{case.case_id}.py")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(elapsed_ms)

        detected_cwes = _extract_cwes([v.category for v in vulns])
        expected = case.expected_cwes

        case_tp = len(detected_cwes & expected)
        case_fp = len(detected_cwes - expected)
        case_fn = len(expected - detected_cwes)

        tp += case_tp
        fp += case_fp
        fn += case_fn

        if not expected:
            clean_total += 1
            if detected_cwes:
                clean_fp += 1

        case_results.append(
            {
                "case_id": case.case_id,
                "expected": sorted(expected),
                "detected": sorted(detected_cwes),
                "passed": (case_fp == 0 and case_fn == 0),
                "latency_ms": round(elapsed_ms, 3),
            }
        )

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = clean_fp / clean_total if clean_total > 0 else 0.0
    sorted_lat = sorted(latencies_ms)
    mean_ms = sum(sorted_lat) / len(sorted_lat) if sorted_lat else 0.0
    p95_idx = min(len(sorted_lat) - 1, int(0.95 * len(sorted_lat)))
    p95_ms = sorted_lat[p95_idx] if sorted_lat else 0.0

    return {
        "total_cases": len(BENCHMARK_CASES),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "mean_latency_ms": round(mean_ms, 3),
        "p95_latency_ms": round(p95_ms, 3),
        "cases": case_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CodeSentinel OWASP AST benchmark.")
    parser.add_argument("--json", action="store_true", help="Print full benchmark report as JSON")
    args = parser.parse_args()

    report = run_benchmark()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("CodeSentinel OWASP/CWE AST Benchmark Results")
        print("=" * 46)
        print(f"Total cases          : {report['total_cases']}")
        print(f"TP / FP / FN         : {report['true_positives']} / {report['false_positives']} / {report['false_negatives']}")
        print(f"Precision            : {report['precision'] * 100:.1f}%")
        print(f"Recall               : {report['recall'] * 100:.1f}%")
        print(f"F1-Score             : {report['f1_score'] * 100:.1f}%")
        print(f"False Positive Rate  : {report['false_positive_rate'] * 100:.1f}%")
        print(f"Mean / P95 Latency   : {report['mean_latency_ms']:.3f} ms / {report['p95_latency_ms']:.3f} ms")

    return 0 if report["false_positives"] == 0 and report["false_negatives"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
