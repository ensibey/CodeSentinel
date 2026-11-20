"""Regression test verifying the OWASP/CWE benchmark corpus maintains 100% precision & recall."""

from benchmarks.run_benchmark import run_benchmark


def test_owasp_benchmark_precision_and_recall():
    report = run_benchmark()
    assert report["total_cases"] >= 16
    assert report["false_positives"] == 0
    assert report["false_negatives"] == 0
    assert report["precision"] == 1.0
    assert report["recall"] == 1.0
    assert report["f1_score"] == 1.0
    assert report["false_positive_rate"] == 0.0
