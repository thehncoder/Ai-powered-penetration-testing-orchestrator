"""
Automated Pytest Runner for Ground-Truth Benchmark Evaluation.
Runs the complete 30-case benchmark test corpus to ensure detection precision and recall
remain calibrated on every CI build.
"""

from benchmark.evaluate_benchmark import run_benchmark


def test_benchmark_corpus_precision_and_recall():
    """Verify that the benchmark evaluation achieves >= 95% precision and recall on the test corpus."""
    report = run_benchmark()
    assert report is not None
    metrics = report["metrics"]
    
    assert metrics["total_cases"] == 30
    assert metrics["false_positives"] == 0, f"False positives detected in benchmark: {metrics['false_positives']}"
    assert metrics["false_negatives"] == 0, f"False negatives detected in benchmark: {metrics['false_negatives']}"
    assert metrics["precision_percentage"] >= 95.0
    assert metrics["recall_percentage"] >= 95.0
    assert metrics["f1_score"] >= 0.95
