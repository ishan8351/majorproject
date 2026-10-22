"""
Empirical Benchmarking and Evaluation Engine for RegRadar.
"""

from regradar.benchmark.models import (
    BenchmarkResult,
    ComparativeAblationResult,
    BenchmarkMetrics,
)
from regradar.benchmark.evaluator import BenchmarkEvaluator
from regradar.benchmark.baselines import UnconstrainedBaseline
from regradar.benchmark.report_generator import ReportGenerator

__all__ = [
    "BenchmarkResult",
    "ComparativeAblationResult",
    "BenchmarkMetrics",
    "BenchmarkEvaluator",
    "UnconstrainedBaseline",
    "ReportGenerator",
]
