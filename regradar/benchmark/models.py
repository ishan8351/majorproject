from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class BenchmarkMetrics(BaseModel):
    """Core quantitative evaluation metrics for IaC governance."""
    initial_violations: int
    remaining_violations: int
    fixed_violations: int
    remediation_rate: float  # Percentage of identified violations remediated
    invariant_preservation_rate: float  # Percentage of mutations preserving state continuity (100.0% goal)
    destructive_mutations_attempted: int
    destructive_mutations_blocked: int
    human_escalations_routed: int
    autonomous_patches_accepted: int
    execution_latency_seconds: float


class BenchmarkResult(BaseModel):
    """Complete evaluation report for a benchmark run."""
    benchmark_name: str
    target_path: str
    metrics: BenchmarkMetrics
    fixed_check_ids: List[str] = Field(default_factory=list)
    escalated_check_ids: List[str] = Field(default_factory=list)


class ComparativeAblationResult(BaseModel):
    """
    Ablation study comparing RegRadar against an unconstrained generative AI baseline
    (e.g., standard LLM without graph centrality bounds or dry-run invariant gates).
    """
    benchmark_name: str
    regradar_metrics: BenchmarkMetrics
    unconstrained_metrics: BenchmarkMetrics
    safety_differential_destructive_prevented: int
    hallucinations_rejected: int
