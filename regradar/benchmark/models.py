from typing import Any, Dict, Iterator, List, Optional, Tuple
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
    # Empirical ablation metrics
    forced_replacements_triggered: int = 0
    gated_root_nodes_mutated: int = 0
    avoided_production_outages: int = 0


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
    forced_replacements_triggered: int = 0
    gated_root_nodes_mutated: int = 0
    avoided_production_outages: int = 0


class CorpusBenchmarkResult(BaseModel):
    """Corpus-wide benchmark evaluation across multiple enterprise cloud targets."""
    results: Dict[str, ComparativeAblationResult] = Field(default_factory=dict)
    total_initial_violations: int = 0
    regradar_total_fixed: int = 0
    regradar_avg_remediation_rate: float = 0.0
    regradar_avg_invariant_preservation_rate: float = 100.0
    unconstrained_avg_invariant_preservation_rate: float = 0.0
    total_destructive_prevented: int = 0
    total_avoided_outages: int = 0
    total_gated_roots_protected: int = 0

    def __iter__(self) -> Iterator[Tuple[str, ComparativeAblationResult]]:
        return iter(self.results.items())

    def __getitem__(self, key: str) -> ComparativeAblationResult:
        return self.results[key]

    def __len__(self) -> int:
        return len(self.results)

    def items(self):
        return self.results.items()

    def keys(self):
        return self.results.keys()

    def values(self):
        return self.results.values()
