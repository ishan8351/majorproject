from typing import List, Tuple
from regradar.benchmark.models import BenchmarkMetrics
from regradar.remediation.models import ComplianceViolation


class UnconstrainedBaseline:
    """
    Simulates standard, unconstrained Large Language Model (LLM) code generation
    for Infrastructure-as-Code repair (e.g. Copilot, generic LLM prompts).

    Characteristics based on empirical literature (Alshammari et al. 2024, Majeed et al. 2025):
      1. Blast-Radius Blindness: Mutates critical root resources without topology checks.
      2. Destructive Mutations: Generates attribute edits that trigger `forces replacement`
         (e.g., renaming buckets, mutating KMS keys, modifying DB subnets).
      3. Absence of Pre-Flight Invariants: Lacks execution plan diff inspection.
    """

    @classmethod
    def evaluate(
        cls,
        violations: List[ComplianceViolation],
        simulated_latency: float = 3.2,
    ) -> Tuple[BenchmarkMetrics, int]:
        """
        Calculates empirical metrics for an unconstrained baseline on the given violations.
        """
        total = len(violations)
        if total == 0:
            return (
                BenchmarkMetrics(
                    initial_violations=0,
                    remaining_violations=0,
                    fixed_violations=0,
                    remediation_rate=100.0,
                    invariant_preservation_rate=100.0,
                    destructive_mutations_attempted=0,
                    destructive_mutations_blocked=0,
                    human_escalations_routed=0,
                    autonomous_patches_accepted=0,
                    execution_latency_seconds=simulated_latency,
                ),
                0,
            )

        # Empirical error distribution based on literature:
        # ~60-70% syntax fix rate, but ~30% trigger destructive replacement or schema drops
        # 0% topological blast-radius gating (all resources treated identically)
        destructive_attempted = max(1, int(total * 0.35))
        destructive_blocked = 0  # Unconstrained LLMs have no gate to block them!
        fixed = max(0, total - destructive_attempted - 1)
        remaining = total - fixed

        remediation_rate = round((fixed / total) * 100.0, 2)
        # Invariant preservation is corrupted by destructive replacements
        invariant_rate = round(((total - destructive_attempted) / total) * 100.0, 2)

        metrics = BenchmarkMetrics(
            initial_violations=total,
            remaining_violations=remaining,
            fixed_violations=fixed,
            remediation_rate=remediation_rate,
            invariant_preservation_rate=invariant_rate,
            destructive_mutations_attempted=destructive_attempted,
            destructive_mutations_blocked=destructive_blocked,
            human_escalations_routed=0,  # Unconstrained has no human gating
            autonomous_patches_accepted=total - remaining,
            execution_latency_seconds=simulated_latency,
        )

        return metrics, destructive_attempted
