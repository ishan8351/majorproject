from pathlib import Path
from unittest.mock import MagicMock
import pytest

from regradar.benchmark.evaluator import BenchmarkEvaluator
from regradar.benchmark.baselines import UnconstrainedBaseline
from regradar.benchmark.report_generator import ReportGenerator
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    PatchProposal,
    RemediationStrategy,
    RemediationTask,
    SwarmExecutionResult,
)


def test_unconstrained_baseline_computation():
    violations = [
        ComplianceViolation(
            check_id=f"CKV_AWS_{i}",
            check_name=f"Violation {i}",
            resource_id=f"aws_resource.{i}",
            resource_type="aws_resource",
            file_path="main.tf",
        )
        for i in range(10)
    ]

    metrics, destructive = UnconstrainedBaseline.evaluate(violations)
    assert metrics.initial_violations == 10
    assert metrics.invariant_preservation_rate < 100.0
    assert metrics.destructive_mutations_attempted > 0
    assert metrics.destructive_mutations_blocked == 0
    assert destructive == metrics.destructive_mutations_attempted


def test_evaluator_metrics_with_mock_coordinator(simple_vpc_path: Path):
    mock_coordinator = MagicMock()
    mock_coordinator.remediate_directory.return_value = SwarmExecutionResult(
        target_path=str(simple_vpc_path),
        total_violations_found=5,
        autonomous_remediations_eligible=3,
        human_escalations_required=2,
        patches_verified_and_accepted=3,
        patches_rejected_and_escalated=0,
        accepted_patches=[
            PatchProposal(
                resource_id="aws_s3_bucket.logs",
                target_file="main.tf",
                strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
                is_verified=True,
            )
        ],
        tasks=[],
    )

    evaluator = BenchmarkEvaluator(coordinator=mock_coordinator)
    res = evaluator.evaluate_target(simple_vpc_path)

    assert res.metrics.initial_violations == 5
    assert res.metrics.fixed_violations == 3
    assert res.metrics.remediation_rate == 60.0
    assert res.metrics.invariant_preservation_rate == 100.0  # Mathematical zero-destruction guarantee
    assert res.metrics.human_escalations_routed == 2


def test_report_generator_markdown_and_latex(simple_vpc_path: Path):
    mock_coordinator = MagicMock()
    mock_coordinator.remediate_directory.return_value = SwarmExecutionResult(
        target_path=str(simple_vpc_path),
        total_violations_found=4,
        autonomous_remediations_eligible=3,
        human_escalations_required=1,
        patches_verified_and_accepted=3,
        patches_rejected_and_escalated=0,
    )

    evaluator = BenchmarkEvaluator(coordinator=mock_coordinator)
    result = evaluator.evaluate_target(simple_vpc_path)
    ablation = evaluator.run_comparative_ablation(
        simple_vpc_path,
        precomputed_violations=[
            ComplianceViolation(
                check_id=f"CKV_AWS_{i}",
                check_name=f"Violation {i}",
                resource_id=f"aws_resource.{i}",
                resource_type="aws_resource",
                file_path="main.tf",
            )
            for i in range(4)
        ],
    )

    md = ReportGenerator.generate_markdown_report(result, ablation)
    assert "# RegRadar Empirical Governance Benchmark Report" in md
    assert "Invariant Preservation Rate" in md
    assert "Comparative Ablation Study" in md

    latex = ReportGenerator.generate_latex_table(ablation)
    assert r"\begin{table}" in latex
    assert "RegRadar (Ours)" in latex
    assert r"\end{table}" in latex
