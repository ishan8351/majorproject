import json
import os
from pathlib import Path
import pytest

from regradar.models import CentralityMetrics, GraphSummary, RiskTier
from regradar.invariant.models import InvariantReport, ResourceChange
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    PatchProposal,
    RemediationStrategy,
)
from regradar.integrations.github_action import PRGateEvaluation, PRGatekeeper, main as gatekeeper_main


@pytest.fixture
def sample_graph_summary() -> GraphSummary:
    metrics = {
        "aws_vpc.main": CentralityMetrics(
            node_id="aws_vpc.main",
            resource_type="aws_vpc",
            in_degree=0,
            out_degree=3,
            descendant_count=5,
            ancestor_count=0,
            betweenness=0.6,
            blast_radius_score=0.85,
            risk_tier=RiskTier.CRITICAL_ROOT,
            auto_remediate=False,
        ),
        "aws_subnet.public": CentralityMetrics(
            node_id="aws_subnet.public",
            resource_type="aws_subnet",
            in_degree=1,
            out_degree=2,
            descendant_count=2,
            ancestor_count=1,
            betweenness=0.3,
            blast_radius_score=0.45,
            risk_tier=RiskTier.INTERMEDIATE,
            auto_remediate=True,
        ),
        "aws_s3_bucket.logs": CentralityMetrics(
            node_id="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            in_degree=0,
            out_degree=0,
            descendant_count=0,
            ancestor_count=0,
            betweenness=0.0,
            blast_radius_score=0.05,
            risk_tier=RiskTier.LEAF_SAFE,
            auto_remediate=True,
        ),
    }
    return GraphSummary(
        total_resources=3,
        total_dependencies=2,
        root_resources=["aws_vpc.main"],
        leaf_resources=["aws_s3_bucket.logs"],
        metrics=metrics,
    )


def test_pr_gatekeeper_safe_plan_verdict_pass(sample_graph_summary):
    gatekeeper = PRGatekeeper()

    safe_changes = [
        ResourceChange(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            name="logs",
            actions=["update"],
            before={"bucket": "my-logs", "tags": {"Env": "dev"}},
            after={"bucket": "my-logs", "tags": {"Env": "dev", "Compliance": "HIPAA"}},
        ),
        ResourceChange(
            address="aws_subnet.public",
            resource_type="aws_subnet",
            name="public",
            actions=["update"],
            before={"map_public_ip_on_launch": True},
            after={"map_public_ip_on_launch": False},
        ),
    ]

    evaluation: PRGateEvaluation = gatekeeper.evaluate(
        plan_changes=safe_changes,
        graph_summary=sample_graph_summary,
    )

    assert evaluation.exit_code == 0
    assert evaluation.invariant_verdict == "PASS"
    assert evaluation.is_safe is True
    assert len(evaluation.destructive_changes) == 0
    assert len(evaluation.unapproved_root_mutations) == 0

    # Markdown assertions
    md = evaluation.summary_markdown
    assert "Zero-Destruction Invariant Verdict: **PASS**" in md
    assert "CRITICAL_ROOT" in md
    assert "INTERMEDIATE" in md
    assert "LEAF_SAFE" in md
    assert "![CRITICAL_ROOT]" in md
    assert "![INTERMEDIATE]" in md
    assert "![LEAF_SAFE]" in md


def test_pr_gatekeeper_destructive_plan_verdict_fail(sample_graph_summary):
    gatekeeper = PRGatekeeper()

    destructive_changes = [
        ResourceChange(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            name="logs",
            actions=["delete"],
            before={"bucket": "my-logs"},
            after=None,
        ),
        ResourceChange(
            address="aws_subnet.public",
            resource_type="aws_subnet",
            name="public",
            actions=["delete", "create"],
            action_reason="replace_because_cannot_be_updated",
            before={"cidr_block": "10.0.1.0/24"},
            after={"cidr_block": "10.0.2.0/24"},
        ),
    ]

    evaluation = gatekeeper.evaluate(
        plan_changes=destructive_changes,
        graph_summary=sample_graph_summary,
    )

    assert evaluation.exit_code == 1
    assert evaluation.invariant_verdict == "FAIL"
    assert evaluation.is_safe is False
    assert len(evaluation.destructive_changes) == 2
    assert "Zero-Destruction Invariant Verdict: **FAIL**" in evaluation.summary_markdown


def test_pr_gatekeeper_unapproved_root_mutation_fail(sample_graph_summary):
    gatekeeper = PRGatekeeper()

    root_change = [
        ResourceChange(
            address="aws_vpc.main",
            resource_type="aws_vpc",
            name="main",
            actions=["update"],
            before={"enable_dns_hostnames": True},
            after={"enable_dns_hostnames": False},
        )
    ]

    evaluation = gatekeeper.evaluate(
        plan_changes=root_change,
        graph_summary=sample_graph_summary,
    )

    assert evaluation.exit_code == 1
    assert evaluation.invariant_verdict == "FAIL"
    assert len(evaluation.unapproved_root_mutations) == 1
    assert evaluation.unapproved_root_mutations[0].address == "aws_vpc.main"
    assert "Unapproved Root Mutations" in evaluation.summary_markdown
    assert "aws_vpc.main" in evaluation.summary_markdown


def test_pr_gatekeeper_approved_root_mutation_pass(sample_graph_summary):
    gatekeeper = PRGatekeeper()

    root_change = [
        ResourceChange(
            address="aws_vpc.main",
            resource_type="aws_vpc",
            name="main",
            actions=["update"],
            before={"enable_dns_hostnames": True},
            after={"enable_dns_hostnames": False},
        )
    ]

    evaluation = gatekeeper.evaluate(
        plan_changes=root_change,
        graph_summary=sample_graph_summary,
        approved_resources=["aws_vpc.main"],
    )

    assert evaluation.exit_code == 0
    assert evaluation.invariant_verdict == "PASS"
    assert len(evaluation.unapproved_root_mutations) == 0
    assert evaluation.is_safe is True


def test_pr_gatekeeper_approved_destructive_pass(sample_graph_summary):
    gatekeeper = PRGatekeeper()

    destructive = [
        ResourceChange(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            name="logs",
            actions=["delete"],
            before={"bucket": "my-logs"},
            after=None,
        )
    ]

    evaluation = gatekeeper.evaluate(
        plan_changes=destructive,
        graph_summary=sample_graph_summary,
        approved_resources={"aws_s3_bucket.logs"},
    )

    assert evaluation.exit_code == 0
    assert evaluation.invariant_verdict == "PASS"
    assert len(evaluation.destructive_changes) == 0


def test_pr_gatekeeper_autonomous_patches_and_manual_signoff(sample_graph_summary):
    gatekeeper = PRGatekeeper()

    violations = [
        ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="Ensure S3 bucket has server side encryption",
            resource_id="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        ComplianceViolation(
            check_id="CKV_AWS_119",
            check_name="Ensure VPC flow logging is enabled",
            resource_id="aws_vpc.main",
            resource_type="aws_vpc",
            file_path="main.tf",
        ),
    ]

    evaluation = gatekeeper.evaluate(
        graph_summary=sample_graph_summary,
        violations=violations,
        plan_changes=[],
    )

    assert evaluation.exit_code == 0
    assert evaluation.invariant_verdict == "PASS"
    assert len(evaluation.tasks) == 2

    # Autonomous patch should be synthesized for CKV_AWS_19
    assert len(evaluation.verified_patches) >= 1
    assert any("aws_s3_bucket.logs" in p.resource_id for p in evaluation.verified_patches)

    # Manual sign-off required for aws_vpc.main
    assert len(evaluation.manual_signoff_items) == 1
    assert evaluation.manual_signoff_items[0].violation.resource_id == "aws_vpc.main"

    md = evaluation.summary_markdown
    assert "Verified Autonomous Patches" in md
    assert "Manual Security Sign-Off Required" in md
    assert "aws_vpc.main" in md


def test_pr_gatekeeper_parse_destructive_plan_file(fixtures_dir, sample_graph_summary):
    plan_json_path = fixtures_dir / "sample_destructive_plan.json"
    gatekeeper = PRGatekeeper()

    evaluation = gatekeeper.evaluate(
        plan_path=plan_json_path,
        graph_summary=sample_graph_summary,
    )

    assert evaluation.exit_code == 1
    assert evaluation.invariant_verdict == "FAIL"
    assert len(evaluation.destructive_changes) > 0


def test_pr_gatekeeper_cli_main_entrypoint(tmp_path, fixtures_dir, monkeypatch):
    plan_json_path = fixtures_dir / "sample_destructive_plan.json"
    out_md = tmp_path / "pr_comment.md"
    out_json = tmp_path / "eval.json"
    step_summary = tmp_path / "step_summary.md"
    step_summary.touch()

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))

    test_args = [
        "github_action.py",
        "--dir", str(fixtures_dir / "simple_vpc"),
        "--plan", str(plan_json_path),
        "--output", str(out_md),
        "--json", str(out_json),
    ]
    monkeypatch.setattr("sys.argv", test_args)

    with pytest.raises(SystemExit) as exc_info:
        gatekeeper_main()

    assert exc_info.value.code == 1
    assert out_md.exists()
    assert out_json.exists()
    assert step_summary.stat().st_size > 0

    json_content = json.loads(out_json.read_text(encoding="utf-8"))
    assert json_content["exit_code"] == 1
    assert json_content["invariant_verdict"] == "FAIL"


def test_pr_gatekeeper_cli_safe_approved_exit_zero(tmp_path, fixtures_dir, monkeypatch):
    out_md = tmp_path / "pr_comment.md"

    test_args = [
        "github_action.py",
        "--dir", str(fixtures_dir / "simple_vpc"),
        "--output", str(out_md),
        "--approved", "aws_vpc.main",
    ]
    monkeypatch.setattr("sys.argv", test_args)

    with pytest.raises(SystemExit) as exc_info:
        gatekeeper_main()

    assert exc_info.value.code == 0
    assert out_md.exists()
    assert "PASS" in out_md.read_text(encoding="utf-8")
