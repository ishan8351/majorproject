from pathlib import Path
import pytest

from regradar.models import CentralityMetrics, GraphSummary, RiskTier
from regradar.remediation.agents import AuditorAgent, PolicyPlannerAgent, SynthesizerAgent
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    RemediationStrategy,
)


def test_auditor_agent_gating():
    # Setup mock graph metrics
    metrics = {
        "aws_vpc.prod_vpc": CentralityMetrics(
            node_id="aws_vpc.prod_vpc",
            resource_type="aws_vpc",
            in_degree=0,
            out_degree=4,
            descendant_count=6,
            ancestor_count=0,
            betweenness=0.5,
            blast_radius_score=0.75,
            risk_tier=RiskTier.CRITICAL_ROOT,
            auto_remediate=False,
        ),
        "aws_s3_bucket.audit_logs": CentralityMetrics(
            node_id="aws_s3_bucket.audit_logs",
            resource_type="aws_s3_bucket",
            in_degree=0,
            out_degree=0,
            descendant_count=0,
            ancestor_count=0,
            betweenness=0.0,
            blast_radius_score=0.0,
            risk_tier=RiskTier.LEAF_SAFE,
            auto_remediate=True,
        ),
    }

    summary = GraphSummary(
        total_resources=2,
        total_dependencies=1,
        root_resources=["aws_vpc.prod_vpc"],
        leaf_resources=["aws_s3_bucket.audit_logs"],
        metrics=metrics,
    )

    auditor = AuditorAgent(summary)

    violations = [
        ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption",
            resource_id="aws_s3_bucket.audit_logs",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="Hypothetical VPC Violation",
            resource_id="aws_vpc.prod_vpc",
            resource_type="aws_vpc",
            file_path="main.tf",
        ),
    ]

    tasks = auditor.audit_and_gate(violations)
    assert len(tasks) == 2

    # S3 bucket should be eligible
    t_s3 = next(t for t in tasks if t.violation.resource_id == "aws_s3_bucket.audit_logs")
    assert t_s3.gating_status == GatingStatus.AUTONOMOUS_ELIGIBLE

    # VPC should be gated for human escalation
    t_vpc = next(t for t in tasks if t.violation.resource_id == "aws_vpc.prod_vpc")
    assert t_vpc.gating_status == GatingStatus.HUMAN_ESCALATION_REQUIRED

    # Planner should only pick eligible tasks
    eligible = PolicyPlannerAgent.filter_eligible_tasks(tasks)
    assert len(eligible) == 1
    assert eligible[0].violation.resource_id == "aws_s3_bucket.audit_logs"


def test_synthesizer_agent_additive_attachment():
    metrics = {
        "aws_s3_bucket.audit_logs": CentralityMetrics(
            node_id="aws_s3_bucket.audit_logs",
            resource_type="aws_s3_bucket",
            in_degree=0,
            out_degree=0,
            descendant_count=0,
            ancestor_count=0,
            betweenness=0.0,
            blast_radius_score=0.0,
            risk_tier=RiskTier.LEAF_SAFE,
            auto_remediate=True,
        )
    }
    summary = GraphSummary(
        total_resources=1,
        total_dependencies=0,
        root_resources=["aws_s3_bucket.audit_logs"],
        leaf_resources=["aws_s3_bucket.audit_logs"],
        metrics=metrics,
    )

    auditor = AuditorAgent(summary)
    v = ComplianceViolation(
        check_id="CKV_AWS_19",
        check_name="S3 Encryption",
        resource_id="aws_s3_bucket.audit_logs",
        resource_type="aws_s3_bucket",
        file_path="main.tf",
    )
    task = auditor.audit_and_gate([v])[0]

    synthesizer = SynthesizerAgent()
    base_hcl = 'resource "aws_s3_bucket" "audit_logs" {\n  bucket = "my-audit-logs"\n}\n'
    proposal = synthesizer.synthesize_patch(task, base_hcl)

    assert proposal.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT
    assert "aws_s3_bucket_server_side_encryption_configuration" in proposal.remediated_snippet
    assert "aws_s3_bucket.audit_logs.id" in proposal.remediated_snippet
    assert 'resource "aws_s3_bucket" "audit_logs"' in proposal.modified_content
