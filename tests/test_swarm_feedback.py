"""
Comprehensive test suite for closed-loop self-correction feedback loop.

Tests multi-agent swarm adaptation when initial patches trigger invariant violations:
- Forces replacement diagnosis -> switch to additive attachment
- Semantic verification failure diagnosis -> complete missing attribute
- Security regression detection -> revert insecure changes
- Retry exhaustion -> human escalation
- End-to-end SwarmCoordinator closed-loop feedback workflow
"""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from regradar.invariant.models import (
    InvariantReport,
    InvariantViolation,
    ResourceChange,
    ViolationType,
)
from regradar.invariant.semantic_verifier import (
    SemanticInvariantVerifier,
    SemanticVerificationResult,
    SemanticViolation,
    SemanticViolationType,
)
from regradar.models import CentralityMetrics, GraphSummary, RiskTier
from regradar.remediation.agents import (
    AuditorAgent,
    PolicyPlannerAgent,
    SupervisorAgent,
    SynthesizerAgent,
)
from regradar.remediation.llm.client import MockLLMClient
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    PatchProposal,
    RemediationAction,
    RemediationStrategy,
    RemediationTask,
)
from regradar.remediation.state_machine import (
    RemediationContext,
    RemediationState,
    SwarmStateMachine,
)
from regradar.remediation.swarm_coordinator import SwarmCoordinator


# ==============================================================================
# 1. Forces Replacement Invariant Feedback Loop
# ==============================================================================

def test_supervisor_forces_replacement_feedback_loop(tmp_path: Path):
    """
    Validates that when an initial in-place patch triggers 'FORCES_REPLACEMENT',
    the Supervisor diagnoses the failure, switches strategy to ADDITIVE_ATTACHMENT,
    and the Synthesizer successfully repairs the patch on retry.
    """
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_s3_bucket" "prod_vault" {\n  bucket = "prod-vault"\n}\n')

    # Mock Sandbox Runner simulating 2 attempts:
    # Attempt 1: Rejects with FORCES_REPLACEMENT
    # Attempt 2: Accepts with safe additive creation
    mock_sandbox = MagicMock()
    rep_report = InvariantReport(
        is_safe=False,
        zero_destruction_guarantee_met=False,
        total_resources_evaluated=1,
        count_replaced=1,
        violations=[
            InvariantViolation(
                resource_address="aws_s3_bucket.prod_vault",
                violation_type=ViolationType.FORCES_REPLACEMENT,
                actions=["delete", "create"],
                action_reason="forces replacement",
                message="Plan mutates immutable identifier: forces replacement on aws_s3_bucket.prod_vault",
            )
        ],
    )
    safe_report = InvariantReport(
        is_safe=True,
        zero_destruction_guarantee_met=True,
        total_resources_evaluated=2,
        count_created=1,
        changes=[
            ResourceChange(
                address="aws_s3_bucket_server_side_encryption_configuration.prod_vault_encryption",
                resource_type="aws_s3_bucket_server_side_encryption_configuration",
                name="prod_vault_encryption",
                actions=["create"],
                after={"bucket": "aws_s3_bucket.prod_vault.id"},
            )
        ],
    )
    mock_sandbox.simulate_and_verify.side_effect = [rep_report, safe_report]

    mock_llm = MockLLMClient()
    synthesizer = SynthesizerAgent(llm_client=mock_llm)
    supervisor = SupervisorAgent(
        sandbox_runner=mock_sandbox,
        llm_client=mock_llm,
        max_retries=3,
    )

    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption at Rest",
            resource_id="aws_s3_bucket.prod_vault",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        action=RemediationAction(
            check_id="CKV_AWS_19",
            framework="HIPAA",
            statute_reference="HIPAA §164.312(a)(2)(iv)",
            strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
            target_attribute="server_side_encryption_configuration",
            attribute_value='server_side_encryption_configuration {\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}',
            additive_resource_template='resource "aws_s3_bucket_server_side_encryption_configuration" "{name}_encryption" {{\n  bucket = {resource_id}.id\n\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = "AES256"\n    }}\n  }}\n}}',
            description="Enable S3 bucket default encryption",
        ),
        reason="Autonomous leaf repair",
    )

    ctx = RemediationContext(task=task, current_state=RemediationState.SYNTHESIZE, max_retries=3)

    # Initial patch synthesis (in-place)
    initial_proposal = synthesizer.synthesize_patch(task, tf_file.read_text())

    # Supervisor verification loop
    verified = supervisor.verify_and_refine(
        base_dir=tmp_path,
        proposal=initial_proposal,
        task=task,
        synthesizer=synthesizer,
        state_context=ctx,
        file_content=tf_file.read_text(),
    )

    assert verified.is_verified is True
    assert verified.attempts == 2
    # Strategy was automatically refined to ADDITIVE_ATTACHMENT
    assert verified.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT
    assert len(verified.feedback_history) == 1
    assert "Attempt 1 rejected [FORCES_REPLACEMENT]" in verified.feedback_history[0]
    assert "ADDITIVE_ATTACHMENT" in verified.feedback_history[0]

    # Verify state transitions reached ACCEPT
    assert ctx.is_accepted is True
    state_names = [t.to_state.value for t in ctx.history]
    assert "SANDBOX_SIMULATE" in state_names
    assert "RETRY_WITH_FEEDBACK" in state_names
    assert "ACCEPT" in state_names


# ==============================================================================
# 2. Semantic Unmet Requirement Feedback Loop
# ==============================================================================

def test_supervisor_semantic_unmet_requirement_feedback_loop(tmp_path: Path):
    """
    Validates that when a patch passes sandbox dry-run (zero destruction)
    but fails semantic compliance verification, the Supervisor diagnoses the
    unmet requirement and guides the Synthesizer to complete the patch on retry.
    """
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_s3_bucket" "audit_data" {\n  bucket = "audit-data"\n}\n')

    # Sandbox accepts both attempts with zero destruction
    mock_sandbox = MagicMock()
    # Attempt 1 plan changes: bucket updated but encryption attribute not configured
    report_attempt1 = InvariantReport(
        is_safe=True,
        zero_destruction_guarantee_met=True,
        total_resources_evaluated=1,
        count_updated=1,
        changes=[
            ResourceChange(
                address="aws_s3_bucket.audit_data",
                resource_type="aws_s3_bucket",
                name="audit_data",
                actions=["update"],
                before={"bucket": "audit-data"},
                after={"bucket": "audit-data", "tags": {"Env": "prod"}},  # encryption missing
            )
        ],
    )
    # Attempt 2 plan changes: encryption properly configured
    report_attempt2 = InvariantReport(
        is_safe=True,
        zero_destruction_guarantee_met=True,
        total_resources_evaluated=2,
        count_created=1,
        changes=[
            ResourceChange(
                address="aws_s3_bucket_server_side_encryption_configuration.audit_data_encryption",
                resource_type="aws_s3_bucket_server_side_encryption_configuration",
                name="audit_data_encryption",
                actions=["create"],
                after={
                    "bucket": "aws_s3_bucket.audit_data.id",
                    "rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}},
                },
            )
        ],
    )
    mock_sandbox.simulate_and_verify.side_effect = [report_attempt1, report_attempt2]

    semantic_verifier = SemanticInvariantVerifier()
    mock_llm = MockLLMClient()
    synthesizer = SynthesizerAgent(llm_client=mock_llm)
    supervisor = SupervisorAgent(
        sandbox_runner=mock_sandbox,
        semantic_verifier=semantic_verifier,
        llm_client=mock_llm,
        max_retries=3,
    )

    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption at Rest",
            resource_id="aws_s3_bucket.audit_data",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        action=RemediationAction(
            check_id="CKV_AWS_19",
            framework="HIPAA",
            statute_reference="HIPAA §164.312(a)(2)(iv)",
            strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
            target_attribute="server_side_encryption_configuration",
            additive_resource_template='resource "aws_s3_bucket_server_side_encryption_configuration" "{name}_encryption" {{\n  bucket = {resource_id}.id\n\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = "AES256"\n    }}\n  }}\n}}',
            description="Enable S3 bucket default encryption",
        ),
        reason="Autonomous leaf repair",
    )

    ctx = RemediationContext(task=task, current_state=RemediationState.SYNTHESIZE, max_retries=3)
    initial_proposal = PatchProposal(
        resource_id="aws_s3_bucket.audit_data",
        target_file="main.tf",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        modified_content=tf_file.read_text(),
    )

    verified = supervisor.verify_and_refine(
        base_dir=tmp_path,
        proposal=initial_proposal,
        task=task,
        synthesizer=synthesizer,
        state_context=ctx,
        file_content=tf_file.read_text(),
    )

    assert verified.is_verified is True
    assert verified.attempts == 2
    assert any("UNMET_REQUIREMENT" in fb or "SEMANTIC" in fb for fb in verified.feedback_history)
    assert ctx.is_accepted is True


# ==============================================================================
# 3. Retry Exhaustion and Escalation
# ==============================================================================

def test_supervisor_exhausts_retries_and_escalates(tmp_path: Path):
    """
    Validates that when invariant violations persist across all attempts,
    the supervisor halts retries and transitions to ESCALATE.
    """
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_s3_bucket" "unfixable" {\n  bucket = "unfixable"\n}\n')

    mock_sandbox = MagicMock()
    failing_report = InvariantReport(
        is_safe=False,
        zero_destruction_guarantee_met=False,
        total_resources_evaluated=1,
        violations=[
            InvariantViolation(
                resource_address="aws_s3_bucket.unfixable",
                violation_type=ViolationType.UNINTENDED_DELETION,
                actions=["delete"],
                message="Resource was deleted",
            )
        ],
    )
    mock_sandbox.simulate_and_verify.return_value = failing_report

    mock_llm = MockLLMClient()
    synthesizer = SynthesizerAgent(llm_client=mock_llm)
    supervisor = SupervisorAgent(
        sandbox_runner=mock_sandbox,
        llm_client=mock_llm,
        max_retries=2,
    )

    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption",
            resource_id="aws_s3_bucket.unfixable",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        reason="Leaf safe",
    )

    ctx = RemediationContext(task=task, current_state=RemediationState.SYNTHESIZE, max_retries=2)
    initial_proposal = PatchProposal(
        resource_id="aws_s3_bucket.unfixable",
        target_file="main.tf",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        modified_content=tf_file.read_text(),
    )

    verified = supervisor.verify_and_refine(
        base_dir=tmp_path,
        proposal=initial_proposal,
        task=task,
        synthesizer=synthesizer,
        state_context=ctx,
        file_content=tf_file.read_text(),
    )

    assert verified.is_verified is False
    assert verified.attempts == 2
    assert ctx.is_escalated is True
    assert ctx.current_state == RemediationState.ESCALATE


# ==============================================================================
# 4. End-to-End SwarmCoordinator with Closed-Loop Feedback
# ==============================================================================

def test_swarm_coordinator_closed_loop_feedback_integration(tmp_path: Path):
    """
    Tests end-to-end SwarmCoordinator remediation where the first synthesized patch
    triggers an invariant rejection, feedback is delivered, the patch is self-corrected
    on retry, and changes are applied to disk.
    """
    main_tf = tmp_path / "main.tf"
    main_tf.write_text(
        'resource "aws_s3_bucket" "medical_records" {\n'
        '  bucket = "hospital-medical-records"\n'
        '}\n'
    )

    # Sandbox sequence:
    # Attempt 1: Invariant failure (forces replacement)
    # Attempt 2: Safe additive creation
    mock_sandbox = MagicMock()
    failed_report = InvariantReport(
        is_safe=False,
        zero_destruction_guarantee_met=False,
        total_resources_evaluated=1,
        count_replaced=1,
        violations=[
            InvariantViolation(
                resource_address="aws_s3_bucket.medical_records",
                violation_type=ViolationType.FORCES_REPLACEMENT,
                actions=["delete", "create"],
                action_reason="forces replacement",
                message="forces replacement: cannot modify bucket in place",
            )
        ],
    )
    passed_report = InvariantReport(
        is_safe=True,
        zero_destruction_guarantee_met=True,
        total_resources_evaluated=2,
        count_created=1,
        changes=[
            ResourceChange(
                address="aws_s3_bucket_server_side_encryption_configuration.medical_records_encryption",
                resource_type="aws_s3_bucket_server_side_encryption_configuration",
                name="medical_records_encryption",
                actions=["create"],
                after={
                    "bucket": "aws_s3_bucket.medical_records.id",
                    "rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}},
                },
            )
        ],
    )
    mock_sandbox.simulate_and_verify.side_effect = [failed_report, passed_report]

    mock_llm = MockLLMClient()
    coordinator = SwarmCoordinator(
        sandbox_runner=mock_sandbox,
        llm_client=mock_llm,
        max_retries=3,
    )

    violations = [
        ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Server Side Encryption",
            resource_id="aws_s3_bucket.medical_records",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        )
    ]

    result = coordinator.remediate_directory(
        target_dir=tmp_path,
        apply_changes=True,
        precomputed_violations=violations,
    )

    assert result.total_violations_found == 1
    assert result.autonomous_remediations_eligible == 1
    assert result.human_escalations_required == 0
    assert result.patches_verified_and_accepted == 1
    assert result.patches_rejected_and_escalated == 0

    accepted_proposal = result.accepted_patches[0]
    assert accepted_proposal.attempts == 2
    assert accepted_proposal.is_verified is True
    assert "Attempt 1 rejected [FORCES_REPLACEMENT]" in accepted_proposal.feedback_history[0]

    # Verify disk content was updated with the additive patch
    disk_content = main_tf.read_text()
    assert "aws_s3_bucket_server_side_encryption_configuration" in disk_content
    assert "aws_s3_bucket.medical_records.id" in disk_content

    # Verify context state history
    ctx = result.contexts[0]
    assert ctx.is_accepted is True
    transitions = [t.to_state.value for t in ctx.history]
    assert transitions == [
        "GRAPH_RAG_RETRIEVE",
        "PLAN",
        "SYNTHESIZE",
        "SANDBOX_SIMULATE",
        "RETRY_WITH_FEEDBACK",
        "SYNTHESIZE",
        "SANDBOX_SIMULATE",
        "SEMANTIC_VERIFY",
        "ACCEPT",
    ]


# ==============================================================================
# 5. Security Regression Feedback Loop
# ==============================================================================

def test_supervisor_security_regression_feedback_loop(tmp_path: Path):
    """
    Validates that when an initial patch introduces a security regression (e.g. S3 versioning
    disabled or TLS downgrade), the Supervisor detects the regression, prompts self-correction,
    and accepts the patch once the regression is eliminated.
    """
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_s3_bucket" "secure_vault" {\n  bucket = "secure-vault"\n}\n')

    mock_sandbox = MagicMock()
    # Attempt 1: Introduces a versioning downgrade regression (versioning disabled)
    report_reg = InvariantReport(
        is_safe=True,
        zero_destruction_guarantee_met=True,
        total_resources_evaluated=1,
        count_updated=1,
        changes=[
            ResourceChange(
                address="aws_s3_bucket.secure_vault",
                resource_type="aws_s3_bucket",
                name="secure_vault",
                actions=["update"],
                before={"bucket": "secure-vault", "versioning": {"enabled": True}},
                after={"bucket": "secure-vault", "versioning": {"enabled": False}},  # Regression!
            )
        ],
    )
    # Attempt 2: Clean additive attachment without regression
    report_safe = InvariantReport(
        is_safe=True,
        zero_destruction_guarantee_met=True,
        total_resources_evaluated=2,
        count_created=1,
        changes=[
            ResourceChange(
                address="aws_s3_bucket_server_side_encryption_configuration.secure_vault_encryption",
                resource_type="aws_s3_bucket_server_side_encryption_configuration",
                name="secure_vault_encryption",
                actions=["create"],
                after={"bucket": "aws_s3_bucket.secure_vault.id"},
            )
        ],
    )
    mock_sandbox.simulate_and_verify.side_effect = [report_reg, report_safe]

    semantic_verifier = SemanticInvariantVerifier(check_regressions=True)
    mock_llm = MockLLMClient()
    synthesizer = SynthesizerAgent(llm_client=mock_llm)
    supervisor = SupervisorAgent(
        sandbox_runner=mock_sandbox,
        semantic_verifier=semantic_verifier,
        llm_client=mock_llm,
        max_retries=3,
    )

    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_19",
            check_name="S3 Encryption at Rest",
            resource_id="aws_s3_bucket.secure_vault",
            resource_type="aws_s3_bucket",
            file_path="main.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.0,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        action=RemediationAction(
            check_id="CKV_AWS_19",
            framework="HIPAA",
            statute_reference="HIPAA §164.312(a)(2)(iv)",
            strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
            target_attribute="server_side_encryption_configuration",
            description="Enable S3 bucket default encryption",
        ),
        reason="Autonomous leaf repair",
    )

    ctx = RemediationContext(task=task, current_state=RemediationState.SYNTHESIZE, max_retries=3)
    initial_proposal = PatchProposal(
        resource_id="aws_s3_bucket.secure_vault",
        target_file="main.tf",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        modified_content=tf_file.read_text(),
    )

    verified = supervisor.verify_and_refine(
        base_dir=tmp_path,
        proposal=initial_proposal,
        task=task,
        synthesizer=synthesizer,
        state_context=ctx,
        file_content=tf_file.read_text(),
    )

    assert verified.is_verified is True
    assert verified.attempts == 2
    assert ctx.is_accepted is True
    assert any("versioning was disabled" in fb or "UNMET" in fb or "SEMANTIC" in fb for fb in verified.feedback_history)
