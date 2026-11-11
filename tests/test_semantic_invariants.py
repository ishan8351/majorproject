import pytest

from regradar.invariant.models import ResourceChange
from regradar.invariant.semantic_verifier import (
    SemanticInvariantVerifier,
    SemanticRequirement,
    SemanticVerificationResult,
    SemanticViolation,
    SemanticViolationType,
    resolve_nested_attribute,
)
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    RemediationAction,
    RemediationStrategy,
    RemediationTask,
)


# ==============================================================================
# Helper / Attribute Resolver Tests
# ==============================================================================

def test_resolve_nested_attribute():
    data = {
        "bucket": "test-bucket",
        "tags": {"Compliance": "HIPAA", "Tier": 1},
        "server_side_encryption_configuration": [
            {
                "rule": [
                    {
                        "apply_server_side_encryption_by_default": {
                            "sse_algorithm": "AES256"
                        }
                    }
                ]
            }
        ],
    }

    found, val = resolve_nested_attribute(data, "bucket")
    assert found is True
    assert val == "test-bucket"

    found, val = resolve_nested_attribute(data, "tags.Compliance")
    assert found is True
    assert val == "HIPAA"

    found, val = resolve_nested_attribute(
        data,
        "server_side_encryption_configuration[0].rule[0].apply_server_side_encryption_by_default.sse_algorithm",
    )
    assert found is True
    assert val == "AES256"

    found, val = resolve_nested_attribute(data, "non_existent.path")
    assert found is False
    assert val is None


# ==============================================================================
# Semantic Requirement Satisfaction Tests
# ==============================================================================

def test_semantic_in_place_encryption_satisfied():
    """Verifies that an applied patch satisfies in-place S3 encryption."""
    verifier = SemanticInvariantVerifier()
    changes = [
        ResourceChange(
            address="aws_s3_bucket.audit_logs",
            resource_type="aws_s3_bucket",
            name="audit_logs",
            actions=["update"],
            before={"bucket": "audit-logs"},
            after={
                "bucket": "audit-logs",
                "server_side_encryption_configuration": {
                    "rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}
                },
            },
        )
    ]

    req = SemanticRequirement(
        resource_address="aws_s3_bucket.audit_logs",
        attribute_path="server_side_encryption_configuration",
        description="Enforce S3 server-side encryption",
        statute_reference="HIPAA §164.312(a)(2)(iv)",
    )

    result = verifier.verify(changes=changes, requirements=[req])
    assert result.is_valid is True
    assert result.requirements_satisfied is True
    assert result.no_regressions is True
    assert len(result.satisfied_requirements) == 1
    assert len(result.violations) == 0


def test_semantic_additive_encryption_satisfied():
    """Verifies that an attached additive resource satisfies encryption for target bucket."""
    verifier = SemanticInvariantVerifier()
    changes = [
        # Base bucket untouched or updated
        ResourceChange(
            address="aws_s3_bucket.finance",
            resource_type="aws_s3_bucket",
            name="finance",
            actions=["no-op"],
            before={"bucket": "corp-finance"},
            after={"bucket": "corp-finance"},
        ),
        # Additive attachment created
        ResourceChange(
            address="aws_s3_bucket_server_side_encryption_configuration.finance_enc",
            resource_type="aws_s3_bucket_server_side_encryption_configuration",
            name="finance_enc",
            actions=["create"],
            before=None,
            after={
                "bucket": "aws_s3_bucket.finance.id",
                "rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "aws:kms"}}],
            },
        ),
    ]

    req = SemanticRequirement(
        resource_address="aws_s3_bucket.finance",
        resource_type="aws_s3_bucket",
        attribute_path="server_side_encryption_configuration",
        allow_additive_attachment=True,
        description="Verify S3 encryption satisfied via additive attachment",
    )

    result = verifier.verify(changes=changes, requirements=[req])
    assert result.is_valid is True
    assert result.requirements_satisfied is True
    assert len(result.satisfied_requirements) == 1
    assert len(result.violations) == 0


def test_semantic_detects_incomplete_patch():
    """Detects when a proposed patch fails to actually enable the required attribute."""
    verifier = SemanticInvariantVerifier()
    # Proposed patch only modified tags, didn't actually enable encryption!
    changes = [
        ResourceChange(
            address="aws_s3_bucket.audit_logs",
            resource_type="aws_s3_bucket",
            name="audit_logs",
            actions=["update"],
            before={"bucket": "audit-logs"},
            after={"bucket": "audit-logs", "tags": {"Env": "prod"}},
        )
    ]

    req = SemanticRequirement(
        resource_address="aws_s3_bucket.audit_logs",
        attribute_path="server_side_encryption_configuration",
        description="Enforce S3 server-side encryption",
    )

    result = verifier.verify(changes=changes, requirements=[req])
    assert result.is_valid is False
    assert result.requirements_satisfied is False
    assert len(result.unmet_requirements) == 1
    assert len(result.violations) == 1
    assert result.violations[0].violation_type == SemanticViolationType.UNMET_REQUIREMENT
    assert "audit_logs" in result.violations[0].resource_address


# ==============================================================================
# Security Regression Prevention Tests
# ==============================================================================

def test_semantic_detects_encryption_regression():
    """Rejects patches that silently drop or disable encryption on modified resources."""
    verifier = SemanticInvariantVerifier()
    changes = [
        ResourceChange(
            address="aws_ebs_volume.data",
            resource_type="aws_ebs_volume",
            name="data",
            actions=["update"],
            before={"size": 50, "encrypted": True},
            after={"size": 100, "encrypted": False},
        )
    ]

    result = verifier.verify(changes=changes)
    assert result.is_valid is False
    assert result.no_regressions is False
    assert len(result.regressions) == 1
    assert result.violations[0].violation_type == SemanticViolationType.SECURITY_REGRESSION
    assert result.violations[0].attribute_path == "encrypted"


def test_semantic_detects_public_access_regression():
    """Detects security regression when public access blocking is weakened."""
    verifier = SemanticInvariantVerifier()
    changes = [
        ResourceChange(
            address="aws_s3_bucket.public_repo",
            resource_type="aws_s3_bucket",
            name="public_repo",
            actions=["update"],
            before={"bucket": "repo", "block_public_acls": True},
            after={"bucket": "repo", "block_public_acls": False},
        )
    ]

    result = verifier.verify(changes=changes)
    assert result.is_valid is False
    assert result.no_regressions is False
    assert any("block_public_acls" in v.attribute_path for v in result.violations)


def test_semantic_detects_azure_public_blob_regression():
    """Detects regression when allow_blob_public_access is set to True."""
    verifier = SemanticInvariantVerifier()
    changes = [
        ResourceChange(
            address="azurerm_storage_account.sa",
            resource_type="azurerm_storage_account",
            name="sa",
            actions=["update"],
            before={"name": "storesa", "allow_blob_public_access": False},
            after={"name": "storesa", "allow_blob_public_access": True},
        )
    ]

    result = verifier.verify(changes=changes)
    assert result.is_valid is False
    assert result.no_regressions is False
    assert any("allow_blob_public_access" in v.attribute_path for v in result.violations)


def test_semantic_detects_tls_version_downgrade():
    """Detects regression when minimum TLS version is downgraded."""
    verifier = SemanticInvariantVerifier()
    changes = [
        ResourceChange(
            address="azurerm_storage_account.sa",
            resource_type="azurerm_storage_account",
            name="sa",
            actions=["update"],
            before={"name": "storesa", "min_tls_version": "TLS1_2"},
            after={"name": "storesa", "min_tls_version": "TLS1_0"},
        )
    ]

    result = verifier.verify(changes=changes)
    assert result.is_valid is False
    assert result.no_regressions is False
    assert any("min_tls_version" in v.attribute_path for v in result.violations)
    assert "downgraded from TLS1_2 to TLS1_0" in result.violations[0].message


def test_semantic_detects_versioning_downgrade():
    """Detects regression when S3 bucket versioning is disabled or suspended."""
    verifier = SemanticInvariantVerifier()
    changes = [
        ResourceChange(
            address="aws_s3_bucket.archive",
            resource_type="aws_s3_bucket",
            name="archive",
            actions=["update"],
            before={"bucket": "archive", "versioning": {"enabled": True, "status": "Enabled"}},
            after={"bucket": "archive", "versioning": {"enabled": False, "status": "Suspended"}},
        )
    ]

    result = verifier.verify(changes=changes)
    assert result.is_valid is False
    assert result.no_regressions is False
    assert any("versioning" in v.attribute_path for v in result.violations)


# ==============================================================================
# Remediation Task Integration & Custom Checks
# ==============================================================================

def test_semantic_verifier_remediation_task_integration():
    """Tests automated requirement synthesis and verification from a RemediationTask."""
    verifier = SemanticInvariantVerifier()

    task = RemediationTask(
        violation=ComplianceViolation(
            check_id="CKV_AWS_145",
            check_name="Ensure S3 buckets have server-side encryption enabled",
            resource_id="aws_s3_bucket.phi_data",
            resource_type="aws_s3_bucket",
            file_path="storage.tf",
        ),
        risk_tier="LEAF_SAFE",
        blast_radius_score=0.05,
        gating_status=GatingStatus.AUTONOMOUS_ELIGIBLE,
        action=RemediationAction(
            check_id="CKV_AWS_145",
            framework="HIPAA",
            statute_reference="HIPAA §164.312(a)(2)(iv)",
            strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
            target_attribute="server_side_encryption_configuration",
            attribute_value='server_side_encryption_configuration {\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}',
            description="Enable S3 bucket default encryption",
        ),
        reason="Autonomous leaf remediation",
    )

    valid_changes = [
        ResourceChange(
            address="aws_s3_bucket.phi_data",
            resource_type="aws_s3_bucket",
            name="phi_data",
            actions=["update"],
            before={"bucket": "phi-data"},
            after={
                "bucket": "phi-data",
                "server_side_encryption_configuration": {
                    "rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}
                },
            },
        )
    ]

    result = verifier.verify_remediation_task(changes=valid_changes, task=task)
    assert result.is_valid is True
    assert result.requirements_satisfied is True
    assert len(result.satisfied_requirements) == 1


def test_semantic_verifier_custom_regression_callback():
    """Tests registering custom enterprise compliance regression check."""
    verifier = SemanticInvariantVerifier()

    def check_custom_tag(change: ResourceChange) -> list:
        violations = []
        if change.after and "CustomSecurityTag" not in change.after.get("tags", {}):
            violations.append(
                SemanticViolation(
                    resource_address=change.address,
                    violation_type=SemanticViolationType.SECURITY_REGRESSION,
                    attribute_path="tags.CustomSecurityTag",
                    message="Missing mandatory enterprise CustomSecurityTag",
                )
            )
        return violations

    verifier.add_regression_check(check_custom_tag)

    changes = [
        ResourceChange(
            address="aws_s3_bucket.test",
            resource_type="aws_s3_bucket",
            name="test",
            actions=["update"],
            before={"tags": {"CustomSecurityTag": "Verified"}},
            after={"tags": {"Env": "prod"}},
        )
    ]

    result = verifier.verify(changes=changes)
    assert result.is_valid is False
    assert result.no_regressions is False
    assert any("CustomSecurityTag" in v.message for v in result.violations)
