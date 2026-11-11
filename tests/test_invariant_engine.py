import pytest

from regradar.invariant.invariant_engine import InvariantEngine
from regradar.invariant.models import ResourceChange, ViolationType


def test_invariant_safe_in_place_update():
    engine = InvariantEngine()
    changes = [
        ResourceChange(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            name="logs",
            actions=["update"],
            before={"bucket": "prod-logs", "tags": {"Env": "prod"}},
            after={"bucket": "prod-logs", "tags": {"Env": "prod", "Compliance": "HIPAA"}},
        )
    ]

    report = engine.verify(changes)
    assert report.is_safe is True
    assert report.zero_destruction_guarantee_met is True
    assert len(report.violations) == 0
    assert report.count_updated == 1


def test_invariant_safe_additive_creation():
    engine = InvariantEngine(allow_additive_creations=True)
    changes = [
        ResourceChange(
            address="aws_s3_bucket_server_side_encryption_configuration.enc",
            resource_type="aws_s3_bucket_server_side_encryption_configuration",
            name="enc",
            actions=["create"],
            before=None,
            after={"bucket": "prod-logs", "rule": []},
        )
    ]

    report = engine.verify(changes)
    assert report.is_safe is True
    assert report.count_created == 1
    assert len(report.violations) == 0


def test_invariant_rejects_forces_replacement():
    engine = InvariantEngine()
    changes = [
        ResourceChange(
            address="aws_db_instance.primary",
            resource_type="aws_db_instance",
            name="primary",
            actions=["delete", "create"],
            action_reason="replace_because_cannot_be_updated",
            before={"identifier": "old-db", "allocated_storage": 20},
            after={"identifier": "new-db", "allocated_storage": 20},
        )
    ]

    report = engine.verify(changes)
    assert report.is_safe is False
    assert report.zero_destruction_guarantee_met is False
    assert report.count_replaced == 1
    assert len(report.violations) == 1

    v = report.violations[0]
    assert v.violation_type == ViolationType.FORCES_REPLACEMENT
    assert "identifier" in v.problematic_attributes


def test_invariant_rejects_unintended_deletion():
    engine = InvariantEngine()
    changes = [
        ResourceChange(
            address="aws_ebs_volume.storage",
            resource_type="aws_ebs_volume",
            name="storage",
            actions=["delete"],
            before={"size": 100},
            after=None,
        )
    ]

    report = engine.verify(changes)
    assert report.is_safe is False
    assert report.count_deleted == 1
    assert len(report.violations) == 1
    assert report.violations[0].violation_type == ViolationType.UNINTENDED_DELETION


def test_invariant_detects_schema_drop():
    engine = InvariantEngine()
    changes = [
        ResourceChange(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            name="logs",
            actions=["update"],
            before={"bucket": "my-logs", "lifecycle_rule": [{"enabled": True}]},
            after={"bucket": "my-logs", "lifecycle_rule": None},
        )
    ]

    report = engine.verify(changes)
    assert report.is_safe is False
    assert len(report.violations) == 1
    assert report.violations[0].violation_type == ViolationType.SCHEMA_DROP
    assert "lifecycle_rule" in report.violations[0].problematic_attributes


def test_invariant_detects_nested_dropped_tags():
    engine = InvariantEngine()
    changes = [
        ResourceChange(
            address="aws_s3_bucket.data",
            resource_type="aws_s3_bucket",
            name="data",
            actions=["update"],
            before={"bucket": "my-data", "tags": {"Env": "prod", "Owner": "SecOps", "CostCenter": "CC123"}},
            after={"bucket": "my-data", "tags": {"Env": "prod"}},
        )
    ]

    report = engine.verify(changes)
    assert report.is_safe is False
    assert len(report.violations) == 1
    v = report.violations[0]
    assert v.violation_type == ViolationType.SCHEMA_DROP
    assert "tags.CostCenter" in v.problematic_attributes
    assert "tags.Owner" in v.problematic_attributes


def test_invariant_detects_nested_dropped_ingress_rule():
    engine = InvariantEngine()
    changes = [
        ResourceChange(
            address="aws_security_group.web",
            resource_type="aws_security_group",
            name="web",
            actions=["update"],
            before={
                "name": "web-sg",
                "ingress": [
                    {"from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]},
                    {"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]},
                ],
            },
            after={
                "name": "web-sg",
                "ingress": [
                    {"from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]},
                ],
            },
        )
    ]

    report = engine.verify(changes)
    assert report.is_safe is False
    assert len(report.violations) == 1
    v = report.violations[0]
    assert v.violation_type == ViolationType.SCHEMA_DROP
    assert "ingress[1]" in v.problematic_attributes


def test_invariant_detects_nested_modified_attributes():
    engine = InvariantEngine()
    before = {
        "tags": {"Env": "staging", "Owner": "Dev"},
        "ingress": [{"from_port": 80, "to_port": 80, "protocol": "tcp"}],
    }
    after = {
        "tags": {"Env": "production", "Owner": "Dev"},
        "ingress": [{"from_port": 8080, "to_port": 8080, "protocol": "tcp"}],
    }

    modified = engine._find_modified_attributes(before, after)
    assert "tags.Env" in modified
    assert "ingress[0].from_port" in modified
    assert "ingress[0].to_port" in modified
    assert "tags.Owner" not in modified
