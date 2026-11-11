import pytest

from regradar.remediation.knowledge_base import RegulatoryKnowledgeBase
from regradar.remediation.models import RemediationStrategy


def test_knowledge_base_retrieves_rules():
    action = RegulatoryKnowledgeBase.get_action_for_check("CKV_AWS_19")
    assert action is not None
    assert action.strategy == RemediationStrategy.ADDITIVE_ATTACHMENT
    assert "HIPAA" in action.statute_reference
    assert "aws_s3_bucket_server_side_encryption_configuration" in action.additive_resource_template

    action_imds = RegulatoryKnowledgeBase.get_action_for_check("CKV_AWS_79")
    assert action_imds is not None
    assert action_imds.strategy == RemediationStrategy.IN_PLACE_ATTRIBUTE
    assert "http_tokens" in action_imds.attribute_value


def test_knowledge_base_unknown_check():
    assert RegulatoryKnowledgeBase.get_action_for_check("UNKNOWN_CHECK_999") is None


def test_catalog_loads_from_external_rules_directory(tmp_path):
    import json
    from regradar.knowledge.catalog import get_default_catalog, load_catalog_from_directory

    stds, ctrls, reqs, res, rules = get_default_catalog()
    assert len(rules) >= 30
    assert "CKV_AWS_19" in rules

    # Test loading from a custom directory with a new custom rule
    custom_rules_dir = tmp_path / "rules"
    custom_rules_dir.mkdir()
    custom_sub = custom_rules_dir / "custom"
    custom_sub.mkdir()

    new_rule = {
        "check_id": "CKV_CUSTOM_01",
        "name": "Custom Organization Security Tag",
        "description": "Ensure resources have required SecurityZone tag",
        "resource_type": "aws_s3_bucket",
        "framework": "Internal Policy",
        "statute_reference": "Corp Sec 4.1",
        "control_ids": [],
        "requirement_id": None,
        "strategy": "IN_PLACE_ATTRIBUTE",
        "target_attribute": "tags.SecurityZone",
        "attribute_value": '  tags = { SecurityZone = "restricted" }',
        "validation_rules": [],
    }
    (custom_sub / "custom_rule.json").write_text(json.dumps([new_rule]), encoding="utf-8")

    stds2, ctrls2, reqs2, res2, rules2 = load_catalog_from_directory(custom_rules_dir)
    assert "CKV_CUSTOM_01" in rules2
    assert rules2["CKV_CUSTOM_01"].name == "Custom Organization Security Tag"


def test_semantic_verifier_dynamic_registration():
    from regradar.invariant.semantic_verifier import (
        SemanticInvariantVerifier,
        register_additive_security_resource,
        register_security_attribute,
    )
    from regradar.invariant.models import ResourceChange

    # Test registering a custom security attribute
    register_security_attribute("custom_encryption_mode", cannot_be_dropped=True)
    verifier = SemanticInvariantVerifier()
    assert "custom_encryption_mode" in verifier.security_attributes

    # Regression detected when custom attribute dropped
    change = ResourceChange(
        address="aws_custom_resource.test",
        resource_type="aws_custom_resource",
        name="test",
        actions=["update"],
        before={"custom_encryption_mode": "strict"},
        after={"custom_encryption_mode": None},
    )
    violations = verifier._check_resource_regressions(change)
    assert any(v.attribute_path == "custom_encryption_mode" for v in violations)
