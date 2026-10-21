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
