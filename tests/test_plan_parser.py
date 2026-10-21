import json
import pytest

from regradar.invariant.models import ResourceChange
from regradar.invariant.plan_parser import PlanParser


def test_plan_parser_extracts_actions():
    sample_plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.logs",
                "type": "aws_s3_bucket",
                "name": "logs",
                "change": {
                    "actions": ["update"],
                    "before": {"bucket": "my-logs", "tags": {"Env": "prod"}},
                    "after": {"bucket": "my-logs", "tags": {"Env": "prod", "Compliance": "HIPAA"}},
                },
            },
            {
                "address": "aws_s3_bucket.bad_bucket",
                "type": "aws_s3_bucket",
                "name": "bad_bucket",
                "action_reason": "replace_because_cannot_be_updated",
                "change": {
                    "actions": ["delete", "create"],
                    "before": {"bucket": "old-name"},
                    "after": {"bucket": "new-name"},
                },
            },
            {
                "address": "aws_security_group_rule.ssh",
                "type": "aws_security_group_rule",
                "name": "ssh",
                "change": {
                    "actions": ["delete"],
                    "before": {"from_port": 22, "to_port": 22},
                    "after": None,
                },
            },
        ]
    }

    changes = PlanParser.parse_json_dict(sample_plan)
    assert len(changes) == 3

    # 1. Update
    c1 = changes[0]
    assert c1.address == "aws_s3_bucket.logs"
    assert c1.is_update is True
    assert c1.is_replace is False
    assert c1.is_delete is False
    assert c1.is_destructive is False

    # 2. Replace
    c2 = changes[1]
    assert c2.address == "aws_s3_bucket.bad_bucket"
    assert c2.is_replace is True
    assert c2.is_destructive is True

    # 3. Delete
    c3 = changes[2]
    assert c3.address == "aws_security_group_rule.ssh"
    assert c3.is_delete is True
    assert c3.is_destructive is True
