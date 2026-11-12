import json
from pathlib import Path
import tempfile
import pytest

from regradar.storage.db import GovernanceDatabase
from regradar.integrations.github_webhook import GitHubPRStore, StagedPR
from regradar.integrations.dispatcher import WebhookDispatcher


@pytest.fixture
def temp_db(tmp_path: Path):
    db_file = tmp_path / "test_governance.db"
    return GovernanceDatabase(db_path=db_file)


def test_sqlite_pr_lifecycle(temp_db: GovernanceDatabase):
    # 1. Insert PR
    pr = {
        "id": "pr-999",
        "pr_number": 999,
        "repo": "enterprise/infra",
        "title": "Enable KMS CMK for EBS Volumes",
        "author": "security-bot[bot]",
        "head_branch": "bot/ebs-kms",
        "base_branch": "main",
        "is_agent_pr": True,
        "status": "AWAITING_HUMAN_APPROVAL",
        "risk_tier": "CRITICAL_ROOT",
        "invariant_verdict": "PASS",
        "destructive_changes_count": 0,
        "summary_markdown": "### Audit Summary",
    }
    saved = temp_db.upsert_pr(pr)
    assert saved["id"] == "pr-999"
    assert saved["status"] == "AWAITING_HUMAN_APPROVAL"

    # 2. Retrieve
    retrieved = temp_db.get_pr("pr-999")
    assert retrieved is not None
    assert retrieved["title"] == "Enable KMS CMK for EBS Volumes"
    assert retrieved["is_agent_pr"] is True

    # 3. Update decision
    updated = temp_db.update_pr_decision(
        pr_id="pr-999",
        decision="APPROVE",
        reviewer="secops_lead",
        comment="Verified invariant proof.",
    )
    assert updated is not None
    assert updated["status"] == "APPROVED"
    assert updated["reviewed_by"] == "secops_lead"
    assert updated["review_comment"] == "Verified invariant proof."

    # 4. Stats
    stats = temp_db.get_database_stats()
    assert stats["db_engine"] == "SQLite 3"
    assert stats["tables"]["staged_prs"]["total"] == 1
    assert stats["tables"]["staged_prs"]["awaiting_human_approval"] == 0


def test_sqlite_staged_reviews_persistence(temp_db: GovernanceDatabase):
    workspace = "/workspace/project"
    items = [
        {
            "resource_id": "aws_s3_bucket.data",
            "check_id": "CKV_AWS_19",
            "check_name": "Ensure all data stored in the S3 bucket is secure_at_rest",
            "frameworks": ["HIPAA §164.312", "GDPR Art. 32"],
            "statute": "HIPAA §164.312",
            "risk_tier": "LEAF_SAFE",
            "blast_radius_score": 0.05,
            "descendant_count": 0,
            "ancestor_count": 1,
            "betweenness": 0.0,
            "eigenvector": 0.0,
            "pagerank": 0.02,
            "gating_status": "AUTONOMOUS_ELIGIBLE",
            "strategy": "ADDITIVE_ATTACHMENT",
            "target_file": "main.tf",
            "original_snippet": 'resource "aws_s3_bucket" "data" {}',
            "patch_snippet": 'resource "aws_s3_bucket" "data" {}\nresource "aws_s3_bucket_server_side_encryption_configuration" "enc" {}',
            "is_verified": True,
            "requires_human": False,
            "verification_message": "Pre-flight sandbox verified.",
            "decision": "PENDING",
        }
    ]

    temp_db.save_staged_reviews(workspace, items)
    reviews = temp_db.list_staged_reviews(workspace)
    assert len(reviews) == 1
    assert reviews[0]["resource_id"] == "aws_s3_bucket.data"
    assert reviews[0]["check_id"] == "CKV_AWS_19"
    assert reviews[0]["is_verified"] is True
    assert "HIPAA §164.312" in reviews[0]["frameworks"]

    # Record decision
    ok = temp_db.record_review_decision(
        workspace_path=workspace,
        resource_id="aws_s3_bucket.data",
        check_id="CKV_AWS_19",
        decision="APPROVE",
        applied=True,
        reviewer="admin",
    )
    assert ok is True

    updated_reviews = temp_db.list_staged_reviews(workspace)
    assert updated_reviews[0]["decision"] == "APPROVE"
    assert updated_reviews[0]["applied"] is True


def test_webhook_dispatch_logging(temp_db: GovernanceDatabase):
    log_id = temp_db.log_webhook_dispatch(
        event_type="pr.staged",
        target_url="https://hooks.slack.com/services/T00/B00/X00",
        payload={"pr_id": "pr-100"},
        status_code=200,
        success=True,
    )
    assert log_id is not None
    logs = temp_db.list_webhook_logs()
    assert len(logs) == 1
    assert logs[0]["event_type"] == "pr.staged"
    assert logs[0]["success"] is True
    assert logs[0]["payload"]["pr_id"] == "pr-100"
