import pytest
from pathlib import Path

from regradar.integrations.gitlab_webhook import (
    GitLabWebhookHandler,
    verify_gitlab_token,
)
from regradar.storage.db import GovernanceDatabase


@pytest.fixture
def temp_db(tmp_path: Path):
    db_file = tmp_path / "test_gitlab_governance.db"
    return GovernanceDatabase(db_path=db_file)


def test_verify_gitlab_token():
    # Dev mode (empty secret) passes
    assert verify_gitlab_token(None, "") is True
    assert verify_gitlab_token("random-token", "") is True

    # Configured secret
    secret = "secret-token-12345"
    assert verify_gitlab_token(secret, secret) is True
    assert verify_gitlab_token(None, secret) is False
    assert verify_gitlab_token("wrong-token", secret) is False


def test_gitlab_simulation_staging(temp_db: GovernanceDatabase):
    handler = GitLabWebhookHandler()
    handler.db = temp_db

    simulated = handler.simulate_event(
        repo="gitlab-org/production-iac",
        title="[RegRadar Agent] Restrict Public Ingress",
        author="regradar-remediation-bot",
        risk_tier="LEAF_SAFE",
        is_agent=True,
    )

    assert simulated.provider == "gitlab"
    assert simulated.repo == "gitlab-org/production-iac"
    assert simulated.is_agent_pr is True
    assert simulated.status == "AWAITING_HUMAN_APPROVAL"

    # Verify persisted in DB
    retrieved = temp_db.get_pr(simulated.id)
    assert retrieved is not None
    assert retrieved["provider"] == "gitlab"
    assert retrieved["repo"] == "gitlab-org/production-iac"

    # Verify auto-registered into connected_repositories
    connected = temp_db.list_connected_repositories()
    assert any(c["repo_name"] == "gitlab-org/production-iac" and c["provider"] == "gitlab" for c in connected)
