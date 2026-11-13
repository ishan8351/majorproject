import subprocess
import pytest
from pathlib import Path
from fastapi import HTTPException

from regradar.storage.db import GovernanceDatabase, set_governance_db
from regradar.api.routes import (
    connect_remote_workspace,
    sync_remote_workspace,
    list_workspaces,
    disconnect_workspace,
    _resolve_target_path,
    _normalize_repo_input,
    _raise_git_error,
    ConnectRepoRequest,
)


@pytest.fixture
def clean_db(tmp_path: Path):
    db_file = tmp_path / "test_remotes.db"
    db = GovernanceDatabase(db_path=db_file)
    set_governance_db(db)
    return db


@pytest.fixture
def git_repo_fixture(tmp_path: Path):
    src = tmp_path / "sample_origin"
    src.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=src, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "ci@regradar.test"], cwd=src, check=True)
    subprocess.run(["git", "config", "user.name", "RegRadar CI"], cwd=src, check=True)

    tf_code = """
resource "aws_s3_bucket" "b" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {
  bucket = aws_s3_bucket.b.id
}
"""
    (src / "main.tf").write_text(tf_code.strip() + "\n")
    subprocess.run(["git", "add", "."], cwd=src, check=True)
    subprocess.run(["git", "commit", "-m", "Initial IaC commit"], cwd=src, check=True)
    return src


def test_normalize_and_error_handling():
    # 1. Normalizing standard owner/repo
    p, name, url = _normalize_repo_input("github", "acme-corp/infra")
    assert p == "github"
    assert name == "acme-corp/infra"
    assert url == "https://github.com/acme-corp/infra.git"

    # 2. Normalizing GitLab URL
    p2, name2, url2 = _normalize_repo_input("github", "https://gitlab.com/group/subgroup/repo.git")
    assert p2 == "gitlab"
    assert name2 == "group/subgroup/repo"
    assert url2 == "https://gitlab.com/group/subgroup/repo.git"

    # 3. Invalid inputs
    with pytest.raises(HTTPException) as exc_info:
        _normalize_repo_input("github", "singleword")
    assert exc_info.value.status_code == 400

    # 4. Error diagnostic masking and categorization
    with pytest.raises(HTTPException) as exc_info:
        _raise_git_error("fatal: Authentication failed for 'https://token:secret@github.com'", "github", "test/repo")
    assert exc_info.value.status_code == 400
    assert "secret" not in exc_info.value.detail
    assert "Authentication failed" in exc_info.value.detail


def test_remote_repositories_lifecycle(clean_db: GovernanceDatabase, git_repo_fixture: Path):
    # 1. Fresh database starts empty
    workspaces = list_workspaces()
    assert workspaces == []

    # 2. Local filesystem paths outside managed repos are disallowed
    with pytest.raises(HTTPException) as exc_info:
        _resolve_target_path("/etc/passwd")
    assert exc_info.value.status_code == 403
    assert "disallowed" in exc_info.value.detail.lower()

    # 3. Connect a remote repository from git_repo_fixture
    req_gh = ConnectRepoRequest(
        provider="github",
        repo_name="acme-corp/terraform-production",
        default_branch="main",
        framework="Terraform AWS",
        clone_url=str(git_repo_fixture),
    )
    gh_item = connect_remote_workspace(req_gh)
    assert gh_item.name == "GitHub: acme-corp/terraform-production"
    assert gh_item.resource_count == 2
    assert "2 resources" in gh_item.framework

    # 4. List workspaces returns connected repo
    updated = list_workspaces()
    assert len(updated) == 1
    assert updated[0].path == "acme-corp/terraform-production"
    assert updated[0].resource_count == 2

    # 5. Connected repo resolves to managed directory inside .regradar_repos
    resolved_dir = _resolve_target_path("acme-corp/terraform-production")
    assert resolved_dir.is_dir()
    assert (resolved_dir / "main.tf").exists()
    assert ".regradar_repos" in str(resolved_dir)

    # 6. Test sync endpoint after adding a resource to remote
    tf_add = """
resource "aws_sqs_queue" "q" {
  name = "remediation-queue"
}
"""
    with open(git_repo_fixture / "main.tf", "a") as f:
        f.write(tf_add)
    subprocess.run(["git", "add", "."], cwd=git_repo_fixture, check=True)
    subprocess.run(["git", "commit", "-m", "Add SQS queue"], cwd=git_repo_fixture, check=True)

    synced = sync_remote_workspace(gh_item.id)
    assert synced.workspace.resource_count == 3
    assert "3 resources" in synced.workspace.framework

    # 7. Disconnect repository
    res = disconnect_workspace(gh_item.id)
    assert res["status"] == "success"

    remaining = list_workspaces()
    assert len(remaining) == 0
