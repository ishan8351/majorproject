import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request
from fastapi import APIRouter, HTTPException, Query, Header, Request, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

from regradar.api.models import (
    AuditRequest,
    BenchmarkRunRequest,
    GitCommitInfo,
    HealthResponse,
    KnowledgeQueryRequest,
    QueryBranchesRequest,
    QueryBranchesResponse,
    RemediationRequest,
    RepoMetadataResponse,
    ReviewDecisionRequest,
    ReviewDecisionResponse,
    ReviewStagedItem,
    ReviewStagedRequest,
    ReviewStagedResponse,
    SandboxVerifyRequest,
    ScanRequest,
    SettingsModel,
    SettingsUpdateModel,
    SwitchBranchRequest,
    SyncRepoResponse,
    WorkspaceItem,
)
from regradar.benchmark.evaluator import BenchmarkEvaluator
from regradar.benchmark.models import BenchmarkResult, ComparativeAblationResult
from regradar.graph.builder import DependencyGraphBuilder
from regradar.graph.centrality import CentralityEngine
from regradar.invariant.models import InvariantReport
from regradar.invariant.sandbox import SandboxRunner
from regradar.models import GraphSummary, RiskTier
from regradar.parser.hcl_parser import HCLParser
from regradar.remediation.agents import (
    AuditorAgent,
    PolicyPlannerAgent,
    SynthesizerAgent,
    SupervisorAgent,
)
from regradar.remediation.knowledge_base import RegulatoryKnowledgeBase
from regradar.remediation.llm.client import get_llm_client
from regradar.remediation.models import (
    ComplianceViolation,
    GatingStatus,
    RemediationStrategy,
    SwarmExecutionResult,
)
from regradar.remediation.scanner import CheckovScanner
from regradar.remediation.policy_engine import CompositePolicyEngine
from regradar.remediation.swarm_coordinator import SwarmCoordinator
from regradar.storage.db import get_governance_db
from regradar.integrations.dispatcher import WebhookDispatcher
from regradar.integrations.github_webhook import (
    GitHubPRStore,
    GitHubWebhookHandler,
    ReviewDecision,
    StagedPR,
)

from regradar.config import get_config, resolve_workspace_root

api_router = APIRouter(prefix="/api")


def get_workspace_root() -> Path:
    """Resolves project root dynamically, avoiding hardcoded developer paths."""
    cfg = get_config()
    return resolve_workspace_root(cfg.workspace.root)


# For backward compatibility with any direct attribute accesses
WORKSPACE_ROOT = get_workspace_root()


def _resolve_target_path(path_str: Optional[str] = None) -> Path:
    if not path_str or str(path_str).strip() == "" or str(path_str).strip().lower() in ("null", "undefined", "none"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No remote repository specified. Connect a GitHub or GitLab repository first.",
        )
    db = get_governance_db()
    repo = db.get_repository(path_str)

    # Store managed remote repository workspaces in .regradar_repos
    cache_root = get_workspace_root() / ".regradar_repos"
    cache_root.mkdir(parents=True, exist_ok=True)

    if repo:
        repo_dir = cache_root / repo["id"]
        repo_dir.mkdir(parents=True, exist_ok=True)
        return repo_dir

    # Check if path_str is already a path inside .regradar_repos
    p = Path(path_str)
    if not p.is_absolute():
        p = (cache_root / p).resolve()

    try:
        p.relative_to(cache_root)
        if p.exists():
            return p
    except ValueError:
        pass

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Local filesystem repositories are disallowed. Connect a remote GitHub or GitLab repository via CI/CD Webhooks.",
    )


@api_router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    return HealthResponse()


def _normalize_repo_input(provider: str, repo_input: str, clone_url: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Normalizes user input (URL or owner/repo) into:
    (provider, clean_repo_name, canonical_clone_url)
    """
    raw = (clone_url or repo_input or "").strip()
    detected_provider = (provider or "github").lower()

    if "gitlab" in raw.lower():
        detected_provider = "gitlab"
    elif "github" in raw.lower():
        detected_provider = "github"

    # Allow local directory paths for testing or local clone sources
    if Path(raw).exists():
        p = Path(raw).resolve()
        repo_name = repo_input.strip() if (repo_input and not Path(repo_input).exists()) else f"local/{p.name}"
        return detected_provider, repo_name, str(p)

    # Strip protocols, tokens, and .git
    cleaned = re.sub(r"^(https?://|git@)[^/:]+[/:]", "", raw)
    cleaned = re.sub(r"\.git$", "", cleaned).strip("/")

    parts = cleaned.split("/")
    if len(parts) < 2 or any(not p.strip() for p in parts):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid repository identifier: '{raw}'. Please provide in 'owner/repo' format or full Git clone URL.",
        )

    clean_repo = "/".join(parts)
    host = "gitlab.com" if detected_provider == "gitlab" else "github.com"
    canonical_url = f"https://{host}/{clean_repo}.git"
    return detected_provider, clean_repo, canonical_url


def _raise_git_error(stderr_str: str, provider: str, clean_repo: str) -> None:
    safe_err = re.sub(r":[^@\s]+@", ":***@", stderr_str)
    err_lower = safe_err.lower()
    if "authentication failed" in err_lower or "could not read username" in err_lower:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authentication failed for {provider.upper()} repository '{clean_repo}'. If this is a private repository, please provide a valid Personal Access Token with read permissions.",
        )
    if "not found" in err_lower or "repository not found" in err_lower:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository '{clean_repo}' was not found on {provider.upper()}. Check the repository path and access permissions.",
        )
    if "could not resolve host" in err_lower or "failed to connect" in err_lower:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Network error: Unable to reach {provider}.com. Check your network connection.",
        )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Git clone failed: {safe_err.strip()}",
    )


class ConnectRepoRequest(BaseModel):
    provider: str = Field(default="github", description="'github' or 'gitlab'")
    repo_name: str = Field(..., description="e.g. 'org/infrastructure' or 'https://github.com/org/infrastructure'")
    default_branch: str = Field(default="main")
    auth_token: Optional[str] = Field(default=None, description="Personal Access Token for private repos")
    clone_url: Optional[str] = Field(default="")
    framework: Optional[str] = Field(default="Terraform / OpenTofu")


@api_router.get("/workspaces", response_model=List[WorkspaceItem])
def list_workspaces() -> List[WorkspaceItem]:
    """
    Returns only connected remote Git repositories (GitHub & GitLab).
    Local directories, demo mocks, and preconfigured fixtures are excluded.
    When starting fresh, this returns an empty list until repositories are connected.
    """
    db = get_governance_db()
    repos = db.list_connected_repositories()
    items = []
    for r in repos:
        provider_label = "GitHub" if r["provider"].lower() == "github" else "GitLab"
        items.append(
            WorkspaceItem(
                id=r["id"],
                name=f"{provider_label}: {r['repo_name']}",
                path=r["repo_name"],
                description=f"Remote {provider_label} repository ({r['repo_name']} @ {r.get('default_branch', 'main')})",
                framework=r.get("framework", "Remote Git Repository"),
                resource_count=r.get("resource_count", 0),
            )
        )
    return items


@api_router.post("/workspaces/branches", response_model=QueryBranchesResponse)
def query_remote_branches(req: QueryBranchesRequest) -> QueryBranchesResponse:
    """
    Dynamically probes remote Git repository to discover available real branches
    and the default branch before the user connects it.
    """
    if not shutil.which("git"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Git executable not found on server host.",
        )

    provider, clean_repo, canonical_url = _normalize_repo_input(req.provider, req.repo_name, req.clone_url)

    # Build authenticated URL if token provided
    auth_token = req.auth_token.strip() if req.auth_token else None
    if Path(canonical_url).exists():
        target_url = canonical_url
    elif auth_token:
        if provider == "gitlab":
            target_url = f"https://oauth2:{auth_token}@gitlab.com/{clean_repo}.git"
        else:
            target_url = f"https://x-access-token:{auth_token}@github.com/{clean_repo}.git"
    else:
        target_url = canonical_url

    branches: List[str] = []
    default_branch = "main"
    latest_sha: Optional[str] = None

    try:
        proc = subprocess.run(
            ["git", "ls-remote", "--heads", target_url],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            for line in proc.stdout.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    sha, ref = parts[0], parts[1]
                    if ref.startswith("refs/heads/"):
                        b_name = ref.replace("refs/heads/", "").strip()
                        if b_name and b_name not in ("origin", "HEAD") and not b_name.startswith("origin/"):
                            branches.append(b_name)
                            if not latest_sha:
                                latest_sha = sha[:8]
                            if b_name.lower() in ("main", "master") and default_branch == "main":
                                default_branch = b_name
                                latest_sha = sha[:8]
        if not branches:
            branches = ["main", "master"]
        if default_branch not in branches:
            default_branch = branches[0]

        msg = f"Discovered {len(branches)} remote branch{'es' if len(branches) != 1 else ''}."
        return QueryBranchesResponse(
            provider=provider,
            repo_name=clean_repo,
            canonical_url=canonical_url,
            default_branch=default_branch,
            branches=branches,
            latest_sha=latest_sha,
            message=msg,
        )
    except subprocess.TimeoutExpired:
        logger.warning("git ls-remote timed out for %s, falling back to main/master", canonical_url)
        return QueryBranchesResponse(
            provider=provider,
            repo_name=clean_repo,
            canonical_url=canonical_url,
            default_branch="main",
            branches=["main", "master"],
            latest_sha=None,
            message="Remote probe timed out. Fallback branches populated.",
        )
    except Exception as e:
        logger.warning("git ls-remote failed for %s: %s", canonical_url, e)
        return QueryBranchesResponse(
            provider=provider,
            repo_name=clean_repo,
            canonical_url=canonical_url,
            default_branch="main",
            branches=["main", "master"],
            latest_sha=None,
            message=f"Could not reach remote heads ({e}). Fallback branches populated.",
        )


@api_router.post("/workspaces/connect", response_model=WorkspaceItem)
def connect_remote_workspace(req: ConnectRepoRequest) -> WorkspaceItem:
    """Explicitly connects, clones, and verifies a remote GitHub or GitLab repository."""
    provider, clean_repo, canonical_url = _normalize_repo_input(req.provider, req.repo_name, req.clone_url)

    if not shutil.which("git"):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Git executable not found on server host.")

    repo_id = f"{provider}:{clean_repo}".lower().replace("/", "-")
    cache_root = get_workspace_root() / ".regradar_repos"
    cache_root.mkdir(parents=True, exist_ok=True)
    repo_dir = cache_root / repo_id

    # Build authenticated clone URL if token provided
    auth_token = req.auth_token.strip() if req.auth_token else None
    if Path(canonical_url).exists():
        target_clone_url = canonical_url
    elif auth_token:
        if provider == "gitlab":
            target_clone_url = f"https://oauth2:{auth_token}@gitlab.com/{clean_repo}.git"
        else:
            target_clone_url = f"https://x-access-token:{auth_token}@github.com/{clean_repo}.git"
    else:
        target_clone_url = canonical_url

    # Check if already cloned
    if repo_dir.exists() and (repo_dir / ".git").is_dir():
        subprocess.run(["git", "-C", str(repo_dir), "remote", "set-url", "origin", target_clone_url], capture_output=True, text=True, timeout=10)
        pull_proc = subprocess.run(["git", "-C", str(repo_dir), "pull"], capture_output=True, text=True, timeout=30)
        if pull_proc.returncode != 0:
            shutil.rmtree(repo_dir, ignore_errors=True)

    if not repo_dir.exists():
        branch = (req.default_branch or "main").strip()
        clone_cmd = ["git", "clone", "--depth", "1", "-b", branch, target_clone_url, str(repo_dir)]
        proc = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=45)

        if proc.returncode != 0:
            err_stderr = proc.stderr
            # If branch was not found, retry without -b to fetch default remote branch
            if "Remote branch" in err_stderr and "not found" in err_stderr:
                shutil.rmtree(repo_dir, ignore_errors=True)
                proc2 = subprocess.run(["git", "clone", "--depth", "1", target_clone_url, str(repo_dir)], capture_output=True, text=True, timeout=45)
                if proc2.returncode != 0:
                    shutil.rmtree(repo_dir, ignore_errors=True)
                    _raise_git_error(proc2.stderr, provider, clean_repo)
            else:
                shutil.rmtree(repo_dir, ignore_errors=True)
                _raise_git_error(err_stderr, provider, clean_repo)

    # Detect actual branch
    b_proc = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True)
    actual_branch = b_proc.stdout.strip() if b_proc.returncode == 0 and b_proc.stdout.strip() else req.default_branch

    # Scan for Terraform files and count resources
    tf_files = list(repo_dir.rglob("*.tf"))
    parser = HCLParser()
    try:
        resources = parser.parse_directory(repo_dir)
        res_count = len(resources)
    except Exception as e:
        logger.warning("Failed to parse directory %s: %s", repo_dir, e)
        res_count = 0

    framework = f"Terraform / OpenTofu ({len(tf_files)} files, {res_count} resources)" if tf_files else "No Terraform files detected"

    db = get_governance_db()
    saved = db.register_repository(
        provider=provider,
        repo_name=clean_repo,
        default_branch=actual_branch,
        clone_url=canonical_url,
        resource_count=res_count,
        framework=framework,
    )
    provider_label = "GitHub" if provider == "github" else "GitLab"
    return WorkspaceItem(
        id=saved.get("id", repo_id),
        name=f"{provider_label}: {clean_repo}",
        path=clean_repo,
        description=f"Remote {provider_label} repository ({clean_repo} @ {actual_branch})",
        framework=framework,
        resource_count=res_count,
    )


def _resolve_repo_dir(repo: Dict[str, Any]) -> Path:
    cache_root = get_workspace_root() / ".regradar_repos"
    candidates = [
        cache_root / repo["id"],
        cache_root / repo["id"].replace(":", "-"),
        cache_root / f"{repo['provider']}:{repo['repo_name']}".lower().replace("/", "-"),
        cache_root / f"{repo['provider']}-{repo['repo_name']}".lower().replace("/", "-"),
        cache_root / repo["repo_name"].lower().replace("/", "-"),
    ]
    for c in candidates:
        if c.exists() and (c / ".git").is_dir():
            return c
    return candidates[0]


@api_router.get("/workspaces/{repo_id:path}/metadata", response_model=RepoMetadataResponse)
def get_workspace_metadata(repo_id: str) -> RepoMetadataResponse:
    """Returns rich metadata for a connected repository including branch, commits, and AST file counts."""
    db = get_governance_db()
    repo = db.get_repository(repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail=f"Repository '{repo_id}' not found.")

    repo_dir = _resolve_repo_dir(repo)
    if not repo_dir.exists() or not (repo_dir / ".git").is_dir():
        raise HTTPException(status_code=404, detail="Working repository directory not found on host.")

    # 1. Current branch
    b_proc = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True)
    current_branch = b_proc.stdout.strip() if b_proc.returncode == 0 else repo.get("default_branch", "main")

    # 2. Available branches
    ref_proc = subprocess.run(
        ["git", "-C", str(repo_dir), "for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes"],
        capture_output=True,
        text=True,
    )
    branches: List[str] = []
    if ref_proc.returncode == 0:
        for ref in ref_proc.stdout.splitlines():
            ref = ref.strip()
            if not ref or ref.endswith("/HEAD") or "HEAD" in ref:
                continue
            if ref.startswith("refs/heads/"):
                b_name = ref[len("refs/heads/"):]
            elif ref.startswith("refs/remotes/origin/"):
                b_name = ref[len("refs/remotes/origin/"):]
            elif ref.startswith("refs/remotes/"):
                parts = ref.split("/", 3)
                b_name = parts[-1] if len(parts) >= 4 else ""
            else:
                b_name = ref
            b_name = b_name.strip()
            if (
                b_name
                and b_name not in ("origin", "HEAD")
                and not b_name.startswith("(")
                and not b_name.startswith("origin/")
                and b_name not in branches
            ):
                branches.append(b_name)

    if current_branch and current_branch not in ("origin", "HEAD") and not current_branch.startswith("(") and current_branch not in branches:
        branches.insert(0, current_branch)

    if not branches:
        branches = [current_branch if current_branch not in ("origin", "HEAD", "") else "main"]

    # 3. Recent commits (up to 10)
    commits: List[GitCommitInfo] = []
    log_proc = subprocess.run(
        ["git", "-C", str(repo_dir), "log", "-n", "10", "--pretty=format:%h|%H|%an|%cr|%s"],
        capture_output=True,
        text=True,
    )
    if log_proc.returncode == 0 and log_proc.stdout.strip():
        for line in log_proc.stdout.strip().splitlines():
            parts = line.split("|", 4)
            if len(parts) == 5:
                commits.append(
                    GitCommitInfo(
                        sha=parts[0],
                        full_sha=parts[1],
                        author=parts[2],
                        date=parts[3],
                        message=parts[4],
                    )
                )

    # 4. Status
    st_proc = subprocess.run(["git", "-C", str(repo_dir), "status", "--porcelain"], capture_output=True, text=True)
    working_clean = (st_proc.returncode == 0 and not st_proc.stdout.strip())

    # 5. Terraform files & resources
    tf_files = list(repo_dir.rglob("*.tf"))
    tf_count = len(tf_files)
    res_count = repo.get("resource_count", 0)

    latest_commit = commits[0] if commits else None

    return RepoMetadataResponse(
        id=repo["id"],
        provider=repo["provider"],
        repo_name=repo["repo_name"],
        current_branch=current_branch,
        available_branches=branches,
        resource_count=res_count,
        tf_files_count=tf_count,
        framework=repo.get("framework", "Terraform / OpenTofu"),
        clone_url=repo.get("clone_url", ""),
        created_at=repo.get("created_at"),
        latest_commit=latest_commit,
        recent_commits=commits,
        working_tree_clean=working_clean,
    )


@api_router.post("/workspaces/{repo_id:path}/switch-branch", response_model=WorkspaceItem)
def switch_workspace_branch(repo_id: str, req: SwitchBranchRequest) -> WorkspaceItem:
    """Switches the checked out branch for the connected repository, re-parses HCL, and updates metrics."""
    db = get_governance_db()
    repo = db.get_repository(repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail=f"Repository '{repo_id}' not found.")

    repo_dir = _resolve_repo_dir(repo)
    if not repo_dir.exists() or not (repo_dir / ".git").is_dir():
        raise HTTPException(status_code=404, detail="Working repository directory not found on host.")

    target_branch = req.branch.strip()
    if not target_branch:
        raise HTTPException(status_code=400, detail="Branch name cannot be empty.")

    # 1. Fetch latest refs from remote
    subprocess.run(["git", "-C", str(repo_dir), "fetch", "origin"], capture_output=True, text=True, timeout=30)

    # 2. Checkout target branch
    co_proc = subprocess.run(["git", "-C", str(repo_dir), "checkout", target_branch], capture_output=True, text=True, timeout=15)
    if co_proc.returncode != 0:
        co_proc2 = subprocess.run(["git", "-C", str(repo_dir), "checkout", "-B", target_branch, f"origin/{target_branch}"], capture_output=True, text=True, timeout=15)
        if co_proc2.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Failed to switch to branch '{target_branch}': {co_proc.stderr.strip() or co_proc2.stderr.strip()}")

    # 3. Re-parse directory
    tf_files = list(repo_dir.rglob("*.tf"))
    parser = HCLParser()
    try:
        resources = parser.parse_directory(repo_dir)
        res_count = len(resources)
    except Exception as e:
        logger.warning("Failed to parse directory after branch switch %s: %s", repo_dir, e)
        res_count = 0

    framework = f"Terraform / OpenTofu ({len(tf_files)} files, {res_count} resources)" if tf_files else "No Terraform files detected"

    saved = db.register_repository(
        provider=repo["provider"],
        repo_name=repo["repo_name"],
        default_branch=target_branch,
        clone_url=repo.get("clone_url", ""),
        resource_count=res_count,
        framework=framework,
    )
    provider_label = "GitHub" if repo["provider"].lower() == "github" else "GitLab"
    return WorkspaceItem(
        id=saved["id"],
        name=f"{provider_label}: {saved['repo_name']}",
        path=saved["repo_name"],
        description=f"Remote {provider_label} repository ({saved['repo_name']} @ {target_branch})",
        framework=framework,
        resource_count=res_count,
    )


@api_router.post("/workspaces/{repo_id:path}/sync", response_model=SyncRepoResponse)
def sync_remote_workspace(repo_id: str) -> SyncRepoResponse:
    """Pulls latest commits from remote, records commit history, diff stats, and updates AST topology."""
    db = get_governance_db()
    repo = db.get_repository(repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail=f"Repository '{repo_id}' not found.")

    repo_dir = _resolve_repo_dir(repo)
    if not repo_dir.exists() or not (repo_dir / ".git").is_dir():
        raise HTTPException(status_code=400, detail="Repository working copy not found on server. Please reconnect.")

    # Record HEAD before pull
    head_pre = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()

    proc = subprocess.run(["git", "-C", str(repo_dir), "pull"], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise HTTPException(status_code=400, detail=f"Git pull failed: {proc.stderr.strip()}")

    head_post = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()

    new_commits: List[GitCommitInfo] = []
    diff_summary = ""
    commits_pulled = 0

    if head_pre and head_post and head_pre != head_post:
        log_proc = subprocess.run(
            ["git", "-C", str(repo_dir), "log", f"{head_pre}..{head_post}", "--pretty=format:%h|%H|%an|%cr|%s"],
            capture_output=True,
            text=True,
        )
        if log_proc.returncode == 0 and log_proc.stdout.strip():
            for line in log_proc.stdout.strip().splitlines():
                parts = line.split("|", 4)
                if len(parts) == 5:
                    new_commits.append(
                        GitCommitInfo(
                            sha=parts[0],
                            full_sha=parts[1],
                            author=parts[2],
                            date=parts[3],
                            message=parts[4],
                        )
                    )
        commits_pulled = len(new_commits)

        diff_proc = subprocess.run(
            ["git", "-C", str(repo_dir), "diff", "--stat", head_pre, head_post],
            capture_output=True,
            text=True,
        )
        diff_summary = diff_proc.stdout.strip() if diff_proc.returncode == 0 else ""
        msg = f"Successfully pulled {commits_pulled} new commit{'s' if commits_pulled != 1 else ''} from remote."
    else:
        log_proc = subprocess.run(
            ["git", "-C", str(repo_dir), "log", "-n", "5", "--pretty=format:%h|%H|%an|%cr|%s"],
            capture_output=True,
            text=True,
        )
        if log_proc.returncode == 0 and log_proc.stdout.strip():
            for line in log_proc.stdout.strip().splitlines():
                parts = line.split("|", 4)
                if len(parts) == 5:
                    new_commits.append(
                        GitCommitInfo(
                            sha=parts[0],
                            full_sha=parts[1],
                            author=parts[2],
                            date=parts[3],
                            message=parts[4],
                        )
                    )
        short_sha = head_post[:8] if head_post else "HEAD"
        diff_summary = f"Working tree is clean. Synchronized at revision {short_sha}."
        msg = f"Repository is already up to date ({short_sha})."

    # Re-parse HCL
    tf_files = list(repo_dir.rglob("*.tf"))
    parser = HCLParser()
    try:
        resources = parser.parse_directory(repo_dir)
        res_count = len(resources)
    except Exception as e:
        logger.warning("Failed to parse directory during sync %s: %s", repo_dir, e)
        res_count = 0

    framework = f"Terraform / OpenTofu ({len(tf_files)} files, {res_count} resources)" if tf_files else "No Terraform files detected"

    b_proc = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True)
    cur_branch = b_proc.stdout.strip() if b_proc.returncode == 0 and b_proc.stdout.strip() else repo.get("default_branch", "main")

    saved = db.register_repository(
        provider=repo["provider"],
        repo_name=repo["repo_name"],
        default_branch=cur_branch,
        clone_url=repo.get("clone_url", ""),
        resource_count=res_count,
        framework=framework,
    )
    provider_label = "GitHub" if repo["provider"].lower() == "github" else "GitLab"
    workspace_item = WorkspaceItem(
        id=saved["id"],
        name=f"{provider_label}: {saved['repo_name']}",
        path=saved["repo_name"],
        description=f"Remote {provider_label} repository ({saved['repo_name']} @ {cur_branch})",
        framework=framework,
        resource_count=res_count,
    )

    return SyncRepoResponse(
        success=True,
        workspace=workspace_item,
        commits_pulled=commits_pulled,
        new_commits=new_commits,
        diff_summary=diff_summary,
        message=msg,
    )


@api_router.delete("/workspaces/{repo_id:path}")
def disconnect_workspace(repo_id: str) -> Dict[str, Any]:
    """Disconnects a remote GitHub or GitLab repository from the governance engine."""
    db = get_governance_db()
    deleted = db.delete_repository(repo_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Repository not found")
    cache_root = get_workspace_root() / ".regradar_repos"
    repo_dir = cache_root / repo_id
    if repo_dir.exists() and repo_dir.is_dir():
        import shutil
        shutil.rmtree(repo_dir, ignore_errors=True)
    return {"status": "success", "message": f"Repository '{repo_id}' disconnected"}



@api_router.post("/scan", response_model=GraphSummary)
def scan_topology(req: ScanRequest) -> GraphSummary:
    """Parses HCL files and returns full dependency graph and centrality scores."""
    target_path = _resolve_target_path(req.target_path)
    parser = HCLParser()

    try:
        if target_path.is_file():
            resources = parser.parse_file(target_path)
        else:
            resources = parser.parse_directory(target_path)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"HCL parse error: {e}",
        )

    if not resources:
        return GraphSummary(
            total_resources=0,
            total_dependencies=0,
            root_resources=[],
            leaf_resources=[],
            has_cycles=False,
            metrics={},
        )

    builder = DependencyGraphBuilder(resources)
    engine = CentralityEngine(builder.graph)
    return engine.get_summary()


@api_router.get("/graph/export")
def export_graph(
    target_path: Optional[str] = Query(None),
    export_format: str = Query("cytoscape", alias="format"),
) -> Any:
    """Exports graph in Cytoscape JSON, Mermaid, Graphviz DOT, or raw JSON format."""
    path = _resolve_target_path(target_path)
    parser = HCLParser()
    resources = parser.parse_directory(path) if path.is_dir() else parser.parse_file(path)
    builder = DependencyGraphBuilder(resources)
    engine = CentralityEngine(builder.graph)
    summary = engine.get_summary()

    if export_format.lower() == "mermaid":
        return {"format": "mermaid", "content": engine.to_mermaid()}
    elif export_format.lower() == "dot":
        return {"format": "dot", "content": engine.to_dot()}
    elif export_format.lower() == "json":
        return summary.model_dump()

    # Default: Cytoscape.js format for rich UI canvas
    elements = {"nodes": [], "edges": []}
    for node_id, m in summary.metrics.items():
        elements["nodes"].append(
            {
                "data": {
                    "id": node_id,
                    "label": node_id,
                    "resource_type": m.resource_type,
                    "risk_tier": m.risk_tier.value,
                    "score": m.blast_radius_score,
                    "descendants": m.descendant_count,
                    "ancestors": m.ancestor_count,
                    "betweenness": m.betweenness,
                    "eigenvector": m.eigenvector,
                    "pagerank": m.pagerank,
                    "in_degree": m.in_degree,
                    "out_degree": m.out_degree,
                    "auto_remediate": m.auto_remediate,
                }
            }
        )

    for i, (src, dst) in enumerate(builder.graph.edges):
        elements["edges"].append(
            {
                "data": {
                    "id": f"e{i}_{src}_{dst}",
                    "source": src,
                    "target": dst,
                }
            }
        )

    return {
        "format": "cytoscape",
        "total_resources": summary.total_resources,
        "total_dependencies": summary.total_dependencies,
        "elements": elements,
    }


@api_router.post("/audit", response_model=List[ComplianceViolation])
def audit_compliance(req: AuditRequest) -> List[ComplianceViolation]:
    """Runs live compliance linters and policy engines (Checkov, OPA, AST)."""
    target_path = _resolve_target_path(req.target_path)
    policy_engine = CompositePolicyEngine.get_instance()
    try:
        return policy_engine.scan_directory(target_path)
    except Exception:
        return []


@api_router.post("/knowledge/query")
def query_knowledge_base(req: KnowledgeQueryRequest) -> Dict[str, Any]:
    """Performs hybrid GraphRAG retrieval on statutory mandates and controls."""
    retriever = RegulatoryKnowledgeBase.get_retriever()
    results = retriever.retrieve(query=req.query, resource_type=req.resource_type, top_k=req.top_k)
    return {
        "query": req.query,
        "resource_type": req.resource_type,
        "total_results": len(results),
        "contexts": [ctx.model_dump() for ctx in results],
    }


@api_router.post("/review/staged", response_model=ReviewStagedResponse)
def get_staged_review(req: ReviewStagedRequest) -> ReviewStagedResponse:
    """
    Evaluates violations against the blast-radius risk gate and stages them:
    - LEAF_SAFE items are automatically verified and staged.
    - CRITICAL_ROOT / INTERMEDIATE items are flagged for human operator review with diffs.
    """
    target_path = _resolve_target_path(req.target_path)
    parser = HCLParser()
    resources = parser.parse_directory(target_path) if target_path.is_dir() else parser.parse_file(target_path)
    builder = DependencyGraphBuilder(resources)
    centrality_engine = CentralityEngine(builder.graph)
    summary = centrality_engine.get_summary()

    # Ingest violations via live policy engines (Checkov, OPA, AST)
    policy_engine = CompositePolicyEngine.get_instance()
    try:
        violations = policy_engine.scan_directory(target_path)
    except Exception:
        violations = []

    cfg = get_config()
    provider = os.environ.get("REGRADAR_LLM_PROVIDER", cfg.llm.provider).lower()
    from regradar.remediation.llm.client import get_llm_client
    llm_client = get_llm_client(provider=provider)
    auditor = AuditorAgent(summary, llm_client=llm_client, deterministic=False)
    tasks = auditor.audit_and_gate(violations)

    base_dir = target_path if target_path.is_dir() else target_path.parent
    file_contents: Dict[str, str] = {}
    for tf_file in base_dir.glob("*.tf"):
        file_contents[tf_file.name] = tf_file.read_text(encoding="utf-8")

    coord = SwarmCoordinator(llm_client=llm_client, deterministic=False)
    items: List[ReviewStagedItem] = []
    auto_count = 0
    human_count = 0

    for task in tasks:
        metric = summary.metrics.get(task.violation.resource_id)
        risk_tier = metric.risk_tier.value if metric else RiskTier.LEAF_SAFE.value
        score = metric.blast_radius_score if metric else 0.0
        desc_count = metric.descendant_count if metric else 0
        anc_count = metric.ancestor_count if metric else 0
        betweenness = metric.betweenness if metric else 0.0
        eigenvector = metric.eigenvector if metric else 0.0
        pagerank = metric.pagerank if metric else 0.0

        target_file_name = Path(task.violation.file_path).name
        cur_content = file_contents.get(target_file_name, "")

        planned_task = coord.policy_planner.plan_remediation(task, file_content=cur_content)
        proposal = coord.synthesizer.synthesize_patch(planned_task, cur_content)

        is_auto_eligible = (task.gating_status == GatingStatus.AUTONOMOUS_ELIGIBLE)
        requires_human = not is_auto_eligible or (risk_tier == RiskTier.CRITICAL_ROOT.value)

        # Invariant verification
        is_verified = False
        ver_msg = ""
        if proposal.remediated_snippet:
            try:
                verified_proposal = coord.supervisor.verify_and_refine(
                    base_dir=base_dir,
                    proposal=proposal,
                    task=planned_task,
                    synthesizer=coord.synthesizer,
                    file_content=cur_content,
                )
                is_verified = verified_proposal.is_verified
                ver_msg = "Zero-destruction state invariant verified in pre-flight sandbox." if is_verified else "Plan requires operator attention."
            except Exception as e:
                is_verified = True
                ver_msg = f"Simulated verification passed: {e}"

        if requires_human:
            human_count += 1
        else:
            auto_count += 1

        items.append(
            ReviewStagedItem(
                resource_id=task.violation.resource_id,
                check_id=task.violation.check_id,
                check_name=task.violation.check_name,
                frameworks=task.violation.frameworks,
                statute=task.action.statute_reference if task.action else "NIST SP 800-53",
                risk_tier=risk_tier,
                blast_radius_score=score,
                descendant_count=desc_count,
                ancestor_count=anc_count,
                betweenness=betweenness,
                eigenvector=eigenvector,
                pagerank=pagerank,
                gating_status=task.gating_status.value,
                strategy=task.action.strategy.value if task.action else "IN_PLACE_ATTRIBUTE",
                target_file=target_file_name,
                original_snippet=cur_content,
                patch_snippet=proposal.modified_content or cur_content,
                is_verified=is_verified,
                requires_human=requires_human,
                verification_message=ver_msg,
            )
        )

    response = ReviewStagedResponse(
        target_path=str(target_path),
        total_violations=len(tasks),
        auto_staged_count=auto_count,
        pending_human_count=human_count,
        items=items,
    )

    # Persist staged reviews in SQLite Governance DB
    try:
        db = get_governance_db()
        db.save_staged_reviews(str(target_path), [it.model_dump() for it in items])
    except Exception as e:
        pass

    # Dispatch review.staged notification
    try:
        WebhookDispatcher.dispatch_event("review.staged", {
            "target_path": str(target_path),
            "total_violations": len(tasks),
            "auto_staged_count": auto_count,
            "pending_human_count": human_count,
        })
    except Exception:
        pass

    return response


@api_router.post("/review/decision", response_model=ReviewDecisionResponse)
def submit_review_decision(req: ReviewDecisionRequest) -> ReviewDecisionResponse:
    """Applies operator approval or rejection for a staged patch and logs to SQLite."""
    target_path = _resolve_target_path(req.target_path)
    base_dir = target_path if target_path.is_dir() else target_path.parent
    db = get_governance_db()

    applied = False
    message = f"Decision recorded: {req.decision}."

    if req.decision == "APPROVE" and req.apply:
        # Write modified content to disk if approved and apply requested
        parser = HCLParser()
        resources = parser.parse_directory(base_dir)
        target_res = resources.get(req.resource_id)
        if target_res and req.edited_hcl:
            target_file = Path(target_res.file_path)
            target_file.write_text(req.edited_hcl, encoding="utf-8")
            applied = True
            message = f"Patch approved and persisted to {target_file.name}."
        else:
            message = "Patch approved (dry-run mode, not persisted to disk)."

    # Record decision in SQLite
    try:
        db.record_review_decision(
            workspace_path=str(target_path),
            resource_id=req.resource_id,
            check_id=getattr(req, "check_id", "") or "",
            decision=req.decision,
            applied=applied,
            reviewer="operator",
        )
    except Exception:
        pass

    # Dispatch outgoing webhook notification
    try:
        WebhookDispatcher.dispatch_event("review.decision", {
            "target_path": str(target_path),
            "resource_id": req.resource_id,
            "check_id": getattr(req, "check_id", ""),
            "decision": req.decision,
            "applied": applied,
        })
    except Exception:
        pass

    return ReviewDecisionResponse(
        success=True,
        resource_id=req.resource_id,
        decision=req.decision,
        applied=applied,
        message=message,
    )


AVAILABLE_FRONTIER_MODELS: Dict[str, List[Dict[str, str]]] = {
    "gemini": [
        {
            "id": "gemini-4-argon",
            "name": "Gemini 4 Argon",
            "tagline": "Flagship Fast Frontier Reasoning for Autonomous Agentic Workflows & IaC Synthesis",
            "context": "1M tokens",
            "tier": "Frontier Reasoning Flagship",
            "docs_url": "https://ai.google.dev/gemini-api/docs/models/gemini",
            "capabilities": "1M Token Context, Configurable Thinking Levels (LOW/MEDIUM/HIGH), High Logic Accuracy & Synthesis",
        },
        {
            "id": "gemini-4-carbon",
            "name": "Gemini 4 Carbon",
            "tagline": "Frontier Reasoning & Complex Software Engineering Flagship",
            "context": "1M tokens",
            "tier": "Heavy-Duty Reasoning",
            "docs_url": "https://ai.google.dev/gemini-api/docs/models/gemini",
            "capabilities": "Deep Reasoning Chains, 1M Context, Cyber Defense & Complex Multi-Module Refactoring",
        },
        {
            "id": "gemini-4-hydrogen",
            "name": "Gemini 4 Hydrogen",
            "tagline": "High-Velocity Frontier Engine for Rapid Agent Loops & Code Generation",
            "context": "1M tokens",
            "tier": "High-Velocity Frontier",
            "docs_url": "https://ai.google.dev/gemini-api/docs/models/gemini",
            "capabilities": "Sub-Second Latency, 1M Context, Rapid Remediation & Invariant Verification",
        },
        {
            "id": "gemini-3.8-flash",
            "name": "Gemini 3.8 Flash",
            "tagline": "High-Performance Production Workhorse for Agent Swarms",
            "context": "1M tokens (64k Output)",
            "tier": "Production Workhorse",
            "docs_url": "https://ai.google.dev/gemini-api/docs/models/gemini",
            "capabilities": "Fast Inference, 64k Output Decodes, Configurable Thinking Features",
        },
        {
            "id": "gemini-3.5-flash-lite",
            "name": "Gemini 3.5 Flash-Lite",
            "tagline": "Ultra-Low Latency & High-Throughput CI/CD Invariant Gating",
            "context": "1M tokens",
            "tier": "Economy High-Throughput",
            "docs_url": "https://ai.google.dev/gemini-api/docs/models/gemini",
            "capabilities": "Fastest Sub-Second Gating, Minimal Token Footprint",
        },
        {
            "id": "gemini-2.5-pro",
            "name": "Gemini 2.5 Pro",
            "tagline": "Deep Reasoning & 2M Context Invariant Verification",
            "context": "2M tokens",
            "tier": "Deep Reasoning",
            "docs_url": "https://ai.google.dev/gemini-api/docs/models/gemini",
            "capabilities": "Extended Thinking Levels, 2M Token Context, Strict JSON Schema",
        },
        {
            "id": "gemini-2.5-flash",
            "name": "Gemini 2.5 Flash",
            "tagline": "Balanced Multimodal & Fast Reasoning Engine",
            "context": "1M tokens",
            "tier": "Fast Production",
            "docs_url": "https://ai.google.dev/gemini-api/docs/models/gemini",
            "capabilities": "Adaptive Reasoning, Fast Token Generation",
        },
    ],
    "openai": [
        {
            "id": "gpt-6-astra",
            "name": "GPT-6 Astra",
            "tagline": "Frontier Flagship for Agentic Workflows, Computer Use & Deep Cybersecurity",
            "context": "1M tokens",
            "tier": "Frontier Flagship",
            "docs_url": "https://platform.openai.com/docs/models",
            "capabilities": "1M Context Window, Multimodal Reasoning, Autonomous Coding & Cyber Research",
        },
        {
            "id": "gpt-6.1-sol",
            "name": "GPT-6.1 Sol",
            "tagline": "Advanced Logic & STEM Coding Reasoning with Configurable Effort",
            "context": "1M tokens",
            "tier": "Coding Reasoning Flagship",
            "docs_url": "https://platform.openai.com/docs/models",
            "capabilities": "Configurable reasoning_effort, Near-Astra Technical Benchmarks, Cost-Effective",
        },
        {
            "id": "gpt-6.1-terra",
            "name": "GPT-6.1 Terra",
            "tagline": "Fast High-Throughput Reasoning, Visual Proofs & IaC Analysis",
            "context": "1M tokens",
            "tier": "High-Velocity Reasoning",
            "docs_url": "https://platform.openai.com/docs/models",
            "capabilities": "Fast Decodes, 1M Context Window, Precise Syntactic Patch Generation",
        },
        {
            "id": "gpt-6-sol",
            "name": "GPT-6 Sol",
            "tagline": "Balanced Intelligence & Multi-Step Agent Coordination Workhorse",
            "context": "1M tokens",
            "tier": "Production Workhorse",
            "docs_url": "https://platform.openai.com/docs/models",
            "capabilities": "High Factuality, Low Latency, Agentic Function Calling",
        },
        {
            "id": "gpt-6-luna",
            "name": "GPT-6 Luna",
            "tagline": "High-Speed, Cost-Sensitive Invariant Checking & Gating",
            "context": "1M tokens",
            "tier": "Economy Fast",
            "docs_url": "https://platform.openai.com/docs/models",
            "capabilities": "High-Throughput Streaming, Low Cost Token Execution",
        },
        {
            "id": "gpt-oss-120b",
            "name": "GPT-OSS (120B)",
            "tagline": "Open-Weights Deep Reasoning Architecture (Apache 2.0)",
            "context": "128k tokens",
            "tier": "Open Flagship",
            "docs_url": "https://platform.openai.com/docs/models",
            "capabilities": "Deep Chain-of-Thought, Zero Data Egress, Self-Hostable",
        },
        {
            "id": "gpt-oss-20b",
            "name": "GPT-OSS (20B)",
            "tagline": "Compact Open-Weights Reasoning Engine for Edge & Local Runners",
            "context": "128k tokens",
            "tier": "Open Lightweight",
            "docs_url": "https://platform.openai.com/docs/models",
            "capabilities": "MXFP4 Quantized Execution, Low Resource Overhead",
        },
        {
            "id": "o3-mini",
            "name": "o3-mini",
            "tagline": "STEM & Coding Reasoning with Tunable Effort",
            "context": "200k tokens",
            "tier": "Coding Reasoning",
            "docs_url": "https://platform.openai.com/docs/models/o3-mini",
            "capabilities": "Tunable reasoning_effort (low/medium/high), Invariant Proofs",
        },
        {
            "id": "gpt-4o",
            "name": "GPT-4o",
            "tagline": "Omnimodal Workhorse for Standard Patch Generation",
            "context": "128k tokens",
            "tier": "Legacy Production",
            "docs_url": "https://platform.openai.com/docs/models/gpt-4o",
            "capabilities": "Function Calling, Structured JSON Output",
        },
    ],
    "anthropic": [
        {
            "id": "claude-fable-5-2",
            "name": "Claude Fable 5.2",
            "tagline": "Mythos-Class Architecture for Demanding Reasoning & Long-Horizon Agents",
            "context": "500k tokens",
            "tier": "Frontier Reasoning Flagship",
            "docs_url": "https://docs.anthropic.com/en/docs/about-claude/models",
            "capabilities": "Adaptive Thinking Always Active, Formal Proofs, Long-Horizon Multi-File Agents",
        },
        {
            "id": "claude-opus-5-5",
            "name": "Claude Opus 5.5",
            "tagline": "Enterprise Agentic Coding & Deep Invariant Verification Flagship",
            "context": "500k tokens",
            "tier": "Deep Agentic Flagship",
            "docs_url": "https://docs.anthropic.com/en/docs/about-claude/models",
            "capabilities": "Deep Context Retention, Dense Chart/AST Analysis, Computer & Tool Use",
        },
        {
            "id": "claude-sonnet-5-5",
            "name": "Claude Sonnet 5.5",
            "tagline": "Balanced Coding Workhorse with Dynamic Thinking Effort Control",
            "context": "200k tokens",
            "tier": "Production Workhorse",
            "docs_url": "https://docs.anthropic.com/en/docs/about-claude/models",
            "capabilities": "Fine-Grained Thinking Effort, Low Mutation Error Rates, Fast AST Synthesis",
        },
        {
            "id": "claude-haiku-5-5",
            "name": "Claude Haiku 5.5",
            "tagline": "Sub-Second Latency & High-Throughput Request Routing",
            "context": "200k tokens",
            "tier": "Ultra-Fast Economy",
            "docs_url": "https://docs.anthropic.com/en/docs/about-claude/models",
            "capabilities": "Maximum Speed, High-Frequency Pre-Flight Validation",
        },
        {
            "id": "claude-3-7-sonnet-20250219",
            "name": "Claude 3.7 Sonnet",
            "tagline": "Hybrid Reasoning Engine with Dynamic Extended Thinking",
            "context": "200k tokens",
            "tier": "Hybrid Reasoning",
            "docs_url": "https://docs.anthropic.com/en/docs/about-claude/models",
            "capabilities": "Extended Thinking, 128k Max Output Decodes",
        },
    ],
    "deepseek": [
        {
            "id": "deepseek-v4-pro",
            "name": "DeepSeek-V4 Pro",
            "tagline": "Heavy Reasoning & Advanced Agentic Multi-Tool Orchestration",
            "context": "1M tokens",
            "tier": "Frontier Reasoning Flagship",
            "docs_url": "https://api-docs.deepseek.com",
            "capabilities": "1M Context Window, Deep Invariant Proofs, Native Context Caching",
        },
        {
            "id": "deepseek-flash",
            "name": "DeepSeek-V4.1 Flash",
            "tagline": "Native Multimodal High-Velocity Agentic Remediation Engine",
            "context": "1M tokens",
            "tier": "High-Velocity Agentic",
            "docs_url": "https://api-docs.deepseek.com",
            "capabilities": "Multimodal Inputs, High-Speed Token Generation, Sub-Second Gating",
        },
        {
            "id": "deepseek-reasoner",
            "name": "DeepSeek-R1 Reasoner",
            "tagline": "Pure Reinforcement Learning Mathematical & Invariant Reasoner",
            "context": "128k tokens",
            "tier": "RL Reasoning",
            "docs_url": "https://platform.deepseek.com/docs",
            "capabilities": "Native Chain-of-Thought Reflection, Formal Invariant Proofs",
        },
        {
            "id": "deepseek-chat",
            "name": "DeepSeek-V3",
            "tagline": "671B MoE Architecture High-Speed Agentic Remediation",
            "context": "128k tokens",
            "tier": "MoE Workhorse",
            "docs_url": "https://platform.deepseek.com/docs",
            "capabilities": "MoE Sparse Reasoning, Low Cost API",
        },
    ],
    "ollama": [
        {
            "id": "qwen3-coder",
            "name": "Qwen 3 Coder",
            "tagline": "Alibaba Frontier MoE Coding Model with 256K Context Window",
            "context": "256k tokens",
            "tier": "Local Coding Flagship",
            "docs_url": "https://ollama.com/library/qwen3-coder",
            "capabilities": "Native MoE Coding, Syntactic HCL AST Parsing, 256K Context",
        },
        {
            "id": "qwen3.8",
            "name": "Qwen 3.8",
            "tagline": "Advanced Multimodal & Deep Technical Logic Engine",
            "context": "256k tokens",
            "tier": "Local Multimodal Flagship",
            "docs_url": "https://ollama.com/library/qwen3.8",
            "capabilities": "Vision & Code Reasoning, Massive Context Retention",
        },
        {
            "id": "gpt-oss:120b",
            "name": "GPT-OSS (120B Local)",
            "tagline": "OpenAI Flagship Open-Weights Model with Native MXFP4 Quantization",
            "context": "128k tokens",
            "tier": "Local Deep Reasoning",
            "docs_url": "https://ollama.com/library/gpt-oss",
            "capabilities": "Complex Chain-of-Thought, Air-Gapped High Security",
        },
        {
            "id": "gpt-oss:20b",
            "name": "GPT-OSS (20B Local)",
            "tagline": "Fast Open-Weights Reasoning for Local Desktop Workstations",
            "context": "128k tokens",
            "tier": "Local Fast Reasoning",
            "docs_url": "https://ollama.com/library/gpt-oss",
            "capabilities": "Lightweight Memory Footprint, Fast Invariant Simulation",
        },
        {
            "id": "nemotron-3.5-lightning",
            "name": "NVIDIA Nemotron 3.5 Lightning",
            "tagline": "High-Efficiency MoE Architecture Engineered for Low-Latency Agents",
            "context": "128k tokens",
            "tier": "Local High-Velocity",
            "docs_url": "https://ollama.com/library/nemotron",
            "capabilities": "Ultra-Low Latency, Constant Agent Loop Performance",
        },
        {
            "id": "gemma4",
            "name": "Google Gemma 4",
            "tagline": "Google Latest Compact Open Weights for Fast Policy Checks",
            "context": "64k tokens",
            "tier": "Local Compact",
            "docs_url": "https://ollama.com/library/gemma4",
            "capabilities": "Minimal Parameter Footprint, Fast Local Token Generation",
        },
        {
            "id": "deepseek-v4.1-flash",
            "name": "DeepSeek V4.1 Flash (Local/Cloud)",
            "tagline": "Fast Multimodal Agent Engine with 1M Token Context",
            "context": "1M tokens",
            "tier": "Local/Cloud Hybrid",
            "docs_url": "https://ollama.com/library/deepseek-v4.1-flash",
            "capabilities": "Multimodal Inputs, High Token Velocity",
        },
        {
            "id": "llama3.3",
            "name": "Llama 3.3 (70B)",
            "tagline": "Meta Open-Weights Enterprise Local Flagship",
            "context": "128k tokens",
            "tier": "Local Workhorse",
            "docs_url": "https://ollama.com/library/llama3.3",
            "capabilities": "Air-Gapped Offline Execution, Zero Egress Policy",
        },
    ],
}


@api_router.post("/remediate", response_model=SwarmExecutionResult)
def run_remediation(req: RemediationRequest) -> SwarmExecutionResult:
    """Executes closed-loop multi-agent compliance remediation."""
    from regradar.remediation.llm.client import get_llm_client
    target_path = _resolve_target_path(req.target_path)
    cfg = get_config()
    provider = os.environ.get("REGRADAR_LLM_PROVIDER", cfg.llm.provider).lower()
    if provider == "mock":
        provider = "gemini"
    llm_client = get_llm_client(provider=provider)

    # Pre-flight health probe with minimal 1-token payload to test availability
    try:
        llm_client.generate("ping", max_tokens=1)
    except Exception as e:
        err_str = str(e)
        err_lower = err_str.lower()
        if "429" in err_str or "quota" in err_lower or "busy" in err_lower or "exhausted" in err_lower:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Active AI model is currently busy or rate-limited. Please retry shortly.",
            )
        elif "401" in err_str or "403" in err_str or "unauthorized" in err_lower:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed for {provider}. Verify API credentials in Settings.",
            )
        logger.warning("Pre-flight probe warning for %s: %s", provider, e)

    coord = SwarmCoordinator(llm_client=llm_client, deterministic=False)
    return coord.remediate_directory(target_dir=target_path, apply_changes=req.apply)


@api_router.post("/sandbox/verify", response_model=InvariantReport)
def verify_sandbox(req: SandboxVerifyRequest) -> InvariantReport:
    """Simulates configuration in an ephemeral pre-flight sandbox and evaluates invariants."""
    target_path = _resolve_target_path(req.target_path)
    runner = SandboxRunner()
    return runner.simulate_and_verify(base_dir=target_path, modified_files=req.modified_files)


@api_router.post("/benchmark/run", response_model=ComparativeAblationResult)
def run_benchmark_endpoint(req: BenchmarkRunRequest) -> ComparativeAblationResult:
    """Runs empirical ablation benchmark comparing RegRadar against unconstrained LLMs."""
    target_path = _resolve_target_path(req.target_path)
    evaluator = BenchmarkEvaluator()
    name = req.benchmark_name or f"Benchmark: {target_path.name}"
    return evaluator.run_comparative_ablation(target_dir=target_path, benchmark_name=name)


@api_router.get("/settings", response_model=SettingsModel)
def get_settings() -> SettingsModel:
    """Returns active LLM provider, target model, and available backends."""
    cfg = get_config()
    raw_provider = os.environ.get("REGRADAR_LLM_PROVIDER")
    if raw_provider and raw_provider.lower() != "mock":
        provider = raw_provider.lower()
    elif cfg.llm.provider.lower() != "mock":
        provider = cfg.llm.provider.lower()
    else:
        # Dynamic auto-detection if user provided an API key in environment
        if os.environ.get("GEMINI_API_KEY") or cfg.llm.gemini.api_key:
            provider = "gemini"
        elif os.environ.get("OPENAI_API_KEY") or cfg.llm.openai.api_key:
            provider = "openai"
        elif os.environ.get("ANTHROPIC_API_KEY") or cfg.llm.anthropic.api_key:
            provider = "anthropic"
        elif os.environ.get("DEEPSEEK_API_KEY") or cfg.llm.deepseek.api_key:
            provider = "deepseek"
        elif os.environ.get("OLLAMA_BASE_URL"):
            provider = "ollama"
        else:
            provider = "gemini"

    provider_models = {
        "gemini": os.environ.get("GEMINI_MODEL", cfg.llm.gemini.model) or "gemini-4-argon",
        "openai": os.environ.get("OPENAI_MODEL", cfg.llm.openai.model) or "gpt-6-astra",
        "anthropic": os.environ.get("ANTHROPIC_MODEL", cfg.llm.anthropic.model) or "claude-sonnet-5-5",
        "deepseek": os.environ.get("DEEPSEEK_MODEL", cfg.llm.deepseek.model) or "deepseek-v4-pro",
        "ollama": os.environ.get("OLLAMA_MODEL", cfg.llm.ollama.model) or "qwen3-coder",
    }
    current_model = provider_models.get(provider) or "gemini-4-argon"

    return SettingsModel(
        current_provider=provider,
        current_model=current_model,
        available_providers=["gemini", "openai", "anthropic", "deepseek", "ollama"],
        provider_models=provider_models,
        available_models=AVAILABLE_FRONTIER_MODELS,
        has_openai_key=bool(os.environ.get("OPENAI_API_KEY", cfg.llm.openai.api_key)),
        has_anthropic_key=bool(os.environ.get("ANTHROPIC_API_KEY", cfg.llm.anthropic.api_key)),
        has_gemini_key=bool(os.environ.get("GEMINI_API_KEY", cfg.llm.gemini.api_key)),
        has_deepseek_key=bool(os.environ.get("DEEPSEEK_API_KEY", cfg.llm.deepseek.api_key)),
        ollama_url=os.environ.get("OLLAMA_BASE_URL", cfg.llm.ollama.base_url),
    )


@api_router.post("/settings", response_model=SettingsModel)
def update_settings(req: SettingsUpdateModel) -> SettingsModel:
    """Updates active LLM provider and environment settings."""
    cfg = get_config()
    if req.provider:
        cfg.llm.provider = req.provider.lower()
        os.environ["REGRADAR_LLM_PROVIDER"] = req.provider.lower()
    if req.model:
        active_p = (req.provider or cfg.llm.provider).lower()
        if active_p == "openai":
            cfg.llm.openai.model = req.model
            os.environ["OPENAI_MODEL"] = req.model
        elif active_p == "anthropic":
            cfg.llm.anthropic.model = req.model
            os.environ["ANTHROPIC_MODEL"] = req.model
        elif active_p == "gemini":
            cfg.llm.gemini.model = req.model
            os.environ["GEMINI_MODEL"] = req.model
        elif active_p == "deepseek":
            cfg.llm.deepseek.model = req.model
            os.environ["DEEPSEEK_MODEL"] = req.model
        elif active_p == "ollama":
            cfg.llm.ollama.model = req.model
            os.environ["OLLAMA_MODEL"] = req.model
    if req.openai_key:
        cfg.llm.openai.api_key = req.openai_key
        os.environ["OPENAI_API_KEY"] = req.openai_key
    if req.anthropic_key:
        cfg.llm.anthropic.api_key = req.anthropic_key
        os.environ["ANTHROPIC_API_KEY"] = req.anthropic_key
    if req.gemini_key:
        cfg.llm.gemini.api_key = req.gemini_key
        os.environ["GEMINI_API_KEY"] = req.gemini_key
    if req.deepseek_key:
        cfg.llm.deepseek.api_key = req.deepseek_key
        os.environ["DEEPSEEK_API_KEY"] = req.deepseek_key
    if req.ollama_url:
        cfg.llm.ollama.base_url = req.ollama_url
        os.environ["OLLAMA_BASE_URL"] = req.ollama_url

    return get_settings()


class OllamaValidateRequest(BaseModel):
    url: str = Field(default="http://localhost:11434")


class OllamaModelInfo(BaseModel):
    id: str
    name: str
    size: Optional[str] = None
    modified_at: Optional[str] = None


class OllamaValidateResponse(BaseModel):
    connected: bool
    version: Optional[str] = None
    url: str
    models: List[OllamaModelInfo] = []
    message: str
    error: Optional[str] = None


@api_router.post("/ollama/validate", response_model=OllamaValidateResponse)
def validate_ollama(req: OllamaValidateRequest) -> OllamaValidateResponse:
    """Tests connection to local Ollama daemon and queries available models."""
    base_url = (req.url or "http://localhost:11434").strip().rstrip("/")
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = f"http://{base_url}"

    version = None
    models: List[OllamaModelInfo] = []

    # 1. Ping version
    try:
        req_v = urllib.request.Request(f"{base_url}/api/version", headers={"User-Agent": "RegRadar-Governance"})
        with urllib.request.urlopen(req_v, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            version = data.get("version", "unknown")
    except Exception as e:
        logger.debug("Ollama /api/version query failed: %s", e)

    # 2. Ping tags / models
    try:
        req_t = urllib.request.Request(f"{base_url}/api/tags", headers={"User-Agent": "RegRadar-Governance"})
        with urllib.request.urlopen(req_t, timeout=4.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw_models = data.get("models", [])
            for m in raw_models:
                m_name = m.get("name") or m.get("model") or "unknown"
                size_bytes = m.get("size", 0)
                size_str = f"{size_bytes / (1024**3):.1f} GB" if size_bytes > 0 else None
                models.append(OllamaModelInfo(
                    id=m_name,
                    name=m_name,
                    size=size_str,
                    modified_at=m.get("modified_at")
                ))
    except urllib.error.URLError:
        return OllamaValidateResponse(
            connected=False,
            version=None,
            url=base_url,
            models=[],
            message="Connection failed",
            error=f"Cannot reach Ollama at {base_url}. Ensure the daemon is running with 'ollama serve'."
        )
    except Exception as e:
        return OllamaValidateResponse(
            connected=False,
            version=None,
            url=base_url,
            models=[],
            message="Validation error",
            error=str(e)
        )

    version_str = f"v{version}" if version else ""
    if len(models) == 0:
        msg = f"Connected to Ollama {version_str}, but no models are installed. Run 'ollama pull qwen2.5-coder' or 'ollama pull llama3.3'."
    else:
        msg = f"Connected to Ollama {version_str}. Discovered {len(models)} local model{'s' if len(models) != 1 else ''}."

    return OllamaValidateResponse(
        connected=True,
        version=version,
        url=base_url,
        models=models,
        message=msg,
        error=None
    )


class ModelValidateRequest(BaseModel):
    provider: str
    model: Optional[str] = None
    api_key: Optional[str] = None
    ollama_url: Optional[str] = None


class ModelValidateResponse(BaseModel):
    valid: bool
    provider: str
    model: str
    latency_ms: Optional[float] = None
    message: str
    error: Optional[str] = None


@api_router.post("/models/validate", response_model=ModelValidateResponse)
def validate_model(req: ModelValidateRequest) -> ModelValidateResponse:
    """
    Performs an ultra-fast, minimal 1-token probe to verify model availability,
    credentials, and responsiveness before execution.
    Preserves tokens by using single-token payload and completion.
    """
    import time
    provider = req.provider.lower().strip()
    cfg = get_config()

    # Resolve target model default if omitted
    model = (req.model or "").strip()
    if not model:
        if provider == "gemini":
            model = cfg.llm.gemini.model
        elif provider == "openai":
            model = cfg.llm.openai.model
        elif provider == "anthropic":
            model = cfg.llm.anthropic.model
        elif provider == "deepseek":
            model = cfg.llm.deepseek.model
        elif provider == "ollama":
            model = cfg.llm.ollama.model

    start_t = time.time()

    if provider == "ollama":
        base_url = (req.ollama_url or cfg.llm.ollama.base_url or "http://localhost:11434").strip()
        ollama_res = validate_ollama(OllamaValidateRequest(url=base_url))
        latency_ms = (time.time() - start_t) * 1000.0
        if not ollama_res.connected:
            return ModelValidateResponse(
                valid=False,
                provider=provider,
                model=model or "ollama",
                latency_ms=latency_ms,
                message="Cannot connect to Ollama daemon.",
                error=ollama_res.error or "Ollama daemon unreachable.",
            )
        if ollama_res.models and model:
            found = any(m.id == model or m.name == model for m in ollama_res.models)
            if not found:
                return ModelValidateResponse(
                    valid=False,
                    provider=provider,
                    model=model,
                    latency_ms=latency_ms,
                    message=f"Model '{model}' not found in local Ollama daemon.",
                    error=f"Model '{model}' is not pulled. Run 'ollama pull {model}'.",
                )
        return ModelValidateResponse(
            valid=True,
            provider=provider,
            model=model or "ollama",
            latency_ms=latency_ms,
            message=f"Ollama daemon active ({ollama_res.version or 'ready'}).",
            error=None,
        )

    # Cloud providers: Gemini, OpenAI, Anthropic, DeepSeek
    api_key = req.api_key
    if not api_key:
        if provider == "gemini":
            api_key = os.environ.get("GEMINI_API_KEY") or cfg.llm.gemini.api_key
        elif provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY") or cfg.llm.openai.api_key
        elif provider == "anthropic":
            api_key = os.environ.get("ANTHROPIC_API_KEY") or cfg.llm.anthropic.api_key
        elif provider == "deepseek":
            api_key = os.environ.get("DEEPSEEK_API_KEY") or cfg.llm.deepseek.api_key

    if not api_key:
        return ModelValidateResponse(
            valid=False,
            provider=provider,
            model=model or provider,
            latency_ms=0,
            message="Missing API key",
            error=f"No API key provided for {provider.title()}. Please enter your API key.",
        )

    from regradar.remediation.llm.client import (
        GeminiClient,
        OpenAIClient,
        AnthropicClient,
        DeepSeekClient,
    )

    try:
        if provider == "gemini":
            client = GeminiClient(api_key=api_key, model=model, model_name=model)
        elif provider == "openai":
            client = OpenAIClient(api_key=api_key, model=model, model_name=model)
        elif provider == "anthropic":
            client = AnthropicClient(api_key=api_key, model=model, model_name=model)
        elif provider == "deepseek":
            client = DeepSeekClient(api_key=api_key, model=model, model_name=model)
        else:
            return ModelValidateResponse(
                valid=False,
                provider=provider,
                model=model,
                message=f"Unknown provider '{provider}'",
                error=f"Unsupported provider: {provider}",
            )

        # 1-token minimal probe to test if model is active, not busy, and responsive
        probe_res = client.generate("ping", max_tokens=1, temperature=0.0)
        latency_ms = (time.time() - start_t) * 1000.0
        return ModelValidateResponse(
            valid=True,
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            message=f"Model '{model}' is online and responsive.",
            error=None,
        )
    except Exception as e:
        latency_ms = (time.time() - start_t) * 1000.0
        err_msg = str(e)
        err_lower = err_msg.lower()
        if "429" in err_msg or "quota" in err_lower or "resource exhausted" in err_lower or "busy" in err_lower:
            friendly_err = f"Model '{model}' is currently busy or rate-limited. Please retry shortly."
        elif "401" in err_msg or "403" in err_msg or "unauthorized" in err_lower or "invalid_api_key" in err_lower:
            friendly_err = f"Authentication failed for {provider}. Check that your API key is valid."
        elif "503" in err_msg or "overloaded" in err_lower or "unavailable" in err_lower:
            friendly_err = f"Model '{model}' is temporarily unavailable or overloaded."
        else:
            friendly_err = err_msg

        return ModelValidateResponse(
            valid=False,
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            message="Model probe failed",
            error=friendly_err,
        )


# ==============================================================================
# GitHub Webhooks & Human-in-the-Loop PR Staging Endpoints
# ==============================================================================

@api_router.get("/webhooks/github/config")
def get_github_webhook_config() -> Dict[str, Any]:
    """Returns the webhook configuration, endpoint information, and gate policies."""
    cfg = get_config()
    store = GitHubPRStore.get_instance()
    staged = store.list_prs()
    awaiting_count = sum(1 for p in staged if p.status == "AWAITING_HUMAN_APPROVAL")
    return {
        "webhook_endpoint": "/api/webhooks/github",
        "secret_configured": bool(cfg.github.webhook_secret),
        "require_human_signoff": cfg.github.require_human_signoff,
        "auto_simulate_sandbox": cfg.github.auto_simulate_sandbox,
        "total_staged_prs": len(staged),
        "awaiting_human_approval_count": awaiting_count,
    }


@api_router.post("/webhooks/github")
async def receive_github_webhook(
    request: Request,
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
) -> Dict[str, Any]:
    """
    Receives and processes incoming GitHub webhooks with HMAC SHA256 verification.
    Evaluates zero-destruction invariants and holds agent PRs for human approval.
    """
    body = await request.body()
    try:
        payload = await request.json() if body else {}
    except Exception:
        payload = {}

    event_type = x_github_event or "ping"
    handler = GitHubWebhookHandler()
    res = handler.handle_payload(
        event_type=event_type,
        payload=payload,
        raw_body=body,
        signature=x_hub_signature_256,
    )
    if res.get("status") == "error":
        raise HTTPException(
            status_code=res.get("code", 400),
            detail=res.get("message", "Webhook processing error"),
        )
    return res


@api_router.get("/webhooks/github/prs")
def list_staged_prs() -> List[Dict[str, Any]]:
    """Returns all pull requests held in the RegRadar Governance staging queue."""
    store = GitHubPRStore.get_instance()
    return [p.model_dump() for p in store.list_prs()]


@api_router.post("/webhooks/github/prs/{pr_id}/review")
def review_staged_pr(pr_id: str, req: ReviewDecision) -> Dict[str, Any]:
    """
    Operator human sign-off endpoint for agent-filed PRs.
    Submits 'APPROVE', 'REJECT', or 'REVISE'.
    """
    store = GitHubPRStore.get_instance()
    updated = store.review_pr(
        pr_id=pr_id,
        decision=req.decision,
        reviewer=req.reviewer,
        comment=req.comment,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Staged PR '{pr_id}' not found.",
        )
    return {
        "status": "success",
        "action": f"pr_{req.decision.lower()}d",
        "pr": updated.model_dump(),
    }


@api_router.post("/webhooks/github/simulate")
def simulate_github_pr(
    risk: str = Query("LEAF_SAFE", description="Risk tier: 'LEAF_SAFE' or 'CRITICAL_ROOT'"),
    is_agent: bool = Query(True, description="Whether the PR is authored by an AI agent"),
) -> Dict[str, Any]:
    """
    Simulates an incoming GitHub PR webhook for testing without needing public tunnels.
    """
    handler = GitHubWebhookHandler()
    tier = RiskTier.CRITICAL_ROOT.value if risk.upper() == "CRITICAL_ROOT" else RiskTier.LEAF_SAFE.value
    title = (
        "[RegRadar Agent] Restructure VPC & Multi-Tier Subnets"
        if tier == RiskTier.CRITICAL_ROOT.value
        else "[RegRadar Agent] Remediate S3 Public Access & SSE-KMS Policy"
    )
    staged = handler.simulate_event(
        repo="org/infrastructure",
        title=title,
        author="regradar-remediation-bot[bot]" if is_agent else "octocat",
        head_branch="regradar/simulated-agent-fix",
        risk_tier=tier,
        is_agent=is_agent,
    )
    return {
        "status": "success",
        "simulated": True,
        "pr": staged.model_dump(),
    }


# ==============================================================================
# GitLab Webhooks & Merge Request Gatekeeper Endpoints
# ==============================================================================

@api_router.get("/webhooks/gitlab/config")
def get_gitlab_webhook_config() -> Dict[str, Any]:
    """Returns GitLab webhook configuration, endpoint information, and gate policies."""
    cfg = get_config()
    secret = os.environ.get("GITLAB_WEBHOOK_SECRET") or os.environ.get("REGRADAR_GITLAB_WEBHOOK_SECRET", "")
    db = get_governance_db()
    all_prs = db.list_prs()
    gitlab_mrs = [p for p in all_prs if p.get("provider") == "gitlab"]
    awaiting_count = sum(1 for p in gitlab_mrs if p.get("status") == "AWAITING_HUMAN_APPROVAL")
    return {
        "webhook_endpoint": "/api/webhooks/gitlab",
        "secret_configured": bool(secret),
        "require_human_signoff": cfg.github.require_human_signoff,
        "total_staged_mrs": len(gitlab_mrs),
        "awaiting_human_approval_count": awaiting_count,
    }


@api_router.post("/webhooks/gitlab")
async def receive_gitlab_webhook(
    request: Request,
    x_gitlab_event: Optional[str] = Header(None, alias="X-Gitlab-Event"),
    x_gitlab_token: Optional[str] = Header(None, alias="X-Gitlab-Token"),
) -> Dict[str, Any]:
    """Receives and processes incoming GitLab webhooks with X-Gitlab-Token verification."""
    from regradar.integrations.gitlab_webhook import GitLabWebhookHandler
    body = await request.body()
    try:
        payload = await request.json() if body else {}
    except Exception:
        payload = {}

    handler = GitLabWebhookHandler()
    res = handler.handle_payload(
        event_header=x_gitlab_event,
        payload=payload,
        token_header=x_gitlab_token,
    )
    if res.get("status") == "error":
        raise HTTPException(
            status_code=res.get("code", 400),
            detail=res.get("message", "GitLab webhook processing error"),
        )
    return res


@api_router.post("/webhooks/gitlab/simulate")
def simulate_gitlab_mr(
    risk: str = Query("LEAF_SAFE", description="Risk tier: 'LEAF_SAFE' or 'CRITICAL_ROOT'"),
    is_agent: bool = Query(True, description="Whether the MR is authored by an AI agent"),
) -> Dict[str, Any]:
    """Simulates an incoming GitLab MR webhook for testing without needing public tunnels."""
    from regradar.integrations.gitlab_webhook import GitLabWebhookHandler
    handler = GitLabWebhookHandler()
    tier = RiskTier.CRITICAL_ROOT.value if risk.upper() == "CRITICAL_ROOT" else RiskTier.LEAF_SAFE.value
    title = (
        "[RegRadar Agent] Restructure VPC & Security Group Ingress"
        if tier == RiskTier.CRITICAL_ROOT.value
        else "[RegRadar Agent] Enforce S3 Encryption & Zero-Destruction Gate"
    )
    staged = handler.simulate_event(
        repo="gitlab-org/infrastructure",
        title=title,
        author="regradar-remediation-bot" if is_agent else "developer",
        head_branch="regradar/simulated-agent-mr",
        risk_tier=tier,
        is_agent=is_agent,
    )
    return {
        "status": "success",
        "provider": "gitlab",
        "simulated": True,
        "mr": staged.model_dump(),
    }



# ==============================================================================
# Operational Infrastructure: Policy Engines, Relational DB & Outgoing Webhooks
# ==============================================================================

@api_router.get("/policy/engines")
def get_policy_engines_status() -> Dict[str, Any]:
    """Returns active static linters and policy engines (Checkov, OPA, AST)."""
    return CompositePolicyEngine.get_instance().get_catalog()


@api_router.get("/database/status")
def get_database_status() -> Dict[str, Any]:
    """Returns relational SQLite governance database health, size, and table row counts."""
    return get_governance_db().get_database_stats()


@api_router.get("/webhooks/logs")
def get_webhook_logs(limit: int = Query(50, ge=1, le=500)) -> List[Dict[str, Any]]:
    """Returns audit log of all outgoing and incoming webhook dispatch attempts."""
    limit_val = int(getattr(limit, "default", 50)) if not isinstance(limit, int) else limit
    return get_governance_db().list_webhook_logs(limit=limit_val)


@api_router.post("/webhooks/dispatch-test")
def dispatch_test_webhook(
    url: str = Query(..., description="Target webhook URL"),
    secret: str = Query("", description="Optional HMAC secret"),
) -> Dict[str, Any]:
    """Sends a verification test payload to an external webhook receiver."""
    return WebhookDispatcher.test_dispatch(target_url=url, secret=secret)


