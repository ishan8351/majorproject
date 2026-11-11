"""
RegRadar GitHub Webhook Integration & Human-in-the-Loop PR Gatekeeper.

Provides:
- HMAC SHA256 Webhook signature validation.
- Ingestion of GitHub `pull_request`, `push`, and `ping` webhook events.
- Staged PR Store holding agent and human PRs requiring operator sign-off.
- Human intervention workflows ensuring agent-filed PRs cannot merge without human approval.
- Local simulation endpoint for testing without public webhooks.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from pydantic import BaseModel, Field

from regradar.config import get_config
from regradar.models import RiskTier
from regradar.integrations.github_action import PRGatekeeper, PRGateEvaluation
from regradar.invariant.models import ResourceChange

import urllib.request
import urllib.error

logger = logging.getLogger("regradar.integrations.github_webhook")


class ReviewDecision(BaseModel):
    """Operator decision submitted for a staged pull request."""
    decision: str = Field(..., description="'APPROVE', 'REJECT', or 'REVISE'")
    reviewer: str = Field(default="operator", description="Operator identity / username")
    comment: Optional[str] = Field(default=None, description="Optional operator review notes")


class StagedPR(BaseModel):
    """Pull request held in the RegRadar Governance staging queue."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    pr_number: int = Field(default=1)
    repo: str = Field(default="acme/infrastructure")
    title: str = Field(default="Remediate S3 Encryption Compliance")
    author: str = Field(default="regradar-agent[bot]")
    head_branch: str = Field(default="agent/s3-encryption-fix")
    base_branch: str = Field(default="main")
    is_agent_pr: bool = Field(default=True)
    status: str = Field(
        default="AWAITING_HUMAN_APPROVAL",
        description="AWAITING_HUMAN_APPROVAL, APPROVED, REJECTED, REVISION_REQUESTED, or AUTO_PASSED",
    )
    risk_tier: str = Field(default="LEAF_SAFE")
    invariant_verdict: str = Field(default="PASS")
    destructive_changes_count: int = Field(default=0)
    summary_markdown: str = Field(default="")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_comment: Optional[str] = None
    pr_url: Optional[str] = None
    evaluation: Optional[Dict[str, Any]] = None


def dispatch_github_pr_review(
    repo: str,
    pr_number: int,
    decision: str,
    reviewer: str,
    comment: Optional[str] = None,
    github_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Dispatches a formal Pull Request Review to the GitHub REST API.
    Zero external dependencies, using Python standard library urllib.
    """
    token = github_token or os.environ.get("GITHUB_TOKEN") or get_config().github.github_token
    if not token:
        logger.info(
            f"No GITHUB_TOKEN configured; skipping remote GitHub API dispatch for {repo}#{pr_number}."
        )
        return {"dispatched": False, "reason": "No GITHUB_TOKEN configured"}

    event = "APPROVE" if decision.upper() == "APPROVE" else "REQUEST_CHANGES"
    review_body = f"### RegRadar Zero-Destruction Gate Verdict: {decision.upper()}\n\n"
    review_body += f"- **Operator**: `{reviewer}`\n"
    review_body += f"- **Decision**: `{decision.upper()}`\n"
    if comment:
        review_body += f"- **Operator Notes**: {comment}\n"
    review_body += "\n*Audited by RegRadar Autonomous IaC Governance Engine.*"

    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "RegRadar-Governance-Gate",
        "Content-Type": "application/json",
    }
    payload_bytes = json.dumps({"event": event, "body": review_body}).encode("utf-8")

    req = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            logger.info(f"Successfully posted review to GitHub {repo}#{pr_number}: {data.get('html_url')}")
            return {"dispatched": True, "url": data.get("html_url"), "status_code": resp.status}
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        logger.warning(f"GitHub API review dispatch returned HTTP {e.code}: {err_msg}")
        return {"dispatched": False, "error": f"HTTP {e.code}: {err_msg}", "status_code": e.code}
    except Exception as e:
        logger.warning(f"Failed to dispatch review to GitHub: {e}")
        return {"dispatched": False, "error": str(e)}


def verify_github_signature(
    payload_bytes: bytes,
    signature_header: Optional[str],
    secret: str,
) -> bool:
    """
    Validates the GitHub HMAC SHA-256 signature (X-Hub-Signature-256).
    If secret is empty, verification passes in development mode.
    """
    if not secret:
        # Development mode without secret configured
        return True

    if not signature_header:
        return False

    prefix = "sha256="
    if not signature_header.startswith(prefix):
        return False

    received_sig = signature_header[len(prefix):]
    expected_sig = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload_bytes,
        digestmod=hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(received_sig, expected_sig)


class GitHubPRStore:
    """Production-grade persistent store for staged PRs requiring human operator review."""

    _instance: Optional["GitHubPRStore"] = None

    def __init__(self, persistence_file: Optional[Path] = None):
        self._prs: Dict[str, StagedPR] = {}
        self.persistence_file = persistence_file or self._resolve_persistence_file()
        self._load_from_disk()

    @classmethod
    def get_instance(cls) -> "GitHubPRStore":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @staticmethod
    def _resolve_persistence_file() -> Path:
        from regradar.config import get_config, resolve_workspace_root
        cfg = get_config()
        root = resolve_workspace_root(cfg.workspace.root)
        return root / ".regradar_staged_prs.json"

    def _load_from_disk(self) -> None:
        """Loads previously staged PRs from JSON persistence file if available."""
        if self.persistence_file and self.persistence_file.is_file():
            try:
                data = json.loads(self.persistence_file.read_text(encoding="utf-8"))
                for pr_dict in data:
                    pr = StagedPR(**pr_dict)
                    self._prs[pr.id] = pr
            except Exception as e:
                logger.warning(f"Failed to load staged PRs from {self.persistence_file}: {e}")

    def _save_to_disk(self) -> None:
        """Persists current staged PRs to JSON file."""
        if self.persistence_file:
            try:
                self.persistence_file.parent.mkdir(parents=True, exist_ok=True)
                data = [pr.model_dump() for pr in self._prs.values()]
                self.persistence_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except Exception as e:
                logger.warning(f"Failed to save staged PRs to {self.persistence_file}: {e}")

    def seed_demo_examples(self) -> None:
        """Seeds realistic staged PR examples on demand for demonstration or tests."""
        sample_agent_pr = StagedPR(
            id="pr-104",
            pr_number=104,
            repo="org/cloud-infra",
            title="[RegRadar Agent] Enable AWS S3 Bucket Encryption & Block Public Access",
            author="regradar-remediation-bot[bot]",
            head_branch="regradar/fix-s3-ckv-aws-19",
            base_branch="main",
            is_agent_pr=True,
            status="AWAITING_HUMAN_APPROVAL",
            risk_tier="LEAF_SAFE",
            invariant_verdict="PASS",
            destructive_changes_count=0,
            summary_markdown=(
                "### RegRadar Zero-Destruction PR Review\n\n"
                "- **Risk Tier**: `LEAF_SAFE` (Non-destructive patch)\n"
                "- **Invariant Verdict**: **PASS** (0 destructions, 0 replacements)\n"
                "- **Additions**: Added `aws_s3_bucket_server_side_encryption_configuration.enc`\n"
                "- **Gating**: Agent PR requires explicit operator sign-off before merge."
            ),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        sample_critical_pr = StagedPR(
            id="pr-105",
            pr_number=105,
            repo="org/cloud-infra",
            title="[RegRadar Agent] Update Core VPC CIDR & Subnet Segmentation",
            author="regradar-remediation-bot[bot]",
            head_branch="regradar/fix-vpc-centrality",
            base_branch="main",
            is_agent_pr=True,
            status="AWAITING_HUMAN_APPROVAL",
            risk_tier="CRITICAL_ROOT",
            invariant_verdict="PASS",
            destructive_changes_count=0,
            summary_markdown=(
                "### RegRadar Zero-Destruction PR Review\n\n"
                "- **Risk Tier**: `CRITICAL_ROOT` (High blast-radius centrality: S(v)=0.64)\n"
                "- **Invariant Verdict**: **PASS** (Zero destructions)\n"
                "- **Protected Resources**: `aws_vpc.core`, `aws_subnet.app`\n"
                "- **Human Intervention Mandatory**: Foundational blast-radius root modified."
            ),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._prs[sample_agent_pr.id] = sample_agent_pr
        self._prs[sample_critical_pr.id] = sample_critical_pr

    def list_prs(self) -> List[StagedPR]:
        return sorted(self._prs.values(), key=lambda p: p.created_at, reverse=True)

    def get_pr(self, pr_id: str) -> Optional[StagedPR]:
        return self._prs.get(pr_id)

    def stage_pr(self, pr: StagedPR) -> StagedPR:
        self._prs[pr.id] = pr
        self._save_to_disk()
        return pr

    def review_pr(
        self,
        pr_id: str,
        decision: str,
        reviewer: str = "operator",
        comment: Optional[str] = None,
    ) -> Optional[StagedPR]:
        pr = self._prs.get(pr_id)
        if not pr:
            return None

        decision_upper = decision.upper()
        if decision_upper == "APPROVE":
            pr.status = "APPROVED"
        elif decision_upper == "REJECT":
            pr.status = "REJECTED"
        elif decision_upper == "REVISE":
            pr.status = "REVISION_REQUESTED"

        pr.reviewed_by = reviewer
        pr.reviewed_at = datetime.now(timezone.utc).isoformat()
        pr.review_comment = comment

        # Dispatch real review to GitHub REST API if token configured
        remote_res = dispatch_github_pr_review(
            repo=pr.repo,
            pr_number=pr.pr_number,
            decision=decision_upper,
            reviewer=reviewer,
            comment=comment,
        )
        if pr.evaluation is not None:
            pr.evaluation["github_dispatch"] = remote_res

        self._save_to_disk()
        return pr

    def clear(self) -> None:
        self._prs.clear()
        if self.persistence_file and self.persistence_file.exists():
            try:
                self.persistence_file.unlink()
            except Exception:
                pass


class GitHubWebhookHandler:
    """Processes incoming GitHub webhooks, evaluates IaC invariants, and stages PRs."""

    def __init__(self, store: Optional[GitHubPRStore] = None):
        self.store = store or GitHubPRStore.get_instance()
        self.gatekeeper = PRGatekeeper()

    @staticmethod
    def is_agent_actor(author: str, labels: List[str] = None, title: str = "", body: str = "") -> bool:
        """Determines if a pull request was originated by an AI agent or automated bot."""
        author_lower = author.lower()
        if author_lower.endswith("[bot]") or "agent" in author_lower or "bot" in author_lower:
            return True
        if labels:
            for lbl in labels:
                if any(k in lbl.lower() for k in ["agent", "remediation", "bot", "ai"]):
                    return True
        title_lower = title.lower()
        if "[regradar" in title_lower or "remediation" in title_lower:
            return True
        body_lower = body.lower()
        if "generated by regradar" in body_lower or "ai agent" in body_lower:
            return True
        return False

    def handle_payload(
        self,
        event_type: str,
        payload: Dict[str, Any],
        raw_body: bytes,
        signature: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Main dispatcher for webhook events."""
        cfg = get_config()
        secret = cfg.github.webhook_secret

        if secret and not verify_github_signature(raw_body, signature, secret):
            return {
                "status": "error",
                "message": "Invalid HMAC SHA256 signature",
                "code": 401,
            }

        if event_type == "ping":
            return {
                "status": "success",
                "message": "Ping acknowledged",
                "zen": payload.get("zen", "Non-destructive IaC is resilient."),
                "hook_id": payload.get("hook_id"),
            }

        elif event_type == "pull_request":
            return self._handle_pull_request(payload)

        elif event_type == "push":
            return self._handle_push(payload)

        return {
            "status": "ignored",
            "message": f"Event type '{event_type}' not processed by RegRadar.",
        }

    def _handle_pull_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        action = payload.get("action", "opened")
        if action not in ("opened", "synchronize", "reopened", "labeled"):
            return {
                "status": "ignored",
                "message": f"PR action '{action}' does not trigger gating.",
            }

        pr_data = payload.get("pull_request", {})
        repo_data = payload.get("repository", {})
        repo_full = repo_data.get("full_name", "workspace/repo")
        pr_number = pr_data.get("number", 1)
        title = pr_data.get("title", f"Pull Request #{pr_number}")
        body = pr_data.get("body", "")
        author = pr_data.get("user", {}).get("login", "unknown")
        head_branch = pr_data.get("head", {}).get("ref", "feature-branch")
        base_branch = pr_data.get("base", {}).get("ref", "main")
        pr_url = pr_data.get("html_url")
        labels = [l.get("name", "") for l in pr_data.get("labels", [])]

        is_agent = self.is_agent_actor(author=author, labels=labels, title=title, body=body)

        cfg = get_config()
        target_dir = cfg.workspace.root

        # Evaluate through PRGatekeeper
        evaluation: PRGateEvaluation = self.gatekeeper.evaluate(
            target_dir=target_dir,
            simulate_sandbox=False,
            synthesize_patches=False,
        )

        risk_tier = RiskTier.LEAF_SAFE.value
        if evaluation.blast_radius_summary and evaluation.blast_radius_summary.root_resources:
            risk_tier = RiskTier.CRITICAL_ROOT.value

        # Human intervention rule:
        # Agent PRs ALWAYS require operator sign-off when require_human_signoff is True.
        # CRITICAL_ROOT changes always require operator sign-off.
        requires_human = (
            cfg.github.require_human_signoff
            and (is_agent or risk_tier in (RiskTier.CRITICAL_ROOT.value, RiskTier.INTERMEDIATE.value))
        )

        status = "AWAITING_HUMAN_APPROVAL" if requires_human else "AUTO_PASSED"

        pr_id = f"pr-{pr_number}"
        staged = StagedPR(
            id=pr_id,
            pr_number=pr_number,
            repo=repo_full,
            title=title,
            author=author,
            head_branch=head_branch,
            base_branch=base_branch,
            is_agent_pr=is_agent,
            status=status,
            risk_tier=risk_tier,
            invariant_verdict=evaluation.invariant_verdict,
            destructive_changes_count=len(evaluation.destructive_changes),
            summary_markdown=evaluation.summary_markdown,
            pr_url=pr_url,
            evaluation=evaluation.model_dump(),
        )

        self.store.stage_pr(staged)

        logger.info(
            f"Staged PR #{pr_number} from {author} (Agent={is_agent}, Risk={risk_tier}, Status={status})"
        )

        return {
            "status": "success",
            "action": "staged",
            "pr": staged.model_dump(),
            "requires_human_signoff": requires_human,
        }

    def _handle_push(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ref = payload.get("ref", "")
        repo = payload.get("repository", {}).get("full_name", "workspace/repo")
        commits = payload.get("commits", [])
        return {
            "status": "success",
            "action": "push_audited",
            "repo": repo,
            "ref": ref,
            "commits_count": len(commits),
        }

    def simulate_event(
        self,
        repo: str = "org/cloud-infra",
        title: str = "[RegRadar Agent] Remediate S3 Bucket Logging",
        author: str = "regradar-remediation-bot[bot]",
        head_branch: str = "agent/fix-s3-logging",
        risk_tier: str = "LEAF_SAFE",
        is_agent: bool = True,
        changes_count: int = 0,
    ) -> StagedPR:
        """Simulates an incoming pull request webhook without requiring external network connectivity."""
        pr_number = len(self.store.list_prs()) + 101
        pr_id = f"pr-{pr_number}"

        markdown = (
            f"### RegRadar Zero-Destruction PR Review (Simulated)\n\n"
            f"- **Repository**: `{repo}`\n"
            f"- **Author**: `{author}` {'(AI Remediation Agent)' if is_agent else '(Human)'}\n"
            f"- **Risk Tier**: `{risk_tier}`\n"
            f"- **Invariant Verdict**: **PASS** ({changes_count} destructions detected)\n"
            f"- **Human Intervention**: {'Required - Awaiting Operator Approval' if is_agent or risk_tier == 'CRITICAL_ROOT' else 'Auto-Passed'}\n"
        )

        cfg = get_config()
        requires_human = cfg.github.require_human_signoff and (
            is_agent or risk_tier in (RiskTier.CRITICAL_ROOT.value, RiskTier.INTERMEDIATE.value)
        )
        status = "AWAITING_HUMAN_APPROVAL" if requires_human else "AUTO_PASSED"

        staged = StagedPR(
            id=pr_id,
            pr_number=pr_number,
            repo=repo,
            title=title,
            author=author,
            head_branch=head_branch,
            base_branch="main",
            is_agent_pr=is_agent,
            status=status,
            risk_tier=risk_tier,
            invariant_verdict="PASS",
            destructive_changes_count=changes_count,
            summary_markdown=markdown,
            pr_url=f"https://github.com/{repo}/pull/{pr_number}",
        )

        self.store.stage_pr(staged)
        return staged
