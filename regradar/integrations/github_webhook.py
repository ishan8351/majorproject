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
    """Pull request or Merge request held in the RegRadar Governance staging queue."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    provider: str = Field(default="github", description="'github' or 'gitlab'")
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
    """Production-grade persistent store for staged PRs backed by SQLite Governance DB."""

    _instance: Optional["GitHubPRStore"] = None

    def __init__(self, persistence_file: Optional[Path] = None):
        from regradar.storage.db import get_governance_db
        self.db = get_governance_db()
        self.persistence_file = persistence_file

    @classmethod
    def get_instance(cls) -> "GitHubPRStore":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def list_prs(self) -> List[StagedPR]:
        rows = self.db.list_prs()
        return [StagedPR(**r) for r in rows]

    def get_pr(self, pr_id: str) -> Optional[StagedPR]:
        item = self.db.get_pr(pr_id)
        return StagedPR(**item) if item else None

    def stage_pr(self, pr: StagedPR) -> StagedPR:
        saved_dict = self.db.upsert_pr(pr.model_dump())
        saved_pr = StagedPR(**saved_dict)
        try:
            from regradar.integrations.dispatcher import WebhookDispatcher
            WebhookDispatcher.dispatch_event("pr.staged", saved_pr.model_dump())
        except Exception as e:
            logger.warning("Failed to dispatch pr.staged webhook event: %s", e)
        return saved_pr

    def review_pr(
        self,
        pr_id: str,
        decision: str,
        reviewer: str = "operator",
        comment: Optional[str] = None,
    ) -> Optional[StagedPR]:
        existing = self.get_pr(pr_id)
        if not existing:
            return None

        decision_upper = decision.upper()

        # Dispatch real review to GitHub REST API if token configured
        remote_res = dispatch_github_pr_review(
            repo=existing.repo,
            pr_number=existing.pr_number,
            decision=decision_upper,
            reviewer=reviewer,
            comment=comment,
        )

        updated_dict = self.db.update_pr_decision(
            pr_id=pr_id,
            decision=decision_upper,
            reviewer=reviewer,
            comment=comment,
            remote_dispatch=remote_res,
        )

        if updated_dict:
            updated_pr = StagedPR(**updated_dict)
            try:
                from regradar.integrations.dispatcher import WebhookDispatcher
                WebhookDispatcher.dispatch_event("pr.reviewed", {
                    "pr_id": pr_id,
                    "repo": updated_pr.repo,
                    "pr_number": updated_pr.pr_number,
                    "decision": decision_upper,
                    "reviewer": reviewer,
                    "comment": comment,
                    "status": updated_pr.status,
                    "remote_dispatch": remote_res,
                })
            except Exception as e:
                logger.warning("Failed to dispatch pr.reviewed webhook event: %s", e)
            return updated_pr

        return None

    def clear(self) -> None:
        self.db.clear_prs()



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
            provider="github",
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
            provider="github",
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
