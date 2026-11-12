"""
RegRadar Relational Governance Database (SQLite Engine).
Provides ACID-compliant persistence for staged pull requests, operator reviews,
policy audits, and outgoing webhook dispatch logs.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional
import uuid

from regradar.config import get_config, resolve_workspace_root

logger = logging.getLogger("regradar.storage.db")


class GovernanceDatabase:
    """Thread-safe SQLite database manager for RegRadar governance persistence."""

    _instance: Optional["GovernanceDatabase"] = None
    _init_lock = threading.Lock()

    def __init__(self, db_path: Optional[Path] = None):
        self._lock = threading.RLock()
        self.db_path = db_path or self._resolve_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @classmethod
    def get_instance(cls, db_path: Optional[Path] = None) -> "GovernanceDatabase":
        with cls._init_lock:
            if cls._instance is None:
                cls._instance = cls(db_path=db_path)
            return cls._instance

    @classmethod
    def set_instance(cls, instance: Optional["GovernanceDatabase"]) -> None:
        with cls._init_lock:
            cls._instance = instance

    @staticmethod
    def _resolve_db_path() -> Path:
        env_path = os.environ.get("REGRADAR_DB_PATH")
        if env_path:
            return Path(env_path).resolve()
        cfg = get_config()
        root = resolve_workspace_root(cfg.workspace.root)
        return root / ".regradar_governance.db"

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
            isolation_level=None,  # autocommit mode
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS staged_prs (
                        id TEXT PRIMARY KEY,
                        provider TEXT NOT NULL DEFAULT 'github',
                        pr_number INTEGER NOT NULL,
                        repo TEXT NOT NULL,
                        title TEXT NOT NULL,
                        author TEXT NOT NULL,
                        head_branch TEXT NOT NULL,
                        base_branch TEXT NOT NULL,
                        is_agent_pr INTEGER NOT NULL DEFAULT 1,
                        status TEXT NOT NULL,
                        risk_tier TEXT NOT NULL,
                        invariant_verdict TEXT NOT NULL,
                        destructive_changes_count INTEGER NOT NULL DEFAULT 0,
                        summary_markdown TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL,
                        reviewed_by TEXT,
                        reviewed_at TEXT,
                        review_comment TEXT,
                        pr_url TEXT,
                        evaluation_json TEXT
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS connected_repositories (
                        id TEXT PRIMARY KEY,
                        provider TEXT NOT NULL,
                        repo_name TEXT NOT NULL UNIQUE,
                        default_branch TEXT NOT NULL DEFAULT 'main',
                        clone_url TEXT NOT NULL DEFAULT '',
                        resource_count INTEGER NOT NULL DEFAULT 0,
                        framework TEXT NOT NULL DEFAULT 'Remote Git Repository',
                        created_at TEXT NOT NULL
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS staged_reviews (
                        id TEXT PRIMARY KEY,
                        workspace_path TEXT NOT NULL,
                        resource_id TEXT NOT NULL,
                        check_id TEXT NOT NULL,
                        check_name TEXT NOT NULL,
                        frameworks_json TEXT NOT NULL DEFAULT '[]',
                        statute TEXT NOT NULL DEFAULT '',
                        risk_tier TEXT NOT NULL,
                        blast_radius_score REAL NOT NULL DEFAULT 0.0,
                        descendant_count INTEGER NOT NULL DEFAULT 0,
                        ancestor_count INTEGER NOT NULL DEFAULT 0,
                        betweenness REAL NOT NULL DEFAULT 0.0,
                        eigenvector REAL NOT NULL DEFAULT 0.0,
                        pagerank REAL NOT NULL DEFAULT 0.0,
                        gating_status TEXT NOT NULL,
                        strategy TEXT NOT NULL,
                        target_file TEXT NOT NULL,
                        original_snippet TEXT NOT NULL DEFAULT '',
                        patch_snippet TEXT NOT NULL DEFAULT '',
                        is_verified INTEGER NOT NULL DEFAULT 0,
                        requires_human INTEGER NOT NULL DEFAULT 1,
                        verification_message TEXT NOT NULL DEFAULT '',
                        decision TEXT NOT NULL DEFAULT 'PENDING',
                        decision_by TEXT,
                        decision_at TEXT,
                        applied INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS webhook_dispatch_logs (
                        id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        target_url TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        status_code INTEGER NOT NULL,
                        success INTEGER NOT NULL,
                        error_message TEXT,
                        dispatched_at TEXT NOT NULL
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS webhook_subscriptions (
                        id TEXT PRIMARY KEY,
                        url TEXT NOT NULL,
                        secret TEXT NOT NULL DEFAULT '',
                        event_filters_json TEXT NOT NULL DEFAULT '["*"]',
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL
                    );
                """)

                conn.execute("CREATE INDEX IF NOT EXISTS idx_staged_prs_status ON staged_prs(status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_staged_prs_created ON staged_prs(created_at);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_staged_prs_provider ON staged_prs(provider);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_workspace ON staged_reviews(workspace_path);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_resource ON staged_reviews(resource_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_dispatch_logs_event ON webhook_dispatch_logs(event_type);")

    # -------------------------------------------------------------------------
    # Connected Remote Repositories Methods
    # -------------------------------------------------------------------------

    def register_repository(
        self,
        provider: str,
        repo_name: str,
        default_branch: str = "main",
        clone_url: str = "",
        resource_count: int = 0,
        framework: str = "Remote Git Repository",
    ) -> Dict[str, Any]:
        with self._lock:
            with self._get_connection() as conn:
                repo_id = f"{provider}:{repo_name}".lower().replace("/", "-")
                now = datetime.now(timezone.utc).isoformat()
                conn.execute("""
                    INSERT INTO connected_repositories (
                        id, provider, repo_name, default_branch, clone_url, resource_count, framework, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repo_name) DO UPDATE SET
                        default_branch = excluded.default_branch,
                        clone_url = excluded.clone_url,
                        resource_count = excluded.resource_count,
                        framework = excluded.framework;
                """, (
                    repo_id,
                    provider.lower(),
                    repo_name,
                    default_branch,
                    clone_url,
                    resource_count,
                    framework,
                    now,
                ))
                return self.get_repository(repo_name) or {}

    def list_connected_repositories(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM connected_repositories ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def get_repository(self, repo_name: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM connected_repositories WHERE repo_name = ? OR id = ?", (repo_name, repo_name)).fetchone()
            return dict(row) if row else None

    def delete_repository(self, repo_identifier: str) -> bool:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "DELETE FROM connected_repositories WHERE id = ? OR repo_name = ?",
                    (repo_identifier, repo_identifier),
                )
                return cur.rowcount > 0

    # -------------------------------------------------------------------------
    # Pull Request / Merge Request Staging Methods
    # -------------------------------------------------------------------------

    def upsert_pr(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            with self._get_connection() as conn:
                pr_id = pr_data.get("id") or str(uuid.uuid4())[:8]
                provider = pr_data.get("provider") or ("gitlab" if "gitlab" in str(pr_data.get("repo", "")).lower() or "gitlab" in str(pr_data.get("pr_url", "")).lower() else "github")
                repo_name = str(pr_data.get("repo", "org/infra"))

                eval_json = pr_data.get("evaluation")
                if isinstance(eval_json, (dict, list)):
                    eval_json_str = json.dumps(eval_json)
                else:
                    eval_json_str = str(eval_json or "")

                conn.execute("""
                    INSERT INTO staged_prs (
                        id, provider, pr_number, repo, title, author, head_branch, base_branch,
                        is_agent_pr, status, risk_tier, invariant_verdict,
                        destructive_changes_count, summary_markdown, created_at,
                        reviewed_by, reviewed_at, review_comment, pr_url, evaluation_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        status = excluded.status,
                        reviewed_by = excluded.reviewed_by,
                        reviewed_at = excluded.reviewed_at,
                        review_comment = excluded.review_comment,
                        evaluation_json = excluded.evaluation_json;
                """, (
                    pr_id,
                    provider,
                    int(pr_data.get("pr_number", 1)),
                    repo_name,
                    str(pr_data.get("title", "IaC Remediation")),
                    str(pr_data.get("author", "regradar-agent[bot]")),
                    str(pr_data.get("head_branch", "regradar/fix")),
                    str(pr_data.get("base_branch", "main")),
                    1 if pr_data.get("is_agent_pr", True) else 0,
                    str(pr_data.get("status", "AWAITING_HUMAN_APPROVAL")),
                    str(pr_data.get("risk_tier", "LEAF_SAFE")),
                    str(pr_data.get("invariant_verdict", "PASS")),
                    int(pr_data.get("destructive_changes_count", 0)),
                    str(pr_data.get("summary_markdown", "")),
                    str(pr_data.get("created_at") or datetime.now(timezone.utc).isoformat()),
                    pr_data.get("reviewed_by"),
                    pr_data.get("reviewed_at"),
                    pr_data.get("review_comment"),
                    pr_data.get("pr_url"),
                    eval_json_str,
                ))

                # Also automatically record connected repository
                self.register_repository(
                    provider=provider,
                    repo_name=repo_name,
                    default_branch=str(pr_data.get("base_branch", "main")),
                    clone_url=str(pr_data.get("pr_url", "")),
                )

                return self.get_pr(pr_id) or pr_data

    def get_pr(self, pr_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM staged_prs WHERE id = ?", (pr_id,)).fetchone()
            if not row:
                return None
            return self._row_to_pr_dict(row)

    def list_prs(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM staged_prs ORDER BY created_at DESC").fetchall()
            return [self._row_to_pr_dict(r) for r in rows]

    def update_pr_decision(
        self,
        pr_id: str,
        decision: str,
        reviewer: str = "operator",
        comment: Optional[str] = None,
        remote_dispatch: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            existing = self.get_pr(pr_id)
            if not existing:
                return None

            status_map = {
                "APPROVE": "APPROVED",
                "REJECT": "REJECTED",
                "REVISE": "REVISION_REQUESTED",
            }
            new_status = status_map.get(decision.upper(), "APPROVED")
            reviewed_at = datetime.now(timezone.utc).isoformat()

            eval_dict = existing.get("evaluation") or {}
            if remote_dispatch:
                eval_dict["github_dispatch"] = remote_dispatch

            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE staged_prs
                    SET status = ?, reviewed_by = ?, reviewed_at = ?, review_comment = ?, evaluation_json = ?
                    WHERE id = ?
                """, (
                    new_status,
                    reviewer,
                    reviewed_at,
                    comment,
                    json.dumps(eval_dict),
                    pr_id,
                ))

            return self.get_pr(pr_id)

    def delete_pr(self, pr_id: str) -> bool:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute("DELETE FROM staged_prs WHERE id = ?", (pr_id,))
                return cur.rowcount > 0

    def clear_prs(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM staged_prs;")

    def _row_to_pr_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        data["is_agent_pr"] = bool(data["is_agent_pr"])
        eval_str = data.get("evaluation_json")
        if eval_str:
            try:
                data["evaluation"] = json.loads(eval_str)
            except Exception:
                data["evaluation"] = None
        else:
            data["evaluation"] = None
        data.pop("evaluation_json", None)
        return data

    # -------------------------------------------------------------------------
    # Staged Review Decisions Persistence
    # -------------------------------------------------------------------------

    def save_staged_reviews(self, workspace_path: str, items: List[Dict[str, Any]]) -> None:
        """Persists evaluated violation patches for operator inspection."""
        with self._lock:
            with self._get_connection() as conn:
                now = datetime.now(timezone.utc).isoformat()
                for it in items:
                    res_id = it.get("resource_id", "")
                    chk_id = it.get("check_id", "")
                    review_id = f"{workspace_path}:{res_id}:{chk_id}"

                    frameworks = it.get("frameworks") or []
                    fw_json = json.dumps(frameworks) if isinstance(frameworks, list) else "[]"

                    conn.execute("""
                        INSERT INTO staged_reviews (
                            id, workspace_path, resource_id, check_id, check_name,
                            frameworks_json, statute, risk_tier, blast_radius_score,
                            descendant_count, ancestor_count, betweenness, eigenvector,
                            pagerank, gating_status, strategy, target_file,
                            original_snippet, patch_snippet, is_verified, requires_human,
                            verification_message, decision, decision_by, decision_at, applied, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            patch_snippet = excluded.patch_snippet,
                            is_verified = excluded.is_verified,
                            verification_message = excluded.verification_message,
                            decision = excluded.decision;
                    """, (
                        review_id,
                        workspace_path,
                        res_id,
                        chk_id,
                        str(it.get("check_name", "")),
                        fw_json,
                        str(it.get("statute", "")),
                        str(it.get("risk_tier", "LEAF_SAFE")),
                        float(it.get("blast_radius_score", 0.0)),
                        int(it.get("descendant_count", 0)),
                        int(it.get("ancestor_count", 0)),
                        float(it.get("betweenness", 0.0)),
                        float(it.get("eigenvector", 0.0)),
                        float(it.get("pagerank", 0.0)),
                        str(it.get("gating_status", "")),
                        str(it.get("strategy", "")),
                        str(it.get("target_file", "")),
                        str(it.get("original_snippet", "")),
                        str(it.get("patch_snippet", "")),
                        1 if it.get("is_verified") else 0,
                        1 if it.get("requires_human") else 0,
                        str(it.get("verification_message", "")),
                        str(it.get("decision", "PENDING")),
                        it.get("decision_by"),
                        it.get("decision_at"),
                        1 if it.get("applied") else 0,
                        now,
                    ))

    def list_staged_reviews(self, workspace_path: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            if workspace_path:
                rows = conn.execute(
                    "SELECT * FROM staged_reviews WHERE workspace_path = ? ORDER BY created_at DESC",
                    (workspace_path,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM staged_reviews ORDER BY created_at DESC").fetchall()

            results = []
            for r in rows:
                item = dict(r)
                item["is_verified"] = bool(item["is_verified"])
                item["requires_human"] = bool(item["requires_human"])
                item["applied"] = bool(item["applied"])
                try:
                    item["frameworks"] = json.loads(item.get("frameworks_json", "[]"))
                except Exception:
                    item["frameworks"] = []
                item.pop("frameworks_json", None)
                results.append(item)
            return results

    def record_review_decision(
        self,
        workspace_path: str,
        resource_id: str,
        check_id: str,
        decision: str,
        applied: bool = False,
        reviewer: str = "operator",
    ) -> bool:
        with self._lock:
            with self._get_connection() as conn:
                now = datetime.now(timezone.utc).isoformat()
                cur = conn.execute("""
                    UPDATE staged_reviews
                    SET decision = ?, decision_by = ?, decision_at = ?, applied = ?
                    WHERE workspace_path = ? AND resource_id = ? AND check_id = ?
                """, (
                    decision.upper(),
                    reviewer,
                    now,
                    1 if applied else 0,
                    workspace_path,
                    resource_id,
                    check_id,
                ))
                return cur.rowcount > 0

    # -------------------------------------------------------------------------
    # Webhook Dispatch Logging & Subscriptions
    # -------------------------------------------------------------------------

    def log_webhook_dispatch(
        self,
        event_type: str,
        target_url: str,
        payload: Dict[str, Any],
        status_code: int,
        success: bool,
        error_message: Optional[str] = None,
    ) -> str:
        with self._lock:
            dispatch_id = str(uuid.uuid4())[:8]
            now = datetime.now(timezone.utc).isoformat()
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO webhook_dispatch_logs (
                        id, event_type, target_url, payload_json, status_code,
                        success, error_message, dispatched_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    dispatch_id,
                    event_type,
                    target_url,
                    json.dumps(payload),
                    status_code,
                    1 if success else 0,
                    error_message,
                    now,
                ))
            return dispatch_id

    def list_webhook_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM webhook_dispatch_logs ORDER BY dispatched_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            out = []
            for r in rows:
                item = dict(r)
                item["success"] = bool(item["success"])
                try:
                    item["payload"] = json.loads(item.get("payload_json", "{}"))
                except Exception:
                    item["payload"] = {}
                item.pop("payload_json", None)
                out.append(item)
            return out

    def get_subscriptions(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM webhook_subscriptions WHERE is_active = 1").fetchall()
            subs = []
            for r in rows:
                item = dict(r)
                try:
                    item["events"] = json.loads(item.get("event_filters_json", "[]"))
                except Exception:
                    item["events"] = ["*"]
                subs.append(item)
            return subs

    def add_subscription(self, url: str, secret: str = "", events: Optional[List[str]] = None) -> str:
        with self._lock:
            sub_id = str(uuid.uuid4())[:8]
            now = datetime.now(timezone.utc).isoformat()
            events_json = json.dumps(events or ["*"])
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO webhook_subscriptions (id, url, secret, event_filters_json, is_active, created_at)
                    VALUES (?, ?, ?, ?, 1, ?);
                """, (sub_id, url, secret, events_json, now))
            return sub_id

    # -------------------------------------------------------------------------
    # Operational Diagnostics & Stats
    # -------------------------------------------------------------------------

    def get_database_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            pr_count = conn.execute("SELECT COUNT(*) FROM staged_prs").fetchone()[0]
            pr_awaiting = conn.execute(
                "SELECT COUNT(*) FROM staged_prs WHERE status = 'AWAITING_HUMAN_APPROVAL'"
            ).fetchone()[0]
            reviews_count = conn.execute("SELECT COUNT(*) FROM staged_reviews").fetchone()[0]
            logs_count = conn.execute("SELECT COUNT(*) FROM webhook_dispatch_logs").fetchone()[0]
            subs_count = conn.execute("SELECT COUNT(*) FROM webhook_subscriptions WHERE is_active = 1").fetchone()[0]

            size_bytes = 0
            if self.db_path.exists():
                size_bytes = self.db_path.stat().st_size

            return {
                "db_engine": "SQLite 3",
                "db_path": str(self.db_path),
                "db_size_bytes": size_bytes,
                "journal_mode": "WAL",
                "tables": {
                    "staged_prs": {
                        "total": pr_count,
                        "awaiting_human_approval": pr_awaiting,
                    },
                    "staged_reviews": {
                        "total": reviews_count,
                    },
                    "webhook_dispatch_logs": {
                        "total": logs_count,
                    },
                    "webhook_subscriptions": {
                        "total": subs_count,
                    },
                },
            }


def get_governance_db() -> GovernanceDatabase:
    return GovernanceDatabase.get_instance()


def set_governance_db(db: Optional[GovernanceDatabase]) -> None:
    GovernanceDatabase.set_instance(db)
