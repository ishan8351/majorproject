"""
RegRadar Live Webhook Dispatcher & Notification Hub.
Dispatches enterprise webhook payloads to external alerting systems, SIEMs,
Slack/Teams connectors, or downstream CI/CD pipelines with HMAC SHA-256 signatures.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request

from regradar.storage.db import get_governance_db

logger = logging.getLogger("regradar.integrations.dispatcher")


class WebhookDispatcher:
    """Dispatches governance event notifications with delivery tracking and audit logs."""

    @classmethod
    def dispatch_event(
        cls,
        event_type: str,
        payload: Dict[str, Any],
        secret: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Dispatches an event payload to all active webhook subscribers and
        the default configured notification webhook endpoint (if present).
        """
        db = get_governance_db()
        results: List[Dict[str, Any]] = []

        targets: List[Dict[str, Any]] = []

        # 1. Check environment notification URL (e.g. Slack / Teams / Corporate SIEM)
        env_url = os.environ.get("REGRADAR_WEBHOOK_NOTIFY_URL") or os.environ.get("REGRADAR_SLACK_WEBHOOK_URL")
        env_secret = secret or os.environ.get("REGRADAR_WEBHOOK_SECRET", "")
        if env_url:
            targets.append({
                "url": env_url,
                "secret": env_secret,
                "events": ["*"],
            })

        # 2. Check registered subscriptions in the governance database
        subscriptions = db.get_subscriptions()
        for sub in subscriptions:
            events = sub.get("events", ["*"])
            if "*" in events or event_type in events:
                targets.append({
                    "url": sub["url"],
                    "secret": sub.get("secret") or env_secret,
                    "events": events,
                })

        if not targets:
            logger.debug("No webhook notification targets configured for event: %s", event_type)
            return results

        timestamp = datetime.now(timezone.utc).isoformat()
        envelope = {
            "event": event_type,
            "timestamp": timestamp,
            "source": "regradar-governance-engine",
            "data": payload,
        }
        body_bytes = json.dumps(envelope).encode("utf-8")

        for target in targets:
            url = target["url"]
            target_secret = target.get("secret", "")

            headers = {
                "Content-Type": "application/json",
                "User-Agent": "RegRadar-Webhook-Dispatcher/2.0",
                "X-RegRadar-Event": event_type,
                "X-RegRadar-Timestamp": timestamp,
            }

            if target_secret:
                sig = hmac.new(
                    key=target_secret.encode("utf-8"),
                    msg=body_bytes,
                    digestmod=hashlib.sha256,
                ).hexdigest()
                headers["X-RegRadar-Signature-256"] = f"sha256={sig}"

            req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
            status_code = 0
            success = False
            err_msg: Optional[str] = None

            try:
                with urllib.request.urlopen(req, timeout=8) as resp:
                    status_code = resp.status
                    success = (200 <= status_code < 300)
            except urllib.error.HTTPError as e:
                status_code = e.code
                err_msg = f"HTTP {e.code}: {e.reason}"
            except Exception as e:
                status_code = 0
                err_msg = str(e)

            log_id = db.log_webhook_dispatch(
                event_type=event_type,
                target_url=url,
                payload=envelope,
                status_code=status_code,
                success=success,
                error_message=err_msg,
            )

            results.append({
                "log_id": log_id,
                "target_url": url,
                "event_type": event_type,
                "status_code": status_code,
                "success": success,
                "error": err_msg,
            })

        return results

    @classmethod
    def test_dispatch(cls, target_url: str, secret: str = "") -> Dict[str, Any]:
        """Sends a verification ping to validate an endpoint."""
        db = get_governance_db()
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "event": "ping.test",
            "timestamp": timestamp,
            "message": "RegRadar Governance Webhook Verification Ping",
            "status": "HEALTHY",
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "RegRadar-Webhook-Dispatcher/2.0",
            "X-RegRadar-Event": "ping.test",
            "X-RegRadar-Timestamp": timestamp,
        }
        if secret:
            sig = hmac.new(
                key=secret.encode("utf-8"),
                msg=body_bytes,
                digestmod=hashlib.sha256,
            ).hexdigest()
            headers["X-RegRadar-Signature-256"] = f"sha256={sig}"

        req = urllib.request.Request(target_url, data=body_bytes, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                success = (200 <= resp.status < 300)
                db.log_webhook_dispatch("ping.test", target_url, payload, resp.status, success)
                return {"success": success, "status_code": resp.status, "message": "Endpoint verified successfully."}
        except urllib.error.HTTPError as e:
            db.log_webhook_dispatch("ping.test", target_url, payload, e.code, False, str(e.reason))
            return {"success": False, "status_code": e.code, "message": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            db.log_webhook_dispatch("ping.test", target_url, payload, 0, False, str(e))
            return {"success": False, "status_code": 0, "message": str(e)}
