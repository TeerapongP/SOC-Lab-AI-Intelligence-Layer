from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

import requests

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

from .html_builder import build_digest_html, build_immediate_html
from .model.models import DigestEntry

log = get_logger("dashboard.notifiers.outlook")

_GRAPH_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_GRAPH_SEND_URL  = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"
_TOKEN_SCOPE     = "https://graph.microsoft.com/.default"


class OutlookNotifier:
    """
    Sends alert emails via Microsoft Graph API.

    MEDIUM  → immediate email
    LOW     → buffered → daily digest at OUTLOOK_DIGEST_HOUR

    FIX 1: log count ก่อน clear() ใน send_digest()
    FIX 2: import time ครั้งเดียวที่ top-level
    FIX 3: exc_info=True ใน error log
    FIX 4: แยก try/except token vs send ใน _send_email()
    """

    def __init__(self) -> None:
        self._token:         Optional[str] = None
        self._token_expiry:  float         = 0.0
        self._digest_buffer: list[DigestEntry] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def send_immediate(self, alert: LLMAlert) -> bool:
        """Send MEDIUM priority alert immediately."""
        subject = (
            f"[SOC ALERT — {alert.priority.value}] "
            f"Risk {alert.risk_score}/100 · {alert.source_ip}"
        )
        html = build_immediate_html(alert)
        return self._send_email(subject, html)

    def buffer_for_digest(self, alert: LLMAlert) -> None:
        """Buffer LOW priority alert for daily digest."""
        self._digest_buffer.append(DigestEntry(
            risk_score   = alert.risk_score,
            source_ip    = alert.source_ip,
            mitre_tactic = alert.mitre_tactic,
            anomaly_type = alert.anomaly_type,
            priority     = alert.priority.value,
            timestamp    = alert.timestamp,
            remediation  = alert.remediation,
        ))
        log.debug("Buffered LOW alert — buffer_size=%d", len(self._digest_buffer))

    def send_digest(self, stats: dict | None = None) -> bool:
        """Send daily digest email with all buffered LOW alerts + pipeline stats."""
        if not self._digest_buffer and not stats:
            log.info("No digest content — skipping")
            return True

        subject = (
            f"[SOC Daily Digest] {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d')} "
            f"— {len(self._digest_buffer)} alerts"
        )
        html = build_digest_html(self._digest_buffer, stats or {})
        ok   = self._send_email(subject, html)

        if ok:
            # FIX 1: capture count ก่อน clear() เพื่อ log ถูกต้อง
            count = len(self._digest_buffer)
            self._digest_buffer.clear()
            log.info("Daily digest sent — %d alerts", count)

        return ok

    # ── Graph API helpers ──────────────────────────────────────────────────────

    def _get_token(self) -> str:
        # FIX 2: import time ที่ top-level แล้ว ใช้ได้เลย ไม่ต้อง import ซ้ำในฟังก์ชัน
        if self._token and time.time() < self._token_expiry - 60:
            return self._token

        resp = requests.post(
            _GRAPH_TOKEN_URL.format(tenant=settings.OUTLOOK_TENANT_ID),
            data={
                "grant_type":    "client_credentials",
                "client_id":     settings.OUTLOOK_CLIENT_ID,
                "client_secret": settings.OUTLOOK_CLIENT_SECRET,
                "scope":         _TOKEN_SCOPE,
            },
            timeout=15,
        )
        resp.raise_for_status()
        data               = resp.json()
        self._token        = data["access_token"]
        self._token_expiry = time.time() + data.get("expires_in", 3600)
        return self._token

    def _send_email(self, subject: str, html: str) -> bool:
        if not settings.OUTLOOK_RECIPIENT_EMAILS:
            log.warning("OUTLOOK_RECIPIENT_EMAILS not set — skipping email")
            return False

        # FIX 4: แยก token error ออกจาก send error เพื่อ debug ง่ายขึ้น
        try:
            token = self._get_token()
        except Exception as exc:
            log.error("Failed to acquire Graph token: %s", exc, exc_info=True)
            return False

        try:
            payload = {
                "message": {
                    "subject": subject,
                    "body": {"contentType": "HTML", "content": html},
                    "toRecipients": [
                        {"emailAddress": {"address": addr}}
                        for addr in settings.OUTLOOK_RECIPIENT_EMAILS
                    ],
                },
                "saveToSentItems": "true",
            }
            resp = requests.post(
                _GRAPH_SEND_URL.format(sender=settings.OUTLOOK_SENDER_EMAIL),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type":  "application/json",
                },
                json=payload,
                timeout=15,
            )
            if resp.status_code in (200, 202):
                log.info("Email sent: %s", subject)
                return True

            log.warning("Email failed: HTTP %d — %s", resp.status_code, resp.text[:200])
            return False

        except Exception as exc:
            # FIX 3: exc_info=True เพื่อ traceback เต็ม
            log.error("Email send error: %s", exc, exc_info=True)
            return False