from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

from notification.config import settings
from notification.models.alert import LLMAlert, Priority
from notification.logging_utils import get_logger

log = get_logger("dashboard.notifiers.outlook")

_GRAPH_TOKEN_URL  = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_GRAPH_SEND_URL   = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"
_TOKEN_SCOPE      = "https://graph.microsoft.com/.default"


@dataclass
class DigestEntry:
    """Single alert entry buffered for daily digest."""
    risk_score:    int
    source_ip:     str
    mitre_tactic:  str
    anomaly_type:  str
    priority:      str
    timestamp:     str
    remediation:   list[str] = field(default_factory=list)


class OutlookNotifier:
    """
    Sends alert emails via Microsoft Graph API.

    MEDIUM  → immediate email
    LOW     → buffered → daily digest at OUTLOOK_DIGEST_HOUR
    """

    def __init__(self) -> None:
        self._token:       Optional[str] = None
        self._token_expiry: float        = 0.0
        self._digest_buffer: list[DigestEntry] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def send_immediate(self, alert: LLMAlert) -> bool:
        """Send MEDIUM priority alert immediately."""
        subject = f"[SOC ALERT — {alert.priority.value}] Risk {alert.risk_score}/100 · {alert.source_ip}"
        html    = self._build_immediate_html(alert)
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
        log.debug("Buffered LOW alert for digest — buffer_size=%d", len(self._digest_buffer))

    def send_digest(self, stats: dict | None = None) -> bool:
        """Send daily digest email with all buffered LOW alerts + pipeline stats."""
        if not self._digest_buffer and not stats:
            log.info("No digest content — skipping")
            return True

        subject = (
            f"[SOC Daily Digest] {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d')} "
            f"— {len(self._digest_buffer)} alerts"
        )
        html = self._build_digest_html(self._digest_buffer, stats or {})
        ok   = self._send_email(subject, html)
        if ok:
            self._digest_buffer.clear()
            log.info("Daily digest sent — %d alerts", len(self._digest_buffer))
        return ok

    # ── Email builder ─────────────────────────────────────────────────────────

    def _build_immediate_html(self, alert: LLMAlert) -> str:
        steps_html = "".join(f"<li>{s}</li>" for s in alert.remediation)
        features   = ", ".join(alert.top_3_features)
        return f"""
        <html><body style="font-family:Arial,sans-serif;color:#222;">
          <h2 style="color:#c0392b;">SOC Alert — {alert.priority.value}</h2>
          <table style="border-collapse:collapse;width:100%;">
            <tr><td style="padding:6px;color:#555;width:160px;">Risk score</td>
                <td style="padding:6px;font-weight:bold;">{alert.risk_score}/100</td></tr>
            <tr><td style="padding:6px;color:#555;">Source IP</td>
                <td style="padding:6px;">{alert.source_ip}:{alert.dst_port}</td></tr>
            <tr><td style="padding:6px;color:#555;">MITRE tactic</td>
                <td style="padding:6px;">{alert.mitre_tactic}</td></tr>
            <tr><td style="padding:6px;color:#555;">Anomaly type</td>
                <td style="padding:6px;">{alert.anomaly_type}</td></tr>
            <tr><td style="padding:6px;color:#555;">Model</td>
                <td style="padding:6px;">{alert.model_used}</td></tr>
            <tr><td style="padding:6px;color:#555;">Top features</td>
                <td style="padding:6px;">{features}</td></tr>
          </table>
          <h3>คำอธิบาย (ภาษาไทย)</h3>
          <p style="background:#f8f8f8;padding:12px;border-left:4px solid #e74c3c;">
            {alert.explanation_th}
          </p>
          <h3>Remediation steps</h3>
          <ol>{steps_html}</ol>
          <hr/>
          <small style="color:#888;">Timestamp: {alert.timestamp} |
            Faithfulness: {alert.faithfulness_score:.2f} |
            Response: {alert.response_ms}ms</small>
        </body></html>
        """

    def _build_digest_html(self, entries: list[DigestEntry], stats: dict) -> str:
        rows = "".join(
            f"""<tr>
              <td style="padding:6px;border-bottom:1px solid #eee;">{e.timestamp[:19]}</td>
              <td style="padding:6px;border-bottom:1px solid #eee;">{e.source_ip}</td>
              <td style="padding:6px;border-bottom:1px solid #eee;">{e.risk_score}</td>
              <td style="padding:6px;border-bottom:1px solid #eee;">{e.mitre_tactic}</td>
              <td style="padding:6px;border-bottom:1px solid #eee;">{e.anomaly_type}</td>
            </tr>"""
            for e in entries
        )
        mttd     = stats.get("mttd_avg_s", "N/A")
        top_type = stats.get("top_attack_type", "N/A")
        count    = stats.get("alert_count", len(entries))

        return f"""
        <html><body style="font-family:Arial,sans-serif;color:#222;">
          <h2>SOC Daily Digest — {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d')}</h2>
          <table style="border-collapse:collapse;margin-bottom:16px;">
            <tr><td style="padding:6px;color:#555;width:200px;">Total alerts</td>
                <td style="padding:6px;font-weight:bold;">{count}</td></tr>
            <tr><td style="padding:6px;color:#555;">Top attack type</td>
                <td style="padding:6px;">{top_type}</td></tr>
            <tr><td style="padding:6px;color:#555;">Avg MTTD</td>
                <td style="padding:6px;">{mttd}s</td></tr>
          </table>
          <h3>Alert log</h3>
          <table style="border-collapse:collapse;width:100%;font-size:13px;">
            <thead>
              <tr style="background:#f0f0f0;">
                <th style="padding:6px;text-align:left;">Timestamp</th>
                <th style="padding:6px;text-align:left;">Source IP</th>
                <th style="padding:6px;text-align:left;">Risk</th>
                <th style="padding:6px;text-align:left;">MITRE</th>
                <th style="padding:6px;text-align:left;">Type</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
        </body></html>
        """

    # ── Graph API helpers ─────────────────────────────────────────────────────

    def _get_token(self) -> str:
        import time
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
        data              = resp.json()
        self._token        = data["access_token"]
        import time as t
        self._token_expiry = t.time() + data.get("expires_in", 3600)
        return self._token

    def _send_email(self, subject: str, html: str) -> bool:
        if not settings.OUTLOOK_RECIPIENT_EMAILS:
            log.warning("OUTLOOK_RECIPIENT_EMAILS not set — skipping email")
            return False
        try:
            token = self._get_token()
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
            log.error("Email error: %s", exc)
            return False
