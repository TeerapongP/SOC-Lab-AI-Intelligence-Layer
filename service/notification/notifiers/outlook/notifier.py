from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import requests

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

log = get_logger("dashboard.notifiers.outlook")

_TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_GRAPH_SENDMAIL_TMPL = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"
_TIMEOUT_S = 15


class OutlookNotifier:
    """Send immediate alerts and daily digests via Microsoft Graph sendMail."""

    def __init__(self) -> None:
        self._token: str | None = None
        self._token_expiry: datetime = datetime.now(timezone.utc)

    def send(self, alert: LLMAlert) -> bool:
        recipients = settings.OUTLOOK_RECIPIENT_EMAILS
        if not self._configured() or not recipients:
            log.warning("Outlook config incomplete or recipients missing — skipping alert email")
            return False

        subject = f"[SOC][{alert.priority.value}] Alert {alert.source_ip}:{alert.dst_port}"
        recommendation = " / ".join(alert.remediation) if alert.remediation else "ตรวจสอบ IOC และแยกเครื่องที่ได้รับผลกระทบ"

        body_text = (
            "แจ้งเตือนความปลอดภัยระบบ SOC\n"
            f"ระดับความเสี่ยง: {alert.priority.value}\n"
            f"ต้นทาง: {alert.source_ip}:{alert.dst_port}\n"
            f"ประเภทภัยคุกคาม: {alert.anomaly_type}\n"
            f"MITRE Tactic: {alert.mitre_tactic}\n"
            f"คะแนนความเสี่ยง: {alert.risk_score}/100\n"
            f"คำแนะนำเบื้องต้น: {recommendation}\n\n"
            f"คำอธิบาย: {alert.explanation_th}"
        )

        return self._send_mail(subject=subject, body_text=body_text, recipients=recipients)

    def send_digest(self, stats: dict[str, Any]) -> bool:
        recipients = settings.OUTLOOK_RECIPIENT_EMAILS
        if not self._configured() or not recipients:
            log.warning("Outlook config incomplete or recipients missing — skipping digest email")
            return False

        subject = "[SOC] Daily Digest"
        body_text = (
            "สรุปแจ้งเตือนประจำวัน (UTC)\n"
            f"- Alerts ทั้งหมด: {stats.get('alert_count', 0)}\n"
            f"- HIGH: {stats.get('high_count', 0)}\n"
            f"- MEDIUM: {stats.get('medium_count', 0)}\n"
            f"- LOW: {stats.get('low_count', 0)}\n"
            f"- ประเภทโจมตีสูงสุด: {stats.get('top_attack_type', 'N/A')} ({stats.get('top_attack_count', 0)})\n"
            f"- MTTD เฉลี่ย (วินาที): {stats.get('mttd_avg_s', 'N/A')}\n"
        )

        return self._send_mail(subject=subject, body_text=body_text, recipients=recipients)

    def _send_mail(self, *, subject: str, body_text: str, recipients: list[str]) -> bool:
        token = self._get_access_token()
        if not token:
            return False

        payload = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "Text",
                    "content": body_text,
                },
                "toRecipients": [
                    {"emailAddress": {"address": recipient}}
                    for recipient in recipients
                ],
            },
            "saveToSentItems": "false",
        }

        url = _GRAPH_SENDMAIL_TMPL.format(sender=quote(settings.OUTLOOK_SENDER_EMAIL, safe=""))
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=_TIMEOUT_S)
            if resp.status_code == 202:
                log.info("Outlook email sent — subject=%s recipients=%d", subject, len(recipients))
                return True

            log.warning("Outlook sendMail failed: HTTP %d — %s", resp.status_code, resp.text[:300])
            return False
        except requests.RequestException as exc:
            log.error("Outlook sendMail request error: %s", exc, exc_info=True)
            return False

    def _get_access_token(self) -> str | None:
        now = datetime.now(timezone.utc)
        if self._token and now < self._token_expiry:
            return self._token

        token_url = _TOKEN_URL_TMPL.format(tenant_id=settings.OUTLOOK_TENANT_ID)
        data = {
            "grant_type": "client_credentials",
            "client_id": settings.OUTLOOK_CLIENT_ID,
            "client_secret": settings.OUTLOOK_CLIENT_SECRET,
            "scope": _GRAPH_SCOPE,
        }

        try:
            resp = requests.post(token_url, data=data, timeout=_TIMEOUT_S)
            if resp.status_code != 200:
                log.warning("Outlook token request failed: HTTP %d — %s", resp.status_code, resp.text[:300])
                return None

            payload = resp.json()
            access_token = payload.get("access_token", "")
            expires_in = int(payload.get("expires_in", 3600))
            if not access_token:
                log.warning("Outlook token response missing access_token")
                return None

            token_roles = self._token_roles(access_token)
            if "Mail.Send" not in token_roles:
                log.warning(
                    "Outlook app token missing Mail.Send role. Configure Graph Application permission 'Mail.Send' and grant admin consent."
                )

            self._token = access_token
            self._token_expiry = now + timedelta(seconds=max(expires_in - 60, 60))
            return self._token
        except (ValueError, requests.RequestException) as exc:
            log.error("Outlook token request error: %s", exc, exc_info=True)
            return None

    def _configured(self) -> bool:
        return all(
            [
                settings.OUTLOOK_TENANT_ID,
                settings.OUTLOOK_CLIENT_ID,
                settings.OUTLOOK_CLIENT_SECRET,
                settings.OUTLOOK_SENDER_EMAIL,
            ]
        )

    def _token_roles(self, token: str) -> list[str]:
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return []
            payload = parts[1]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            decoded = base64.urlsafe_b64decode(payload.encode("utf-8"))
            claims = json.loads(decoded.decode("utf-8"))
            roles = claims.get("roles", [])
            if isinstance(roles, list):
                return [str(r) for r in roles]
            return []
        except Exception:
            return []
