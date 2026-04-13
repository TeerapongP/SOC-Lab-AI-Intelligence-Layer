from __future__ import annotations

from urllib.parse import quote

import requests

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

log = get_logger("dashboard.notifiers.line")

_GRAFANA_DASHBOARD_PATH = "/d/soc-main/soc-overview"
_LINE_PUSH_URL          = "https://api.line.me/v2/bot/message/push"
_LINE_MAX_TEXT_CHARS    = 5000   # LINE Messaging API text message limit


class LineNotifier:
    """
    Sends HIGH priority alerts to LINE group via LINE Messaging API (Push Message).

    ใช้แทน LINE Notify ที่ปิดบริการ 31 มี.ค. 2568

    Required settings:
        LINE_CHANNEL_ACCESS_TOKEN  — จาก LINE Developers Console
        LINE_GROUP_ID              — Group ID ขึ้นต้นด้วย 'C'

    Message format:
        🚨 [HIGH] ตรวจพบภัยคุกคาม
        IP: <source_ip>  Port: <dst_port>
        MITRE: <mitre_tactic>
        Risk: <risk_score>/100
        <explanation_th สรุป 2 บรรทัด>
        🔗 Dashboard: <grafana link>
    """

    def __init__(self) -> None:
        self._headers = {
            "Authorization": f"Bearer {settings.LINE_CHANNEL_ACCESS_TOKEN}",
            "Content-Type":  "application/json",
        }

    def send(self, alert: LLMAlert) -> bool:
        """
        Push alert message to LINE group.
        Returns True on success, False on any failure.
        """
        payload = {
            "to":       settings.LINE_GROUP_ID,
            "messages": [
                {
                    "type": "text",
                    "text": self._build_message(alert),
                }
            ],
        }

        try:
            resp = requests.post(
                _LINE_PUSH_URL,
                headers = self._headers,
                json    = payload,
                timeout = 10,
            )
            if resp.status_code == 200:
                log.info(
                    "LINE push sent — risk=%d ip=%s",
                    alert.risk_score,
                    alert.source_ip,
                )
                return True

            log.warning(
                "LINE push failed: HTTP %d — %s",
                resp.status_code,
                resp.text,
            )
            return False

        except requests.RequestException as exc:
            log.error("LINE push request error: %s", exc, exc_info=True)
            return False

    # ── Message builder ────────────────────────────────────────────────────────

    def _build_message(self, alert: LLMAlert) -> str:
        explanation_short = "\n".join(alert.explanation_th.splitlines()[:2])
        grafana_url       = self._grafana_url(alert.source_ip)

        message = (
            f"🚨 [{alert.priority.value}] ตรวจพบภัยคุกคาม\n"
            f"IP: {alert.source_ip}  Port: {alert.dst_port}\n"
            f"MITRE: {alert.mitre_tactic}\n"
            f"Risk: {alert.risk_score}/100\n"
            f"{explanation_short}\n"
            f"🔗 Dashboard: {grafana_url}"
        )

        if len(message) > _LINE_MAX_TEXT_CHARS:
            log.warning(
                "LINE message truncated (%d → %d chars) for ip=%s",
                len(message),
                _LINE_MAX_TEXT_CHARS,
                alert.source_ip,
            )
        return message[:_LINE_MAX_TEXT_CHARS]

    def _grafana_url(self, source_ip: str) -> str:
        return (
            f"{settings.LINE_GRAFANA_BASE_URL}{_GRAFANA_DASHBOARD_PATH}"
            f"?var-src_ip={quote(source_ip, safe='')}"
        )
