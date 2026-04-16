from __future__ import annotations

from urllib.parse import quote

import requests

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

log = get_logger("dashboard.notifiers.line")

_GRAFANA_DASHBOARD_PATH = "/d/soc-main/soc-overview"
_LINE_BROADCAST_URL     = "https://api.line.me/v2/bot/message/broadcast"
_LINE_MAX_TEXT_CHARS    = 5000   # LINE Messaging API text message limit


class LineNotifier:
    """
    Sends HIGH priority alerts to all followers via LINE Messaging API (Broadcast).

    Required settings:
        LINE_CHANNEL_ACCESS_TOKEN  — from LINE Developers Console
    """

    def __init__(self) -> None:
        self._headers = {
            "Authorization": f"Bearer {settings.LINE_CHANNEL_ACCESS_TOKEN}",
            "Content-Type":  "application/json",
        }

    def send(self, alert: LLMAlert) -> bool:
        """Broadcast alert message to all followers/subscribers."""
        if not settings.LINE_CHANNEL_ACCESS_TOKEN:
            log.warning("LINE_CHANNEL_ACCESS_TOKEN not set — skipping LINE broadcast")
            return False

        payload = {
            "messages": [
                {
                    "type": "text",
                    "text": self._build_message(alert),
                }
            ]
        }

        try:
            resp = requests.post(
                _LINE_BROADCAST_URL,
                headers = self._headers,
                json    = payload,
                timeout=10,
            )
            if resp.status_code == 200:
                log.info(
                    "LINE broadcast sent — risk=%d ip=%s",
                    alert.risk_score,
                    alert.source_ip,
                )
                return True

            log.warning("LINE broadcast failed: HTTP %d — %s", resp.status_code, resp.text[:200])
            return False
        except requests.RequestException as exc:
            log.error("LINE broadcast request error: %s", exc, exc_info=True)
            return False

    def _build_message(self, alert: LLMAlert) -> str:
        priority_label = self._priority_label(alert)
        recommendation = self._recommendation_text(alert)

        message = (
            "🚨 แจ้งเตือนความปลอดภัยระบบ SOC\n"
            f"พบเหตุการณ์เสี่ยง{priority_label}\n"
            f"ต้นทาง: {alert.source_ip} พอร์ต: {alert.dst_port}\n"
            f"ประเภทภัยคุกคาม: {alert.anomaly_type}\n"
            f"คะแนนความเสี่ยง: {alert.risk_score}/100\n"
            f"คำแนะนำเบื้องต้น: {recommendation}"
        )

        if len(message) > _LINE_MAX_TEXT_CHARS:
            log.warning(
                "LINE message truncated (%d → %d chars) for ip=%s",
                len(message),
                _LINE_MAX_TEXT_CHARS,
                alert.source_ip,
            )

        return message[:_LINE_MAX_TEXT_CHARS]

    def _priority_label(self, alert: LLMAlert) -> str:
        if alert.priority.value == "HIGH":
            return "สูง (HIGH)"
        if alert.priority.value == "MEDIUM":
            return "ปานกลาง (MEDIUM)"
        return "ต่ำ (LOW)"

    def _recommendation_text(self, alert: LLMAlert) -> str:
        if alert.remediation:
            return " / ".join(step.strip() for step in alert.remediation if step.strip())
        return "แยกระบบที่ได้รับผลกระทบ ตรวจสอบ IOC และแจ้งทีม SOC ทันที"

    def _grafana_url(self, source_ip: str) -> str:
        return (
            f"{settings.LINE_GRAFANA_BASE_URL}{_GRAFANA_DASHBOARD_PATH}"
            f"?var-src_ip={quote(source_ip, safe='')}"
        )
