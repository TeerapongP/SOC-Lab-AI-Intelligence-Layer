from __future__ import annotations

import requests

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

log = get_logger("dashboard.notifiers.line")

_GRAFANA_DASHBOARD_PATH = "/d/soc-main/soc-overview"


class LineNotifier:
    """
    Sends HIGH priority alerts to Line Notify immediately.

    Message format:
      [HIGH] 🔴 ตรวจพบภัยคุกคาม
      IP: <source_ip>
      MITRE: <mitre_tactic>
      <explanation_th สรุป 2 บรรทัด>
      🔗 <grafana link>
    """

    def send(self, alert: LLMAlert) -> bool:
        summary = self._build_message(alert)
        try:
            resp = requests.post(
                settings.LINE_NOTIFY_URL,
                headers={"Authorization": f"Bearer {settings.LINE_NOTIFY_TOKEN}"},
                data={"message": summary},
                timeout=10,
            )
            if resp.status_code == 200:
                log.info("Line Notify sent — risk=%d ip=%s", alert.risk_score, alert.source_ip)
                return True
            log.warning("Line Notify failed: HTTP %d — %s", resp.status_code, resp.text)
            return False
        except requests.RequestException as exc:
            log.error("Line Notify request error: %s", exc)
            return False

    def _build_message(self, alert: LLMAlert) -> str:
        explanation_short = "\n".join(alert.explanation_th.splitlines()[:2])
        grafana_url = (
            f"{settings.LINE_GRAFANA_BASE_URL}{_GRAFANA_DASHBOARD_PATH}"
            f"?var-src_ip={alert.source_ip}"
        )
        return (
            f"\n[{alert.priority.value}] ตรวจพบภัยคุกคาม\n"
            f"IP: {alert.source_ip}  Port: {alert.dst_port}\n"
            f"MITRE: {alert.mitre_tactic}\n"
            f"Risk: {alert.risk_score}/100\n"
            f"{explanation_short}\n"
            f"Dashboard: {grafana_url}"
        )
