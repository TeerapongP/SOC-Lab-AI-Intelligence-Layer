from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

import requests

from notification.config import settings
from notification.models.alert import LLMAlert, Priority
from notification.logging_utils import get_logger

log = get_logger("notification.shuffle.webhook")

_TIMEOUT_S = 10

# Webhook URL map — MEDIUM/LOW routed via Shuffle
_WEBHOOK_MAP = {
    Priority.MEDIUM: lambda: settings.SHUFFLE_WEBHOOK_MEDIUM,
    Priority.LOW:    lambda: settings.SHUFFLE_WEBHOOK_LOW,
}


class ShuffleWebhook:
    """
    Sends alert payloads to Shuffle SOAR via HTTP Webhook trigger.

        Priority routing:
            MEDIUM → SHUFFLE_WEBHOOK_MEDIUM → Shuffle workflow → Outlook immediate
            LOW    → SHUFFLE_WEBHOOK_LOW    → Shuffle workflow → Outlook digest buffer

    Daily digest:
      → SHUFFLE_WEBHOOK_DIGEST → Shuffle workflow → Outlook digest email
    """

    def send(self, alert: LLMAlert) -> bool:
        if alert.priority not in _WEBHOOK_MAP:
            log.warning("No Shuffle route for priority=%s", alert.priority.value)
            return False

        url = _WEBHOOK_MAP[alert.priority]()
        if not url:
            log.warning(
                "SHUFFLE_WEBHOOK_%s not set — skipping alert ip=%s",
                alert.priority.value, alert.source_ip,
            )
            return False

        payload = self._build_alert_payload(alert)
        return self._post(url, payload, label=f"alert/{alert.priority.value}")

    def send_digest(self, stats: dict) -> bool:
        url = settings.SHUFFLE_WEBHOOK_DIGEST
        if not url:
            log.warning("SHUFFLE_WEBHOOK_DIGEST not set — skipping digest")
            return False

        payload = {
            "event_type":   "daily_digest",
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            **stats,
        }
        return self._post(url, payload, label="digest")

    # ── Private ────────────────────────────────────────────────────────────────

    def _build_alert_payload(self, alert: LLMAlert) -> dict:
        """
        Flat JSON payload — Shuffle workflow reads these fields directly
        to build Line message and Outlook email body.
        """
        return {
            "event_type":           "alert",
            "priority":             alert.priority.value,
            "risk_score":           alert.risk_score,
            "source_ip":            alert.source_ip,
            "dst_port":             alert.dst_port,
            "anomaly_type":         alert.anomaly_type,
            "mitre_tactic":         alert.mitre_tactic,
            "affected_asset":       alert.affected_asset,
            "explanation_th":       alert.explanation_th,
            "remediation":          alert.remediation,
            "top_3_features":       alert.top_3_features,
            "model_used":           alert.model_used,
            "ensemble_confidence":  alert.ensemble_confidence,
            "faithfulness_score":   alert.faithfulness_score,
            "hallucination_rate":   alert.hallucination_rate,
            "response_ms":          alert.response_ms,
            "timestamp":            alert.timestamp,
            "grafana_url": (
                f"{settings.LINE_GRAFANA_BASE_URL}/d/soc-main/soc-overview"
                f"?var-src_ip={alert.source_ip}"
            ),
        }

    def _post(self, url: str, payload: dict, label: str) -> bool:
        try:
            resp = requests.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=_TIMEOUT_S,
            )
            if resp.status_code in (200, 201, 202):
                log.info("Shuffle webhook OK [%s] status=%d", label, resp.status_code)
                return True
            log.warning(
                "Shuffle webhook failed [%s] status=%d body=%s",
                label, resp.status_code, resp.text[:200],
            )
            return False
        except requests.Timeout:
            log.error("Shuffle webhook timeout [%s] url=%s", label, url)
            return False
        except requests.RequestException as exc:
            log.error("Shuffle webhook error [%s]: %s", label, exc)
            return False
