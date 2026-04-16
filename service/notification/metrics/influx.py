from __future__ import annotations

from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import SYNCHRONOUS
from influxdb_client.domain.write_precision import WritePrecision

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

log = get_logger("dashboard.metrics.influx")


class MetricsWriter:
    """
    Writes alert metrics to InfluxDB.

    Measurement: soc_alert
    Tags:        priority, anomaly_type, mitre_tactic, model_used
    Fields:      risk_score, mttd_s, faithfulness_score, response_ms,
                 ioc_confidence, actor_known
    """

    def __init__(self) -> None:
        try:
            self._client = InfluxDBClient(
                url   = settings.INFLUX_URL,
                token = settings.INFLUX_TOKEN,
                org   = settings.INFLUX_ORG,
            )
            self._write = self._client.write_api(write_options=SYNCHRONOUS)
            log.info("InfluxDB connected — bucket=%s", settings.INFLUX_BUCKET)
        except Exception as exc:
            log.error("InfluxDB init failed: %s", exc, exc_info=True)
            self._client = None
            self._write  = None

    def write_alert(self, alert: LLMAlert) -> None:
        if self._write is None:
            log.warning("InfluxDB not connected — skipping metric for %s", alert.alert_id)
            return

        point = {
            "measurement": "soc_alert",
            "tags": {
                "priority":     alert.priority.value,
                "anomaly_type": alert.anomaly_type,
                "mitre_tactic": alert.mitre_tactic,
                "model_used":   alert.model_used,
            },
            "fields": {
                "risk_score":         float(alert.risk_score),
                "faithfulness_score": alert.faithfulness_score,
                "response_ms":        alert.response_ms,
                "ioc_confidence":     alert.ioc_confidence,
                "actor_known":        int(alert.actor_known),
                "mttd_s":             alert.mttd_s if alert.mttd_s is not None else 0.0,
            },
            "time": alert.timestamp,
        }

        try:
            self._write.write(
                bucket    = settings.INFLUX_BUCKET,
                org       = settings.INFLUX_ORG,
                record    = point,
                precision = WritePrecision.S,
            )
            log.debug("InfluxDB written — alert_id=%s", alert.alert_id)
        except Exception as exc:
            log.error("InfluxDB write failed for %s: %s", alert.alert_id, exc, exc_info=True)

    def close(self) -> None:
        try:
            if self._client:
                self._client.close()
                log.info("InfluxDB connection closed")
        except Exception as exc:
            log.warning("InfluxDB close error: %s", exc)
