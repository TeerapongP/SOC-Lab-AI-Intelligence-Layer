from __future__ import annotations

from datetime import datetime, timezone

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

log = get_logger("dashboard.metrics")


class MetricsWriter:
    """
    Writes pipeline metrics to InfluxDB.

    Measurements:
      soc_alert       — per-alert metrics (risk_score, response_ms, etc.)
      soc_pipeline    — layer-level counters (ingest_rate, enrich_latency, etc.)
    """

    def __init__(self) -> None:
        self._client     = None
        self._write_api  = None
        self._connect()

    def _connect(self) -> None:
        try:
            from influxdb_client import InfluxDBClient, WriteOptions
            from influxdb_client.client.write_api import SYNCHRONOUS

            self._client    = InfluxDBClient(
                url=settings.INFLUX_URL,
                token=settings.INFLUX_TOKEN,
                org=settings.INFLUX_ORG,
            )
            self._write_api = self._client.write_api(write_options=SYNCHRONOUS)
            log.info("Connected to InfluxDB at %s", settings.INFLUX_URL)
        except ImportError:
            log.warning("influxdb-client not installed — metrics disabled")
        except Exception as exc:
            log.error("InfluxDB connection failed: %s", exc)

    def write_alert(self, alert: LLMAlert) -> None:
        if not self._write_api:
            return
        try:
            from influxdb_client import Point
            point = (
                Point("soc_alert")
                .tag("priority",     alert.priority.value)
                .tag("model_used",   alert.model_used)
                .tag("mitre_tactic", alert.mitre_tactic)
                .field("risk_score",          alert.risk_score)
                .field("ensemble_confidence", alert.ensemble_confidence)
                .field("faithfulness_score",  alert.faithfulness_score)
                .field("hallucination_rate",  alert.hallucination_rate)
                .field("response_ms",         alert.response_ms)
                .time(datetime.now(tz=timezone.utc))
            )
            self._write_api.write(
                bucket=settings.INFLUX_BUCKET,
                org=settings.INFLUX_ORG,
                record=point,
            )
        except Exception as exc:
            log.warning("InfluxDB write failed: %s", exc)

    def write_layer_metric(self, layer: str, measurement: str, fields: dict, tags: dict | None = None) -> None:
        """Generic method for writing layer-level pipeline metrics."""
        if not self._write_api:
            return
        try:
            from influxdb_client import Point
            point = Point(measurement).tag("layer", layer)
            for k, v in (tags or {}).items():
                point = point.tag(k, v)
            for k, v in fields.items():
                point = point.field(k, v)
            point = point.time(datetime.now(tz=timezone.utc))
            self._write_api.write(
                bucket=settings.INFLUX_BUCKET,
                org=settings.INFLUX_ORG,
                record=point,
            )
        except Exception as exc:
            log.warning("InfluxDB layer metric write failed: %s", exc)

    def close(self) -> None:
        if self._client:
            self._client.close()
