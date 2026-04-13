from __future__ import annotations

from datetime import datetime, timezone

from elasticsearch import Elasticsearch, ElasticsearchException

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

log = get_logger("dashboard.metrics.elasticsearch")


class ElasticsearchWriter:
    """
    Indexes alert documents into Elasticsearch (reuse opencti-elasticsearch).

    Index:    soc-alerts (settings.ELASTIC_ALERT_INDEX)
    Doc id:   alert.alert_id  — idempotent re-index on replay
    Mapping:  dynamic (no explicit mapping needed for thesis scope)
    """

    def __init__(self) -> None:
        try:
            kwargs: dict = {"hosts": [settings.ELASTIC_URL]}
            if settings.ELASTIC_API_KEY:
                kwargs["api_key"] = settings.ELASTIC_API_KEY
            self._es = Elasticsearch(**kwargs)
            log.info("Elasticsearch connected — index=%s", settings.ELASTIC_ALERT_INDEX)
        except Exception as exc:
            log.error("Elasticsearch init failed: %s", exc, exc_info=True)
            self._es = None

    def write_alert(self, alert: LLMAlert) -> None:
        if self._es is None:
            log.warning("Elasticsearch not connected — skipping index for %s", alert.alert_id)
            return

        doc = alert.to_dict()
        # Add ingested_at for Kibana time filter
        doc["ingested_at"] = datetime.now(tz=timezone.utc).isoformat()

        try:
            self._es.index(
                index      = settings.ELASTIC_ALERT_INDEX,
                id         = alert.alert_id,   # idempotent
                document   = doc,
            )
            log.debug("Elasticsearch indexed — alert_id=%s", alert.alert_id)
        except ElasticsearchException as exc:
            log.error("Elasticsearch index failed for %s: %s", alert.alert_id, exc, exc_info=True)

    def close(self) -> None:
        try:
            if self._es:
                self._es.close()
                log.info("Elasticsearch connection closed")
        except Exception as exc:
            log.warning("Elasticsearch close error: %s", exc)
