from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

import requests

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

log = get_logger("dashboard.metrics.elasticsearch")


class ElasticsearchWriter:
    """
    Writes alerts directly into Elasticsearch using the REST API.

    Index target:
      {ELASTIC_URL}/{ELASTIC_INDEX}/_doc
    """

    def __init__(self) -> None:
        self._enabled = settings.ELASTIC_ENABLED
        self._url = f"{settings.ELASTIC_URL}/{settings.ELASTIC_INDEX}/_doc"
        self._session = requests.Session()

        self._headers = {"Content-Type": "application/json"}
        if settings.ELASTIC_API_KEY:
            self._headers["Authorization"] = f"ApiKey {settings.ELASTIC_API_KEY}"

        self._auth = None
        if settings.ELASTIC_USERNAME and settings.ELASTIC_PASSWORD:
            self._auth = (settings.ELASTIC_USERNAME, settings.ELASTIC_PASSWORD)

        if self._enabled:
            log.info(
                "Elasticsearch writer enabled (url=%s index=%s)",
                settings.ELASTIC_URL,
                settings.ELASTIC_INDEX,
            )
        else:
            log.info("Elasticsearch writer disabled (ELASTIC_ENABLED=false)")

    def write_alert(self, alert: LLMAlert) -> None:
        if not self._enabled:
            return

        doc = asdict(alert)
        doc["priority"] = alert.priority.value
        doc["ingested_at"] = datetime.now(tz=timezone.utc).isoformat()

        if not doc.get("timestamp"):
            doc["timestamp"] = doc["ingested_at"]

        try:
            resp = self._session.post(
                self._url,
                json=doc,
                headers=self._headers,
                auth=self._auth,
                verify=settings.ELASTIC_VERIFY_TLS,
                timeout=settings.ELASTIC_TIMEOUT_SEC,
            )
            if resp.status_code in (200, 201):
                return
            log.warning(
                "Elasticsearch index failed: HTTP %d - %s",
                resp.status_code,
                resp.text[:200],
            )
        except requests.RequestException as exc:
            log.warning("Elasticsearch write error: %s", exc)

    def close(self) -> None:
        self._session.close()
