from __future__ import annotations

import json
import traceback
from datetime import datetime, timezone

from kafka import KafkaProducer

from enrich.config.settings import KAFKA_BOOTSTRAP
from enrich.utils.logging import get_logger

log = get_logger("enrich.dlq")

_DLQ_TOPIC_SUFFIX = ".dlq"


class DeadLetterQueue:
    """
    Sends unparseable / repeatedly-failing messages to a dedicated DLQ topic.

    DLQ topic name = original topic + ".dlq"
    e.g.  pa5220.raw  →  pa5220.raw.dlq

    Each DLQ record wraps the original raw bytes with error context so
    a human (or reprocessing job) can inspect and replay later.
    """

    def __init__(self, source_topic: str) -> None:
        self._topic = source_topic + _DLQ_TOPIC_SUFFIX
        self._producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            acks=1,          # fire-and-forget is acceptable for DLQ
            retries=2,
        )
        log.info("DLQ ready (topic=%s)", self._topic)

    def send(self, raw: dict, exc: Exception) -> None:
        envelope = {
            "failed_at":    datetime.now(tz=timezone.utc).isoformat(),
            "error_type":   type(exc).__name__,
            "error_msg":    str(exc),
            "traceback":    traceback.format_exc(),
            "original":     raw,
        }
        try:
            self._producer.send(self._topic, value=envelope)
        except Exception as send_exc:
            log.error("DLQ send failed: %s", send_exc)

    def close(self) -> None:
        self._producer.flush()
        self._producer.close()
