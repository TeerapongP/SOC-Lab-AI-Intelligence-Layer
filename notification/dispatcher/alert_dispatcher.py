from __future__ import annotations

import json
import signal
import sys
import time
from collections import Counter
from pathlib import Path

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable

_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SERVICE_ROOT))

from notification.config import settings
from notification.eventbus.publisher import EventBus
from notification.metrics.elasticsearch import ElasticsearchWriter
from notification.metrics.influx import MetricsWriter
from notification.models.alert import LLMAlert, Priority
from notification.notifiers.line.notifier import LineNotifier
from notification.logging_utils import get_logger, setup_logging

setup_logging()
log = get_logger("dashboard.dispatcher")

_LOG_INTERVAL = 100
_KAFKA_POLL_TIMEOUT_MS = 5_000


def _make_consumer() -> KafkaConsumer:
    for attempt in range(1, settings.KAFKA_CONNECT_RETRIES + 1):
        try:
            return KafkaConsumer(
                settings.KAFKA_LLM_OUTPUT_TOPIC,
                bootstrap_servers=settings.KAFKA_BOOTSTRAP,
                group_id=settings.KAFKA_DISPATCHER_GROUP,
                auto_offset_reset=settings.KAFKA_AUTO_OFFSET,
                enable_auto_commit=True,
                value_deserializer=lambda b: b.decode("utf-8", errors="replace"),
            )
        except NoBrokersAvailable:
            log.warning("Kafka not ready - attempt %d/%d", attempt, settings.KAFKA_CONNECT_RETRIES)
            time.sleep(5)
    raise RuntimeError("Cannot connect to Kafka after %d attempts" % settings.KAFKA_CONNECT_RETRIES)


def _make_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=settings.KAFKA_BOOTSTRAP,
        value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode("utf-8"),
        linger_ms=50,
        retries=3,
    )


class AlertDispatcher:
    """
    Consumes LLM JSON output from pa5220.llm_output and routes alerts to
    metrics, Elasticsearch, RabbitMQ, and LINE for high-priority alerts.
    """

    def __init__(self) -> None:
        self._consumer = _make_consumer()
        self._producer = _make_producer()
        self._eventbus = EventBus()
        self._metrics = MetricsWriter()
        self._elastic = ElasticsearchWriter()
        self._line = LineNotifier()
        self._running = True

        self._counts: dict[str, int] = {p.value: 0 for p in Priority}
        self._attack_type_counter: Counter = Counter()
        self._mttd_samples: list[float] = []
        self._total_processed: int = 0

        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def run(self) -> None:
        log.info("Dispatcher started (topic=%s)", settings.KAFKA_LLM_OUTPUT_TOPIC)

        while self._running:
            records = self._consumer.poll(timeout_ms=_KAFKA_POLL_TIMEOUT_MS)

            for _tp, messages in records.items():
                if not self._running:
                    break
                for message in messages:
                    self._handle_message(message)

        self._shutdown()

    def _handle_message(self, message) -> None:
        raw_value = message.value
        try:
            payload = json.loads(raw_value)
            alert = LLMAlert.from_dict(payload)
            self._dispatch(alert)

            self._total_processed += 1
            self._counts[alert.priority.value] += 1

            if self._total_processed % _LOG_INTERVAL == 0:
                log.info(
                    "dispatched=%d  HIGH=%d  MEDIUM=%d  LOW=%d",
                    self._total_processed,
                    self._counts["HIGH"],
                    self._counts["MEDIUM"],
                    self._counts["LOW"],
                )

        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            log.warning("Malformed alert: %s - %s", raw_value, exc)
            self._send_dlq(message, raw_value, exc, stage="parse")
        except Exception as exc:
            log.error("Dispatch error: %s", exc, exc_info=True)
            self._send_dlq(message, raw_value, exc, stage="dispatch")

    def _dispatch(self, alert: LLMAlert) -> None:
        self._metrics.write_alert(alert)
        self._elastic.write_alert(alert)
        self._eventbus.publish_alert(alert)

        if alert.mitre_tactic:
            self._attack_type_counter[alert.mitre_tactic] += 1
        if hasattr(alert, "mttd_s") and alert.mttd_s is not None:
            self._mttd_samples.append(float(alert.mttd_s))

        if alert.priority == Priority.HIGH:
            self._line.send(alert)

    def _send_dlq(self, message, raw_value: str, exc: Exception, stage: str) -> None:
        dlq_record = {
            "stage": stage,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "source_topic": message.topic,
            "source_partition": message.partition,
            "source_offset": message.offset,
            "raw_value": raw_value,
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            self._producer.send(settings.KAFKA_LLM_DLQ_TOPIC, dlq_record)
            self._producer.flush(timeout=5)
            log.info(
                "DLQ published topic=%s source_offset=%s stage=%s",
                settings.KAFKA_LLM_DLQ_TOPIC,
                message.offset,
                stage,
            )
        except Exception as dlq_exc:
            log.error("DLQ publish failed: %s", dlq_exc, exc_info=True)

    def _handle_shutdown(self, signum: int, _frame) -> None:
        log.info("Received signal %d - shutting down gracefully", signum)
        self._running = False

    def _shutdown(self) -> None:
        log.info("Flushing and closing connections...")
        self._eventbus.close()
        self._metrics.close()
        self._elastic.close()
        self._producer.close()
        self._consumer.close()
        log.info("Dispatcher stopped. Total processed: %d", self._total_processed)


def main() -> None:
    AlertDispatcher().run()


if __name__ == "__main__":
    main()
