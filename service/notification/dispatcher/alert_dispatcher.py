from __future__ import annotations

import json
import signal
import sys
import time
from pathlib import Path

from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SERVICE_ROOT))

from notification.config import settings
from notification.eventbus.publisher import EventBus
from notification.metrics.influx import MetricsWriter
from notification.models.alert import LLMAlert, Priority
from notification.notifiers.line.notifier import LineNotifier
from notification.notifiers.outlook.notifier import OutlookNotifier
from notification.logging_utils import get_logger, setup_logging

setup_logging()
log = get_logger("dashboard.dispatcher")

_LOG_INTERVAL = 100


def _make_consumer() -> KafkaConsumer:
    for attempt in range(1, settings.KAFKA_CONNECT_RETRIES + 1):
        try:
            return KafkaConsumer(
                settings.KAFKA_LLM_OUTPUT_TOPIC,
                bootstrap_servers=settings.KAFKA_BOOTSTRAP,
                group_id=settings.KAFKA_DISPATCHER_GROUP,
                auto_offset_reset=settings.KAFKA_AUTO_OFFSET,
                enable_auto_commit=True,
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            )
        except NoBrokersAvailable:
            log.warning("Kafka not ready — attempt %d/%d", attempt, settings.KAFKA_CONNECT_RETRIES)
            time.sleep(5)
    raise RuntimeError("Cannot connect to Kafka")


class AlertDispatcher:
    """
    Consumes LLM JSON output from pa5220.llm_output and routes by priority:

      HIGH   → Line Notify (immediate) + RabbitMQ + InfluxDB
      MEDIUM → Outlook email (immediate) + RabbitMQ + InfluxDB
      LOW    → Outlook digest buffer + RabbitMQ + InfluxDB
    """

    def __init__(self) -> None:
        self._consumer  = _make_consumer()
        self._eventbus  = EventBus()
        self._metrics   = MetricsWriter()
        self._line      = LineNotifier()
        self._outlook   = OutlookNotifier()
        self._running   = True
        self._counts    = {p.value: 0 for p in Priority}
        self._last_digest_day: int = -1

        signal.signal(signal.SIGINT,  self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def run(self) -> None:
        log.info("Dispatcher started (topic=%s)", settings.KAFKA_LLM_OUTPUT_TOPIC)
        processed = 0

        for message in self._consumer:
            if not self._running:
                break
            try:
                alert = LLMAlert.from_dict(message.value)
                self._dispatch(alert)
                processed += 1
                self._counts[alert.priority.value] += 1

                if processed % _LOG_INTERVAL == 0:
                    log.info(
                        "dispatched=%d  HIGH=%d  MEDIUM=%d  LOW=%d",
                        processed,
                        self._counts["HIGH"],
                        self._counts["MEDIUM"],
                        self._counts["LOW"],
                    )

                self._check_daily_digest()

            except (KeyError, ValueError) as exc:
                log.warning("Malformed alert: %s — %s", message.value, exc)
            except Exception as exc:
                log.error("Dispatch error: %s", exc)

        self._shutdown()

    # ── Routing logic ─────────────────────────────────────────────────────────

    def _dispatch(self, alert: LLMAlert) -> None:
        # Always write to InfluxDB and publish to event bus
        self._metrics.write_alert(alert)
        self._eventbus.publish_alert(alert)

        if alert.priority == Priority.HIGH:
            self._line.send(alert)

        elif alert.priority == Priority.MEDIUM:
            self._outlook.send_immediate(alert)

        elif alert.priority == Priority.LOW:
            self._outlook.buffer_for_digest(alert)

    def _check_daily_digest(self) -> None:
        from datetime import datetime, timezone
        now = datetime.now(tz=timezone.utc)
        if (
            now.hour == settings.OUTLOOK_DIGEST_HOUR
            and now.day != self._last_digest_day
        ):
            self._last_digest_day = now.day
            self._outlook.send_digest(stats=self._collect_digest_stats())

    def _collect_digest_stats(self) -> dict:
        return {
            "alert_count":     sum(self._counts.values()),
            "top_attack_type": "unknown",   # populated by ML layer in production
            "mttd_avg_s":      "N/A",
        }

    def _handle_shutdown(self, signum: int, _frame) -> None:
        log.info("Received signal %d — shutting down", signum)
        self._running = False

    def _shutdown(self) -> None:
        log.info("Flushing and closing connections...")
        self._eventbus.close()
        self._metrics.close()
        self._consumer.close()
        log.info("Dispatcher stopped.")


def main() -> None:
    AlertDispatcher().run()


if __name__ == "__main__":
    main()
