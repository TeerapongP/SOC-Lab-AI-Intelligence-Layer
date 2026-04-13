from __future__ import annotations

import json
import signal
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from kafka import KafkaConsumer
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
from notification.notifiers.outlook.notifier import OutlookNotifier
from notification.logging_utils import get_logger, setup_logging

setup_logging()
log = get_logger("dashboard.dispatcher")

_LOG_INTERVAL = 100
_KAFKA_POLL_TIMEOUT_MS = 5_000  # wakeup ทุก 5s เพื่อให้ _check_daily_digest() ทำงานได้


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
    raise RuntimeError("Cannot connect to Kafka after %d attempts" % settings.KAFKA_CONNECT_RETRIES)


class AlertDispatcher:
    """
    Consumes LLM JSON output from pa5220.llm_output and routes by priority:

        HIGH   → Line Notify (immediate) + RabbitMQ + InfluxDB + Elasticsearch
        MEDIUM → Outlook email (immediate) + RabbitMQ + InfluxDB + Elasticsearch
        LOW    → Outlook digest buffer + RabbitMQ + InfluxDB + Elasticsearch

    FIX 1: ใช้ poll() แทน for-loop เพื่อให้ _check_daily_digest() ถูก trigger
            แม้ช่วงที่ไม่มี message เข้า Kafka
    FIX 2: _collect_digest_stats() คำนวณจาก counter จริง ไม่ hardcode
    FIX 3: reset daily counters หลัง send_digest() ทุกวัน
    FIX 4: exc_info=True ใน error log เพื่อ traceback ที่ debug ได้
    """

    def __init__(self) -> None:
        self._consumer = _make_consumer()
        self._eventbus = EventBus()
        self._metrics  = MetricsWriter()
        self._elastic  = ElasticsearchWriter()
        self._line     = LineNotifier()
        self._outlook  = OutlookNotifier()
        self._running  = True

        # ── Daily-reset counters (FIX 2 & 3) ──────────────────────────────────
        self._counts: dict[str, int] = {p.value: 0 for p in Priority}
        self._attack_type_counter: Counter[str] = Counter()
        self._mttd_samples: list[float] = []

        # ── Digest guard ───────────────────────────────────────────────────────
        self._last_digest_day: int = -1

        # ── Session total (never reset — for dispatcher log line) ──────────────
        self._total_processed: int = 0

        signal.signal(signal.SIGINT,  self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    # ── Main loop (FIX 1: poll-based) ─────────────────────────────────────────

    def run(self) -> None:
        log.info("Dispatcher started (topic=%s)", settings.KAFKA_LLM_OUTPUT_TOPIC)

        while self._running:
            # poll() unblocks every _KAFKA_POLL_TIMEOUT_MS ms
            # even when Kafka has no new messages → digest check always fires
            records = self._consumer.poll(timeout_ms=_KAFKA_POLL_TIMEOUT_MS)

            for _tp, messages in records.items():
                if not self._running:
                    break
                for message in messages:
                    self._handle_message(message)

            # Check digest on every poll cycle (FIX 1)
            self._check_daily_digest()

        self._shutdown()

    def _handle_message(self, message) -> None:
        try:
            alert = LLMAlert.from_dict(message.value)
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

        except (KeyError, ValueError) as exc:
            log.warning("Malformed alert: %s — %s", message.value, exc)
        except Exception as exc:
            log.error("Dispatch error: %s", exc, exc_info=True)  # FIX 4: traceback

    # ── Routing logic ──────────────────────────────────────────────────────────

    def _dispatch(self, alert: LLMAlert) -> None:
        # Always write to metrics + event bus + Elasticsearch index
        self._metrics.write_alert(alert)
        self._elastic.write_alert(alert)
        self._eventbus.publish_alert(alert)

        # Accumulate stats for daily digest (FIX 2)
        if hasattr(alert, "mitre_tactic") and alert.mitre_tactic:
            self._attack_type_counter[alert.mitre_tactic] += 1
        if hasattr(alert, "mttd_s") and alert.mttd_s is not None:
            self._mttd_samples.append(float(alert.mttd_s))

        # Route by priority
        if alert.priority == Priority.HIGH:
            self._line.send(alert)

        elif alert.priority == Priority.MEDIUM:
            self._outlook.send_immediate(alert)

        elif alert.priority == Priority.LOW:
            self._outlook.buffer_for_digest(alert)

    # ── Daily digest (FIX 1 + 3) ──────────────────────────────────────────────

    def _check_daily_digest(self) -> None:
        now = datetime.now(tz=timezone.utc)
        if (
            now.hour == settings.OUTLOOK_DIGEST_HOUR
            and now.day != self._last_digest_day
        ):
            log.info("Sending daily digest (day=%d hour=%d)", now.day, now.hour)
            self._last_digest_day = now.day
            self._outlook.send_digest(stats=self._collect_digest_stats())
            self._reset_daily_counters()  # FIX 3: reset หลัง send ทุกวัน

    def _collect_digest_stats(self) -> dict:
        """Build digest stats from real accumulators — ไม่ hardcode (FIX 2)."""
        top = self._attack_type_counter.most_common(1)
        avg_mttd = (
            round(sum(self._mttd_samples) / len(self._mttd_samples), 2)
            if self._mttd_samples
            else None
        )
        return {
            "alert_count":     sum(self._counts.values()),
            "high_count":      self._counts["HIGH"],
            "medium_count":    self._counts["MEDIUM"],
            "low_count":       self._counts["LOW"],
            "top_attack_type": top[0][0] if top else "N/A",
            "top_attack_count": top[0][1] if top else 0,
            "mttd_avg_s":      avg_mttd if avg_mttd is not None else "N/A",
        }

    def _reset_daily_counters(self) -> None:
        """Reset per-day accumulators after digest is sent (FIX 3)."""
        self._counts = {p.value: 0 for p in Priority}
        self._attack_type_counter.clear()
        self._mttd_samples.clear()
        log.info("Daily counters reset.")

    # ── Shutdown ───────────────────────────────────────────────────────────────

    def _handle_shutdown(self, signum: int, _frame) -> None:
        log.info("Received signal %d — shutting down gracefully", signum)
        self._running = False

    def _shutdown(self) -> None:
        log.info("Flushing and closing connections...")
        self._eventbus.close()
        self._metrics.close()
        self._elastic.close()
        self._consumer.close()
        log.info("Dispatcher stopped. Total processed: %d", self._total_processed)


def main() -> None:
    AlertDispatcher().run()


if __name__ == "__main__":
    main()