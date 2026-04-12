from __future__ import annotations

import signal
import sys

from kafka import KafkaConsumer, KafkaProducer

from enrich.config import settings
from enrich.cti.client import CTIClient
from enrich.enricher import enrich_record, to_dict
from enrich.metrics.counters import PipelineMetrics
from enrich.pipeline.dlq import DeadLetterQueue
from enrich.utils.logging import get_logger

log = get_logger("enrich.pipeline")

_LOG_INTERVAL = int(settings.LOG_LEVEL == "DEBUG" and 100 or 1_000)


class EnrichmentPipeline:
    """
    Orchestrates the full enrichment loop:
      Kafka consumer → CTI enrichment → label → Kafka producer
      Bad messages → DLQ
      Counters → periodic log

    Handles SIGINT / SIGTERM for graceful shutdown.
    """

    def __init__(
        self,
        consumer: KafkaConsumer,
        producer: KafkaProducer,
        cti: CTIClient,
        dlq: DeadLetterQueue,
        metrics: PipelineMetrics,
    ) -> None:
        self._consumer = consumer
        self._producer = producer
        self._cti      = cti
        self._dlq      = dlq
        self._metrics  = metrics
        self._running  = True

        signal.signal(signal.SIGINT,  self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    # ── Public ─────────────────────────────────────────────────────────────────

    def run(self) -> None:
        log.info(
            "Pipeline started (input=%s → output=%s)",
            settings.KAFKA_INPUT_TOPIC,
            settings.KAFKA_OUTPUT_TOPIC,
        )
        try:
            for message in self._consumer:
                if not self._running:
                    break
                self._process(message.value)
        finally:
            self._shutdown()

    # ── Private ────────────────────────────────────────────────────────────────

    def _process(self, raw: dict) -> None:
        try:
            enriched   = enrich_record(raw, self._cti)
            had_signal = enriched.ioc_confidence > 0

            self._producer.send(
                settings.KAFKA_OUTPUT_TOPIC,
                value=to_dict(enriched),
            )
            self._metrics.inc("processed")
            self._metrics.inc("cti_hits"   if had_signal else "cti_misses")

            processed = self._metrics.processed
            if processed % _LOG_INTERVAL == 0:
                self._log_snapshot()

        except (KeyError, ValueError, TypeError) as exc:
            self._metrics.inc("skipped")
            log.debug("Skipped malformed record: %s — %s", raw, exc)

        except Exception as exc:
            self._metrics.inc("errors")
            self._metrics.inc("dlq_sent")
            log.error("Unhandled error — sending to DLQ: %s", exc)
            self._dlq.send(raw, exc)

    def _log_snapshot(self) -> None:
        snap = self._metrics.snapshot()
        log.info(
            "processed=%(processed)d  skipped=%(skipped)d  errors=%(errors)d  "
            "cti_hit_rate=%(cti_hit_rate_pct).1f%%  "
            "throughput=%(throughput_per_sec).1f msg/s  "
            "cache=%(cache_size)d",
            {**snap, "cache_size": self._cti.cache_size},
        )

    def _handle_shutdown(self, signum: int, _frame) -> None:
        log.info("Received signal %d — shutting down gracefully…", signum)
        self._running = False

    def _shutdown(self) -> None:
        log.info("Flushing producer…")
        self._producer.flush()
        self._producer.close()
        self._dlq.close()
        self._consumer.close()
        self._log_snapshot()
        log.info("Pipeline stopped.")
