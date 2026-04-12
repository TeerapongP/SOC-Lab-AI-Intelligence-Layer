from __future__ import annotations

import json
import time

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable

from enrich.config import settings
from enrich.models import EnrichedRecord
from enrich.utils.logging import get_logger, setup_logging
from feature_extractor.extractor import FeatureExtractor, to_dict

setup_logging()
log = get_logger("feature_extractor")

_LOG_INTERVAL = 1_000


def _make_consumer() -> KafkaConsumer:
    for attempt in range(1, settings.KAFKA_CONNECT_RETRIES + 1):
        try:
            return KafkaConsumer(
                settings.KAFKA_OUTPUT_TOPIC,
                bootstrap_servers=settings.KAFKA_BOOTSTRAP,
                group_id=settings.KAFKA_FEATURES_GROUP_ID,
                auto_offset_reset=settings.KAFKA_AUTO_OFFSET,
                enable_auto_commit=True,
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            )
        except NoBrokersAvailable:
            log.warning("Kafka not ready — attempt %d/%d", attempt, settings.KAFKA_CONNECT_RETRIES)
            time.sleep(5)
    raise RuntimeError("Cannot connect to Kafka")


def _make_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=settings.KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        retries=settings.KAFKA_RETRIES,
        linger_ms=settings.KAFKA_LINGER_MS,
        max_in_flight_requests_per_connection=1,
    )


def main() -> None:
    extractor = FeatureExtractor()
    consumer  = _make_consumer()
    producer  = _make_producer()

    processed = skipped = errors = 0
    log.info(
        "Feature extractor started (%s → %s)",
        settings.KAFKA_OUTPUT_TOPIC,
        settings.KAFKA_FEATURES_TOPIC,
    )

    for message in consumer:
        raw: dict = message.value
        try:
            rec = EnrichedRecord(**raw)
            fv  = extractor.extract(rec)
            fv  = extractor.transform(fv)
            producer.send(settings.KAFKA_FEATURES_TOPIC, value=to_dict(fv))
            processed += 1

            if processed % _LOG_INTERVAL == 0:
                log.info("processed=%d  skipped=%d  errors=%d", processed, skipped, errors)

        except (KeyError, ValueError, TypeError) as exc:
            skipped += 1
            log.debug("Skipped malformed record: %s — %s", raw, exc)
        except Exception as exc:
            errors += 1
            log.error("Unexpected error: %s — %s", raw, exc)


if __name__ == "__main__":
    main()
