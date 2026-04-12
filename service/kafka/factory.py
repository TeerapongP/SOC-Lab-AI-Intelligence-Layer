from __future__ import annotations

import json
import time

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable

from enrich.config import settings
from enrich.utils.logging import get_logger

log = get_logger("enrich.kafka")


def make_consumer(
    topic: str | None = None,
    retries: int | None = None,
) -> KafkaConsumer:
    topic   = topic   or settings.KAFKA_INPUT_TOPIC
    retries = retries or settings.KAFKA_CONNECT_RETRIES

    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=settings.KAFKA_BOOTSTRAP,
                group_id=settings.KAFKA_GROUP_ID,
                auto_offset_reset=settings.KAFKA_AUTO_OFFSET,
                enable_auto_commit=True,
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            )
            log.info("Kafka consumer ready (topic=%s)", topic)
            return consumer
        except NoBrokersAvailable:
            log.warning(
                "Kafka not ready — attempt %d/%d, retrying in 5s",
                attempt, retries,
            )
            time.sleep(5)

    raise RuntimeError(f"Cannot connect to Kafka after {retries} attempts")


def make_producer() -> KafkaProducer:
    producer = KafkaProducer(
        bootstrap_servers=settings.KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        retries=settings.KAFKA_RETRIES,
        linger_ms=settings.KAFKA_LINGER_MS,
        max_in_flight_requests_per_connection=1,
    )
    log.info("Kafka producer ready (bootstrap=%s)", settings.KAFKA_BOOTSTRAP)
    return producer
