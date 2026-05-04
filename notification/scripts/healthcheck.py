from __future__ import annotations

import sys

import pika
from elasticsearch import Elasticsearch
from influxdb_client import InfluxDBClient
from kafka import KafkaProducer

from notification.config import settings


def _check_kafka() -> None:
    producer = KafkaProducer(bootstrap_servers=settings.KAFKA_BOOTSTRAP, request_timeout_ms=5000)
    try:
        if not producer.bootstrap_connected():
            raise RuntimeError("Kafka bootstrap is not connected")
    finally:
        producer.close()


def _check_rabbitmq() -> None:
    connection = pika.BlockingConnection(pika.URLParameters(settings.RABBITMQ_URL))
    try:
        connection.channel()
    finally:
        connection.close()


def _check_influxdb() -> None:
    client = InfluxDBClient(
        url=settings.INFLUX_URL,
        token=settings.INFLUX_TOKEN,
        org=settings.INFLUX_ORG,
    )
    try:
        if not client.ping():
            raise RuntimeError("InfluxDB ping returned false")
    finally:
        client.close()


def _check_elasticsearch() -> None:
    kwargs: dict = {"hosts": [settings.ELASTIC_URL]}
    if settings.ELASTIC_API_KEY:
        kwargs["api_key"] = settings.ELASTIC_API_KEY
    client = Elasticsearch(**kwargs)
    try:
        if not client.ping():
            raise RuntimeError("Elasticsearch ping returned false")
    finally:
        client.close()


def main() -> int:
    checks = (
        ("kafka", _check_kafka),
        ("rabbitmq", _check_rabbitmq),
        ("influxdb", _check_influxdb),
        ("elasticsearch", _check_elasticsearch),
    )
    failed: list[str] = []
    for name, check in checks:
        try:
            check()
        except Exception as exc:
            failed.append(f"{name}: {type(exc).__name__}: {exc}")
    if failed:
        print("notification healthcheck failed: " + " | ".join(failed), file=sys.stderr)
        return 1
    print("notification healthcheck ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
