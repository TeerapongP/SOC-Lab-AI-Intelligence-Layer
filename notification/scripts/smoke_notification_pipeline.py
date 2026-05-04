from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone

import requests
from kafka import KafkaConsumer, KafkaProducer

from notification.config import settings


def _send_raw(topic: str, value: str) -> None:
    producer = KafkaProducer(
        bootstrap_servers=settings.KAFKA_BOOTSTRAP,
        value_serializer=lambda message: message.encode("utf-8"),
        linger_ms=10,
    )
    try:
        producer.send(topic, value).get(timeout=15)
        producer.flush(timeout=10)
    finally:
        producer.close()


def _wait_for_elastic_doc(alert_id: str, timeout_s: int = 45) -> dict:
    api_key = os.getenv("ELASTIC_READER_API_KEY", "").strip() or settings.ELASTIC_API_KEY
    if not api_key:
        raise RuntimeError("ELASTIC_READER_API_KEY or ELASTIC_API_KEY is required for smoke verification")

    headers = {"Authorization": f"ApiKey {api_key}"}
    url = f"{settings.ELASTIC_URL.rstrip('/')}/{settings.ELASTIC_ALERT_INDEX}/_doc/{alert_id}"
    deadline = time.time() + timeout_s
    last_status = None
    while time.time() < deadline:
        response = requests.get(url, headers=headers, timeout=10)
        last_status = response.status_code
        if response.status_code == 200 and response.json().get("found"):
            return response.json()
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for Elasticsearch doc {alert_id}; last_status={last_status}")


def _wait_for_dlq(marker: str, timeout_s: int = 45) -> dict:
    _send_raw(settings.KAFKA_LLM_OUTPUT_TOPIC, marker)
    consumer = KafkaConsumer(
        settings.KAFKA_LLM_DLQ_TOPIC,
        bootstrap_servers=settings.KAFKA_BOOTSTRAP,
        group_id=f"notification-smoke-{uuid.uuid4()}",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
    )
    try:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            records = consumer.poll(timeout_ms=2000)
            for messages in records.values():
                for message in messages:
                    if message.value.get("raw_value") == marker:
                        return message.value
        raise RuntimeError(f"Timed out waiting for DLQ marker {marker!r}")
    finally:
        consumer.close()


def main() -> int:
    alert_id = f"smoke-notification-{uuid.uuid4().hex[:12]}"
    payload = {
        "alert_id": alert_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "10.255.0.20",
        "dst_port": 443,
        "priority": "LOW",
        "risk_score": 12,
        "anomaly_type": "smoke-test",
        "mitre_tactic": "test",
        "mitre_technique": "",
        "model_used": "smoke",
        "explanation_th": "ทดสอบ notification pipeline แบบไม่ผ่าน LLM/ML",
        "remediation": ["no action"],
        "top_3_features": ["smoke"],
        "faithfulness_score": 1.0,
        "response_ms": 1,
    }
    _send_raw(settings.KAFKA_LLM_OUTPUT_TOPIC, json.dumps(payload, ensure_ascii=False))
    doc = _wait_for_elastic_doc(alert_id)

    marker = f"not-json-smoke-{uuid.uuid4().hex[:12]}"
    dlq_record = _wait_for_dlq(marker)

    print("notification smoke ok")
    print(f"alert_id={doc['_source']['alert_id']}")
    print(f"dlq_stage={dlq_record['stage']}")
    print(f"dlq_error_type={dlq_record['error_type']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
