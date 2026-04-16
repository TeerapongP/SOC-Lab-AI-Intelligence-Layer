from __future__ import annotations

import json
import os
from typing import List


def _list(key: str, default: str = "") -> List[str]:
    """Parse JSON array or comma-separated string from env."""
    raw = os.getenv(key, default).strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except json.JSONDecodeError:
            # Fall back to tolerant parsing when JSON is malformed.
            cleaned = raw.strip("[]")
            return [x.strip().strip('"').strip("'") for x in cleaned.split(",") if x.strip()]
    return [x.strip() for x in raw.split(",") if x.strip()]


class _Settings:
    # ── Kafka ──────────────────────────────────────────────────────────────────
    KAFKA_BOOTSTRAP:            str       = os.getenv("KAFKA_BOOTSTRAP",            "localhost:9092")
    KAFKA_LLM_OUTPUT_TOPIC:     str       = os.getenv("KAFKA_LLM_OUTPUT_TOPIC",     "pa5220.llm_output")
    KAFKA_DISPATCHER_GROUP:     str       = os.getenv("KAFKA_DISPATCHER_GROUP",     "alert-dispatcher")
    KAFKA_AUTO_OFFSET:          str       = os.getenv("KAFKA_AUTO_OFFSET",          "latest")
    KAFKA_CONNECT_RETRIES:      int       = int(os.getenv("KAFKA_CONNECT_RETRIES",  "10"))

    # ── LINE Messaging API ─────────────────────────────────────────────────────
    # LINE Notify ปิดบริการ 31 มี.ค. 2568 → ใช้ Messaging API แทน
    LINE_CHANNEL_ACCESS_TOKEN:  str       = os.getenv("LINE_CHANNEL_ACCESS_TOKEN",  "")
    LINE_GRAFANA_BASE_URL:      str       = os.getenv("LINE_GRAFANA_BASE_URL",      "http://localhost:3000")

    # ── Shuffle SOAR webhooks ─────────────────────────────────────────────────
    SHUFFLE_WEBHOOK_HIGH:       str       = os.getenv("SHUFFLE_WEBHOOK_HIGH",       "")
    SHUFFLE_WEBHOOK_MEDIUM:     str       = os.getenv("SHUFFLE_WEBHOOK_MEDIUM",     "")
    SHUFFLE_WEBHOOK_LOW:        str       = os.getenv("SHUFFLE_WEBHOOK_LOW",        "")
    SHUFFLE_WEBHOOK_DIGEST:     str       = os.getenv("SHUFFLE_WEBHOOK_DIGEST",     "")

    # ── Azure / Microsoft Graph ────────────────────────────────────────────────
    OUTLOOK_TENANT_ID:          str       = os.getenv("OUTLOOK_TENANT_ID",          "")
    OUTLOOK_CLIENT_ID:          str       = os.getenv("OUTLOOK_CLIENT_ID",          "")
    OUTLOOK_CLIENT_SECRET:      str       = os.getenv("OUTLOOK_CLIENT_SECRET",      "")
    OUTLOOK_SENDER_EMAIL:       str       = os.getenv("OUTLOOK_SENDER_EMAIL",       "")
    OUTLOOK_RECIPIENT_EMAILS:   List[str] = _list("OUTLOOK_RECIPIENT_EMAILS")
    OUTLOOK_DIGEST_HOUR:        int       = int(os.getenv("OUTLOOK_DIGEST_HOUR",    "8"))  # UTC

    # ── RabbitMQ (EventBus) ────────────────────────────────────────────────────
    RABBITMQ_URL:               str       = os.getenv("RABBITMQ_URL",               "amqp://guest:guest@localhost:5672/")
    RABBITMQ_EXCHANGE:          str       = os.getenv("RABBITMQ_EXCHANGE",          "soc.alerts")

    # ── InfluxDB ───────────────────────────────────────────────────────────────
    INFLUX_URL:                 str       = os.getenv("INFLUX_URL",                 "http://localhost:8086")
    INFLUX_TOKEN:               str       = os.getenv("INFLUX_TOKEN",               "")
    INFLUX_ORG:                 str       = os.getenv("INFLUX_ORG",                 "soc")
    INFLUX_BUCKET:              str       = os.getenv("INFLUX_BUCKET",              "alerts")

    # ── Elasticsearch ──────────────────────────────────────────────────────────
    ELASTIC_URL:                str       = os.getenv("ELASTIC_URL",                "http://localhost:9200")
    ELASTIC_API_KEY:            str       = os.getenv("ELASTIC_API_KEY",            "")
    ELASTIC_ALERT_INDEX:        str       = os.getenv("ELASTIC_ALERT_INDEX",        "soc-alerts")

    # ── Grafana ────────────────────────────────────────────────────────────────
    GRAFANA_URL:                str       = os.getenv("GRAFANA_URL",                "http://localhost:3000")


settings = _Settings()
