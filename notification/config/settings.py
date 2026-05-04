from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List

from dotenv import load_dotenv

_NOTIFICATION_DIR = Path(__file__).resolve().parents[1]
_WORKSPACE_DIR = Path(__file__).resolve().parents[2]

load_dotenv(_NOTIFICATION_DIR / ".env")
load_dotenv(_WORKSPACE_DIR / ".env")


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
            cleaned = raw.strip("[]")
            return [x.strip().strip('"').strip("'") for x in cleaned.split(",") if x.strip()]
    return [x.strip() for x in raw.split(",") if x.strip()]


class _Settings:
    # Kafka
    KAFKA_BOOTSTRAP: str = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
    KAFKA_LLM_OUTPUT_TOPIC: str = os.getenv("KAFKA_LLM_OUTPUT_TOPIC", "pa5220.llm_output")
    KAFKA_LLM_DLQ_TOPIC: str = os.getenv("KAFKA_LLM_DLQ_TOPIC", "pa5220.llm_output.dlq")
    KAFKA_DISPATCHER_GROUP: str = os.getenv("KAFKA_DISPATCHER_GROUP", "alert-dispatcher")
    KAFKA_AUTO_OFFSET: str = os.getenv("KAFKA_AUTO_OFFSET", "latest")
    KAFKA_CONNECT_RETRIES: int = int(os.getenv("KAFKA_CONNECT_RETRIES", "10"))

    # LINE Messaging API
    LINE_CHANNEL_ACCESS_TOKEN: str = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
    LINE_GRAFANA_BASE_URL: str = os.getenv("LINE_GRAFANA_BASE_URL", "http://localhost:3000")

    # RabbitMQ EventBus
    RABBITMQ_URL: str = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    RABBITMQ_EXCHANGE: str = os.getenv("RABBITMQ_EXCHANGE", "soc.alerts")

    # InfluxDB
    INFLUX_URL: str = os.getenv("INFLUX_URL", "http://localhost:8086")
    INFLUX_TOKEN: str = os.getenv("INFLUX_TOKEN", "")
    INFLUX_ORG: str = os.getenv("INFLUX_ORG", "soc")
    INFLUX_BUCKET: str = os.getenv("INFLUX_BUCKET", "alerts")

    # Elasticsearch
    ELASTIC_URL: str = os.getenv("ELASTIC_URL", "http://localhost:9200")
    ELASTIC_API_KEY: str = os.getenv("ELASTIC_API_KEY", "")
    ELASTIC_ALERT_INDEX: str = os.getenv("ELASTIC_ALERT_INDEX", "soc-alerts")

    # Grafana
    GRAFANA_URL: str = os.getenv("GRAFANA_URL", "http://localhost:3000")


settings = _Settings()
