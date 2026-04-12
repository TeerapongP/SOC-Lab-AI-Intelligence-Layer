from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

_SERVICE_DIR = Path(__file__).resolve().parents[2]
_WORKSPACE_DIR = Path(__file__).resolve().parents[3]

load_dotenv(dotenv_path=_SERVICE_DIR / ".env")
load_dotenv(dotenv_path=_WORKSPACE_DIR / ".env")
load_dotenv(dotenv_path=_WORKSPACE_DIR / "opencti" / ".env")


def _require(key: str) -> str:
    value = os.getenv(key, "").strip()
    if not value:
        raise EnvironmentError(f"{key} is not set. Add it to .env or export {key}=<value>")
    return value


def _normalize_bootstrap(raw: str) -> str:
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return ",".join(p.replace("localhost", "127.0.0.1") for p in parts) or "127.0.0.1:9092"


# ── Kafka ──────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP          = _normalize_bootstrap(os.getenv("KAFKA_BOOTSTRAP",        "127.0.0.1:9092"))
KAFKA_LLM_OUTPUT_TOPIC   = os.getenv("KAFKA_LLM_OUTPUT_TOPIC",  "pa5220.llm_output")
KAFKA_DISPATCHER_GROUP   = os.getenv("KAFKA_DISPATCHER_GROUP",  "dispatcher-group")
KAFKA_AUTO_OFFSET        = os.getenv("KAFKA_AUTO_OFFSET",       "earliest")
KAFKA_LINGER_MS          = int(os.getenv("KAFKA_LINGER_MS",     "20"))
KAFKA_RETRIES            = int(os.getenv("KAFKA_RETRIES",       "3"))
KAFKA_CONNECT_RETRIES    = int(os.getenv("KAFKA_CONNECT_RETRIES", "10"))

# ── RabbitMQ event bus ────────────────────────────────────────────────────────
_RABBITMQ_DEFAULT_USER   = os.getenv("RABBITMQ_DEFAULT_USER", "guest")
_RABBITMQ_DEFAULT_PASS   = os.getenv("RABBITMQ_DEFAULT_PASS", "guest")
RABBITMQ_URL             = os.getenv(
    "RABBITMQ_URL",
    f"amqp://{_RABBITMQ_DEFAULT_USER}:{_RABBITMQ_DEFAULT_PASS}@localhost:5672/",
)
RABBITMQ_EXCHANGE        = os.getenv("RABBITMQ_EXCHANGE",       "soc.events")
RABBITMQ_HIGH_ROUTING    = os.getenv("RABBITMQ_HIGH_ROUTING",   "alert.high")
RABBITMQ_MEDIUM_ROUTING  = os.getenv("RABBITMQ_MEDIUM_ROUTING", "alert.medium")
RABBITMQ_LOW_ROUTING     = os.getenv("RABBITMQ_LOW_ROUTING",    "alert.low")
RABBITMQ_METRICS_ROUTING = os.getenv("RABBITMQ_METRICS_ROUTING","metrics.layer")

# ── InfluxDB ──────────────────────────────────────────────────────────────────
INFLUX_URL               = os.getenv("INFLUX_URL",              "http://localhost:8086")
INFLUX_TOKEN             = os.getenv("INFLUX_TOKEN", "")
INFLUX_ORG               = os.getenv("INFLUX_ORG",              "soc")
INFLUX_BUCKET            = os.getenv("INFLUX_BUCKET",           "soc_metrics")
INFLUX_RETENTION_DAYS    = int(os.getenv("INFLUX_RETENTION_DAYS", "90"))

# ── Line Notify ───────────────────────────────────────────────────────────────
LINE_NOTIFY_TOKEN        = os.getenv("LINE_NOTIFY_TOKEN", "")
LINE_NOTIFY_URL          = os.getenv("LINE_NOTIFY_URL",         "https://notify-api.line.me/api/notify")
LINE_GRAFANA_BASE_URL    = os.getenv("LINE_GRAFANA_BASE_URL",   "http://localhost:3000")

# ── Outlook / Microsoft Graph ─────────────────────────────────────────────────
OUTLOOK_TENANT_ID        = os.getenv("OUTLOOK_TENANT_ID", "")
OUTLOOK_CLIENT_ID        = os.getenv("OUTLOOK_CLIENT_ID", "")
OUTLOOK_CLIENT_SECRET    = os.getenv("OUTLOOK_CLIENT_SECRET", "")
OUTLOOK_SENDER_EMAIL     = os.getenv("OUTLOOK_SENDER_EMAIL", "")
OUTLOOK_RECIPIENT_EMAILS = [
    e.strip() for e in os.getenv("OUTLOOK_RECIPIENT_EMAILS", "").split(",") if e.strip()
]
OUTLOOK_DIGEST_HOUR      = int(os.getenv("OUTLOOK_DIGEST_HOUR", "8"))   # 08:00 daily

# ── Priority thresholds ───────────────────────────────────────────────────────
RISK_HIGH_MIN            = int(os.getenv("RISK_HIGH_MIN",   "70"))
RISK_MEDIUM_MIN          = int(os.getenv("RISK_MEDIUM_MIN", "40"))

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_LEVEL                = os.getenv("LOG_LEVEL",       "INFO").upper()
LOG_KAFKA_LEVEL          = os.getenv("LOG_KAFKA_LEVEL", "WARNING").upper()
