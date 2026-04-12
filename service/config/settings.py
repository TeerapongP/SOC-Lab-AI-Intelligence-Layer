from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

_SERVICE_DIR = Path(__file__).resolve().parents[1]
_WORKSPACE_DIR = Path(__file__).resolve().parents[2]

# Load service-local env first (primary), then workspace env as optional fallback.
load_dotenv(dotenv_path=_SERVICE_DIR / ".env")
load_dotenv(dotenv_path=_WORKSPACE_DIR / ".env")


def _require(key: str) -> str:
    value = os.getenv(key, "").strip()
    if not value:
        raise EnvironmentError(
            f"{key} is not set. Add it to .env or export {key}=<value>"
        )
    return value


def _normalize_bootstrap(raw: str) -> str:
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return ",".join(p.replace("localhost", "127.0.0.1") for p in parts) or "127.0.0.1:9092"


# ── Kafka ──────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP           = _normalize_bootstrap(os.getenv("KAFKA_BOOTSTRAP", "127.0.0.1:9092"))
KAFKA_INPUT_TOPIC         = os.getenv("KAFKA_INPUT_TOPIC",         "pa5220.raw")
KAFKA_OUTPUT_TOPIC        = os.getenv("KAFKA_OUTPUT_TOPIC",        "pa5220.enriched")
KAFKA_FEATURES_TOPIC      = os.getenv("KAFKA_FEATURES_TOPIC",      "pa5220.features")
KAFKA_GROUP_ID            = os.getenv("KAFKA_GROUP_ID",            "enrich-group")
KAFKA_FEATURES_GROUP_ID   = os.getenv("KAFKA_FEATURES_GROUP_ID",   "feature-group")
KAFKA_AUTO_OFFSET         = os.getenv("KAFKA_AUTO_OFFSET",         "earliest")
KAFKA_LINGER_MS           = int(os.getenv("KAFKA_LINGER_MS",       "20"))
KAFKA_RETRIES             = int(os.getenv("KAFKA_RETRIES",         "3"))
KAFKA_CONNECT_RETRIES     = int(os.getenv("KAFKA_CONNECT_RETRIES", "10"))

# ── OpenCTI ────────────────────────────────────────────────────────────────────
OPENCTI_URL               = os.getenv("OPENCTI_URL",              "http://localhost:8082")
OPENCTI_TOKEN             = _require("OPENCTI_TOKEN")
OPENCTI_CACHE_SIZE        = int(os.getenv("OPENCTI_CACHE_SIZE",   "5000"))

# ── Enrichment thresholds ──────────────────────────────────────────────────────
CONF_ATTACK_MIN           = float(os.getenv("CONF_ATTACK_MIN",    "0.70"))
CONF_NORMAL_MAX           = float(os.getenv("CONF_NORMAL_MAX",    "0.40"))

# ── Feature extractor ─────────────────────────────────────────────────────────
SCALER_PATH               = os.getenv("SCALER_PATH",              "models/minmax_scaler.pkl")
FEATURE_COLUMNS           = os.getenv(
    "FEATURE_COLUMNS",
    "bytes_per_session,login_velocity,geo_anomaly,failed_auth_ratio,beaconing_interval,"
    "ioc_confidence,ioc_type_enc,mitre_phase_enc,actor_known",
).split(",")

# ── RAG / Vector store ────────────────────────────────────────────────────────
CHROMA_HOST               = os.getenv("CHROMA_HOST",              "localhost")
CHROMA_PORT               = int(os.getenv("CHROMA_PORT",          "8000"))
CHROMA_COLLECTION         = os.getenv("CHROMA_COLLECTION",        "opencti_stix")
EMBED_MODEL               = os.getenv("EMBED_MODEL",              "sentence-transformers/all-MiniLM-L6-v2")
RAG_TOP_K                 = int(os.getenv("RAG_TOP_K",            "3"))
RAG_REINDEX_HOURS         = int(os.getenv("RAG_REINDEX_HOURS",    "24"))
BM25_WEIGHT               = float(os.getenv("BM25_WEIGHT",        "0.4"))
DENSE_WEIGHT              = float(os.getenv("DENSE_WEIGHT",       "0.6"))

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_LEVEL                 = os.getenv("LOG_LEVEL",                "INFO").upper()
LOG_KAFKA_LEVEL           = os.getenv("LOG_KAFKA_LEVEL",          "WARNING").upper()
