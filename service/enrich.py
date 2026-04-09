import os
import json
import logging
import time
from typing import Optional
from dataclasses import dataclass, asdict

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable
from pycti import OpenCTIApiClient
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP    = os.getenv("KAFKA_BOOTSTRAP",    "localhost:9092")
KAFKA_INPUT_TOPIC  = os.getenv("KAFKA_INPUT_TOPIC",  "pa5220.raw")
KAFKA_OUTPUT_TOPIC = os.getenv("KAFKA_OUTPUT_TOPIC", "pa5220.enriched")
KAFKA_GROUP_ID     = os.getenv("KAFKA_GROUP_ID",     "enrich-group")
OPENCTI_URL        = os.getenv("OPENCTI_URL",        "http://localhost:8080")
OPENCTI_TOKEN      = os.getenv("OPENCTI_TOKEN",      "")

# Pre-filter: skip IPs that are always noisy (RFC-1918 + loopback)
NOISY_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                  "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                  "172.30.", "172.31.", "192.168.", "127.", "0.")

# Confidence thresholds (matches label_builder.py)
CONF_ATTACK_MIN = 0.70
CONF_NORMAL_MAX = 0.40

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("enrich")


# ── Data structures ───────────────────────────────────────────────────────────
@dataclass
class EnrichedRecord:
    # Original PA-5220 fields (pass-through)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    bytes_sent: float
    bytes_recv: float
    packets: int
    session_duration: float
    action: str
    app: str
    rule: str
    timestamp: str

    # CTI enrichment (4 ML features)
    ioc_confidence: float   = 0.0   # 0.0–1.0
    ioc_type: str           = "none" # ipv4-addr | domain-name | url | file | none
    mitre_phase: str        = "none" # e.g. initial-access, lateral-movement
    actor_known: int        = 0      # 1 = known threat actor, 0 = unknown

    # Extra context (not ML features — used for LLM prompt)
    actor_name: str         = ""
    campaign_name: str      = ""
    threat_name: str        = ""

    # Weak label (set by label_builder.py downstream, pre-filled here)
    weak_label: str         = "unknown"  # attack | normal | unknown


# ── OpenCTI client wrapper ────────────────────────────────────────────────────
class CTIClient:
    """
    Thin wrapper around pycti with in-process LRU cache.
    Cache avoids hammering OpenCTI for repeated IPs (PA-5220 logs
    often repeat the same src_ip thousands of times per hour).
    """

    def __init__(self, url: str, token: str, cache_size: int = 5_000):
        self._client = OpenCTIApiClient(url, token, log_level="error")
        self._cache: dict = {}
        self._cache_size = cache_size
        log.info("Connected to OpenCTI at %s", url)

    def _evict_if_full(self):
        if len(self._cache) >= self._cache_size:
            # Remove oldest 10% — simple FIFO eviction
            remove = list(self._cache.keys())[: self._cache_size // 10]
            for k in remove:
                del self._cache[k]

    def lookup(self, ip: str) -> dict:
        """
        Query OpenCTI for an IP indicator.
        Returns dict with confidence, ioc_type, mitre_phase,
        actor_known, actor_name, campaign_name, threat_name.
        """
        if ip in self._cache:
            return self._cache[ip]

        result = {
            "confidence": 0.0,
            "ioc_type":   "none",
            "mitre_phase": "none",
            "actor_known": 0,
            "actor_name":  "",
            "campaign_name": "",
            "threat_name": "",
        }

        try:
            indicators = self._client.indicator.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [ip]}],
                    "filterGroups": [],
                },
                first=1,
            )

            if not indicators or not indicators.get("edges"):
                self._evict_if_full()
                self._cache[ip] = result
                return result

            node = indicators["edges"][0]["node"]
            conf_raw = node.get("confidence", 0) or 0
            result["confidence"] = round(min(conf_raw / 100.0, 1.0), 4)
            result["ioc_type"]   = node.get("indicator_types", ["none"])[0] if node.get("indicator_types") else "none"

            # Graph walk — get related kill-chain phases
            kill_chains = node.get("killChainPhases", {}).get("edges", [])
            if kill_chains:
                result["mitre_phase"] = kill_chains[0]["node"].get("phase_name", "none")

            # Graph walk — get related threat actors
            relations = self._client.stix_core_relationship.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "fromId", "values": [node["id"]]},
                        {"key": "relationship_type", "values": ["attributed-to", "indicates"]},
                    ],
                    "filterGroups": [],
                },
                first=3,
            )
            if relations and relations.get("edges"):
                for edge in relations["edges"]:
                    related = edge["node"].get("to", {})
                    entity_type = related.get("entity_type", "")
                    if entity_type == "Threat-Actor":
                        result["actor_known"] = 1
                        result["actor_name"]  = related.get("name", "")
                    elif entity_type == "Campaign":
                        result["campaign_name"] = related.get("name", "")
                    elif entity_type == "Malware":
                        result["threat_name"] = related.get("name", "")

        except Exception as exc:
            log.warning("OpenCTI lookup failed for %s: %s", ip, exc)

        self._evict_if_full()
        self._cache[ip] = result
        return result


# ── Pre-filter ────────────────────────────────────────────────────────────────
def is_noisy(ip: str) -> bool:
    """Return True for RFC-1918 / loopback IPs — skip CTI lookup."""
    return any(ip.startswith(prefix) for prefix in NOISY_PREFIXES)


# ── Enrichment logic ─────────────────────────────────────────────────────────
def enrich(raw: dict, cti: CTIClient) -> EnrichedRecord:
    """
    Build an EnrichedRecord from a raw PA-5220 log dict.
    Checks dst_ip first (destination is usually the target),
    then src_ip as fallback.
    """
    rec = EnrichedRecord(
        src_ip           = raw.get("src_ip", ""),
        dst_ip           = raw.get("dst_ip", ""),
        src_port         = int(raw.get("src_port", 0)),
        dst_port         = int(raw.get("dst_port", 0)),
        bytes_sent       = float(raw.get("bytes_sent", 0)),
        bytes_recv       = float(raw.get("bytes_recv", 0)),
        packets          = int(raw.get("packets", 0)),
        session_duration = float(raw.get("session_duration", 0)),
        action           = raw.get("action", ""),
        app              = raw.get("app", ""),
        rule             = raw.get("rule", ""),
        timestamp        = raw.get("timestamp", ""),
    )

    # Try dst_ip first, then src_ip
    for ip in [rec.dst_ip, rec.src_ip]:
        if not ip or is_noisy(ip):
            continue
        cti_result = cti.lookup(ip)
        if cti_result["confidence"] > 0:
            rec.ioc_confidence  = cti_result["confidence"]
            rec.ioc_type        = cti_result["ioc_type"]
            rec.mitre_phase     = cti_result["mitre_phase"]
            rec.actor_known     = cti_result["actor_known"]
            rec.actor_name      = cti_result["actor_name"]
            rec.campaign_name   = cti_result["campaign_name"]
            rec.threat_name     = cti_result["threat_name"]
            break  # Use first match

    # Pre-fill weak label (label_builder.py will override with full logic)
    if rec.ioc_confidence >= CONF_ATTACK_MIN:
        rec.weak_label = "attack"
    elif rec.ioc_confidence <= CONF_NORMAL_MAX:
        rec.weak_label = "normal"
    else:
        rec.weak_label = "unknown"  # Grey zone → Unsupervised ML

    return rec


# ── Kafka helpers ─────────────────────────────────────────────────────────────
def make_consumer(retries: int = 10) -> KafkaConsumer:
    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                KAFKA_INPUT_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=KAFKA_GROUP_ID,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            )
            log.info("Kafka consumer ready (topic=%s)", KAFKA_INPUT_TOPIC)
            return consumer
        except NoBrokersAvailable:
            log.warning("Kafka not ready — attempt %d/%d, retrying in 5s", attempt, retries)
            time.sleep(5)
    raise RuntimeError("Cannot connect to Kafka after %d attempts" % retries)


def make_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",           # wait for all replicas
        retries=3,
        linger_ms=20,         # small batching window
    )


# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    if not OPENCTI_TOKEN:
        raise EnvironmentError(
            "OPENCTI_TOKEN is not set. "
            "Add it to .env or export OPENCTI_TOKEN=<token>"
        )

    cti      = CTIClient(OPENCTI_URL, OPENCTI_TOKEN)
    consumer = make_consumer()
    producer = make_producer()

    processed = 0
    skipped   = 0
    errors    = 0

    log.info("Starting enrichment loop...")

    for message in consumer:
        raw: dict = message.value
        try:
            enriched = enrich(raw, cti)
            producer.send(KAFKA_OUTPUT_TOPIC, value=asdict(enriched))
            processed += 1

            if processed % 1_000 == 0:
                log.info(
                    "processed=%d  skipped=%d  errors=%d  cache_size=%d",
                    processed, skipped, errors, len(cti._cache),
                )

        except (KeyError, ValueError) as exc:
            skipped += 1
            log.debug("Skipped malformed record: %s — %s", raw, exc)
        except Exception as exc:
            errors += 1
            log.error("Unexpected error on record %s: %s", raw, exc)


if __name__ == "__main__":
    main()
