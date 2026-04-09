"""
label_builder.py — Layer 2: Weak Supervision Labeler
=====================================================
Consumes enriched records from Kafka (pa5220.enriched),
applies weak supervision rules, outputs labeled records to
pa5220.labeled for feature_extractor.py.

Label logic (matches diagram spec):
  conf >= 0.70  →  attack   (Known — CTI confirmed)
  conf <= 0.40  →  normal
  0.40 < conf < 0.70  →  unknown  (→ Unsupervised ML handles zero-days)

Also applies rule-based overrides from PA-5220 THREAT log fields
(severity + threat_name) when CTI confidence is low.

Environment:
  KAFKA_BOOTSTRAP         = localhost:9092
  KAFKA_ENRICHED_TOPIC    = pa5220.enriched
  KAFKA_LABELED_TOPIC     = pa5220.labeled
  KAFKA_GROUP_ID_LABEL    = label-group
"""

import os
import json
import logging
from dataclasses import dataclass, asdict
from kafka import KafkaConsumer, KafkaProducer
from dotenv import load_dotenv

load_dotenv()

KAFKA_BOOTSTRAP      = os.getenv("KAFKA_BOOTSTRAP",       "localhost:9092")
KAFKA_ENRICHED_TOPIC = os.getenv("KAFKA_ENRICHED_TOPIC",  "pa5220.enriched")
KAFKA_LABELED_TOPIC  = os.getenv("KAFKA_LABELED_TOPIC",   "pa5220.labeled")
KAFKA_GROUP_ID_LABEL = os.getenv("KAFKA_GROUP_ID_LABEL",  "label-group")

# Thresholds
CONF_ATTACK_MIN = 0.70
CONF_NORMAL_MAX = 0.40

# PA-5220 severity → confidence boost mapping
# Vendor signature provides weak signal when CTI is absent
SEVERITY_BOOST = {
    "critical": 0.80,
    "high":     0.65,
    "medium":   0.45,
    "low":      0.20,
    "info":     0.05,
}

# Known-bad threat name substrings (case-insensitive)
# Matched against PA-5220 threat_name field
THREAT_NAME_PATTERNS = [
    "brute", "credstuff", "exfil", "c2", "command-and-control",
    "backdoor", "trojan", "ransomware", "exploit", "scan",
    "botnet", "webshell", "mimikatz", "cobalt",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("label_builder")


@dataclass
class LabeledRecord:
    # Pass-through all EnrichedRecord fields
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

    ioc_confidence: float
    ioc_type: str
    mitre_phase: str
    actor_known: int
    actor_name: str
    campaign_name: str
    threat_name: str

    # Final label output
    y_label: str        # attack | normal | unknown
    label_source: str   # cti | severity_boost | threat_name | default
    sample_weight: float  # used in Random Forest fit(sample_weight=...)


def _threat_name_match(threat_name: str) -> bool:
    t = threat_name.lower()
    return any(p in t for p in THREAT_NAME_PATTERNS)


def build_label(rec: dict) -> LabeledRecord:
    """
    Apply weak supervision rules in priority order:
    1. CTI confidence (primary)
    2. PA-5220 severity boost (secondary — when CTI absent)
    3. PA-5220 threat_name pattern (tertiary)
    4. Default → normal
    """
    conf     = float(rec.get("ioc_confidence", 0.0))
    severity = rec.get("severity", "").lower()
    tname    = rec.get("threat_name", "")

    y_label      = "unknown"
    label_source = "default"
    sample_weight = 1.0

    # Priority 1 — CTI confidence
    if conf >= CONF_ATTACK_MIN:
        y_label       = "attack"
        label_source  = "cti"
        sample_weight = 1.0 + conf          # higher conf → higher weight in RF
    elif conf <= CONF_NORMAL_MAX:
        y_label       = "normal"
        label_source  = "cti"
        sample_weight = 1.0

    # Priority 2 — PA-5220 severity boost (only when CTI grey zone or absent)
    elif severity and severity in SEVERITY_BOOST:
        boosted_conf = SEVERITY_BOOST[severity]
        if boosted_conf >= CONF_ATTACK_MIN:
            y_label       = "attack"
            label_source  = "severity_boost"
            sample_weight = 0.7             # vendor signature less reliable → down-weight
        elif boosted_conf <= CONF_NORMAL_MAX:
            y_label       = "normal"
            label_source  = "severity_boost"
            sample_weight = 0.8
        else:
            y_label       = "unknown"
            label_source  = "severity_boost"
            sample_weight = 0.5

    # Priority 3 — Threat name pattern match
    elif tname and _threat_name_match(tname):
        y_label       = "attack"
        label_source  = "threat_name"
        sample_weight = 0.6                 # weakest signal → lowest weight

    # Priority 4 — Default
    else:
        y_label       = "normal"
        label_source  = "default"
        sample_weight = 0.5

    return LabeledRecord(
        src_ip           = rec.get("src_ip", ""),
        dst_ip           = rec.get("dst_ip", ""),
        src_port         = int(rec.get("src_port", 0)),
        dst_port         = int(rec.get("dst_port", 0)),
        bytes_sent       = float(rec.get("bytes_sent", 0)),
        bytes_recv       = float(rec.get("bytes_recv", 0)),
        packets          = int(rec.get("packets", 0)),
        session_duration = float(rec.get("session_duration", 0)),
        action           = rec.get("action", ""),
        app              = rec.get("app", ""),
        rule             = rec.get("rule", ""),
        timestamp        = rec.get("timestamp", ""),
        ioc_confidence   = float(rec.get("ioc_confidence", 0)),
        ioc_type         = rec.get("ioc_type", "none"),
        mitre_phase      = rec.get("mitre_phase", "none"),
        actor_known      = int(rec.get("actor_known", 0)),
        actor_name       = rec.get("actor_name", ""),
        campaign_name    = rec.get("campaign_name", ""),
        threat_name      = tname,
        y_label          = y_label,
        label_source     = label_source,
        sample_weight    = round(sample_weight, 4),
    )


def label_distribution(counts: dict) -> str:
    total = sum(counts.values()) or 1
    return "  ".join(
        f"{k}={v} ({v/total*100:.1f}%)" for k, v in sorted(counts.items())
    )


def main():
    consumer = KafkaConsumer(
        KAFKA_ENRICHED_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=KAFKA_GROUP_ID_LABEL,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
    )
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        retries=3,
        linger_ms=20,
    )

    counts    = {"attack": 0, "normal": 0, "unknown": 0}
    processed = 0

    log.info("Starting label builder loop...")

    for message in consumer:
        rec: dict = message.value
        try:
            labeled = build_label(rec)
            counts[labeled.y_label] += 1
            producer.send(KAFKA_LABELED_TOPIC, value=asdict(labeled))
            processed += 1

            if processed % 5_000 == 0:
                log.info("processed=%d  %s", processed, label_distribution(counts))

        except Exception as exc:
            log.error("Error labeling record: %s — %s", rec, exc)


if __name__ == "__main__":
    main()
