from __future__ import annotations

from dataclasses import asdict

from enrich.cti.client import CTIClient
from enrich.label.builder import apply_label
from enrich.models import EnrichedRecord
from enrich.utils.ip import is_routable


def enrich_record(raw: dict, cti: CTIClient) -> EnrichedRecord:
    """
    Build an EnrichedRecord from a raw PA-5220 log dict.

    CTI lookup strategy:
      1. Try dst_ip first (destination is usually the target).
      2. Fall back to src_ip if dst_ip yields no signal.
      3. Skip RFC-1918 / loopback addresses entirely.
    """
    rec = EnrichedRecord(
        src_ip           = raw.get("src_ip",           ""),
        dst_ip           = raw.get("dst_ip",           ""),
        src_port         = int(raw.get("src_port",         0)),
        dst_port         = int(raw.get("dst_port",         0)),
        bytes_sent       = float(raw.get("bytes_sent",     0)),
        bytes_recv       = float(raw.get("bytes_recv",     0)),
        packets          = int(raw.get("packets",          0)),
        session_duration = float(raw.get("session_duration", 0)),
        action           = raw.get("action",           ""),
        app              = raw.get("app",              ""),
        rule             = raw.get("rule",             ""),
        timestamp        = raw.get("timestamp",        ""),
    )

    for ip in (rec.dst_ip, rec.src_ip):
        if not is_routable(ip):
            continue
        cti_result = cti.lookup(ip)
        if cti_result.has_signal:
            rec.ioc_confidence = cti_result.confidence
            rec.ioc_type       = cti_result.ioc_type
            rec.mitre_phase    = cti_result.mitre_phase
            rec.actor_known    = cti_result.actor_known
            rec.actor_name     = cti_result.actor_name
            rec.campaign_name  = cti_result.campaign_name
            rec.threat_name    = cti_result.threat_name
            break

    return apply_label(rec)


def to_dict(rec: EnrichedRecord) -> dict:
    return asdict(rec)
