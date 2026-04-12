from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EnrichedRecord:
    """PA-5220 firewall log enriched with OpenCTI threat intelligence."""

    # ── Original PA-5220 fields (pass-through) ─────────────────────────────────
    src_ip:           str
    dst_ip:           str
    src_port:         int
    dst_port:         int
    bytes_sent:       float
    bytes_recv:       float
    packets:          int
    session_duration: float
    action:           str
    app:              str
    rule:             str
    timestamp:        str

    # ── CTI enrichment (ML features) ───────────────────────────────────────────
    ioc_confidence: float = 0.0     # 0.0–1.0
    ioc_type:       str   = "none"  # ipv4-addr | domain-name | url | file | none
    mitre_phase:    str   = "none"  # e.g. initial-access, lateral-movement
    actor_known:    int   = 0       # 1 = known threat actor, 0 = unknown

    # ── Extra context (for LLM prompt, not ML features) ────────────────────────
    actor_name:    str = ""
    campaign_name: str = ""
    threat_name:   str = ""

    # ── Weak label ─────────────────────────────────────────────────────────────
    weak_label: str = "unknown"     # attack | normal | unknown


@dataclass
class CTIResult:
    """Normalised result from an OpenCTI indicator lookup."""

    confidence:    float = 0.0
    ioc_type:      str   = "none"
    mitre_phase:   str   = "none"
    actor_known:   int   = 0
    actor_name:    str   = ""
    campaign_name: str   = ""
    threat_name:   str   = ""

    @property
    def has_signal(self) -> bool:
        return self.confidence > 0.0
