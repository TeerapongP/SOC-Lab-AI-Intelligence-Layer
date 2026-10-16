from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EnrichedRecord:
    """PA-5220 firewall log enriched with OpenCTI threat intelligence."""
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


    ioc_confidence: float = 0.0
    ioc_type:       str   = "none"
    mitre_phase:    str   = "none"
    actor_known:    int   = 0


    actor_name:    str = ""
    campaign_name: str = ""
    threat_name:   str = ""


    weak_label: str = "unknown"


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
