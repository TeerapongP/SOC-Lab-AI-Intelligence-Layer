from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DigestEntry:
    """Single alert entry buffered for daily digest."""

    risk_score: int
    source_ip: str
    mitre_tactic: str
    anomaly_type: str
    priority: str
    timestamp: str
    remediation: list[str] = field(default_factory=list)
