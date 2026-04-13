from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Priority(Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"

    @classmethod
    def from_str(cls, value: str) -> "Priority":
        try:
            return cls(value.upper())
        except ValueError:
            raise ValueError(f"Invalid priority: {value!r}. Must be HIGH / MEDIUM / LOW")


@dataclass
class LLMAlert:
    """
    Parsed output from pa5220.llm_output Kafka topic.
    All fields map 1-to-1 with the JSON schema produced by the LLM layer.
    """

    # ── Identity ───────────────────────────────────────────────────────────────
    alert_id:          str
    timestamp:         str           # ISO-8601 UTC

    # ── Network ───────────────────────────────────────────────────────────────
    source_ip:         str
    dst_port:          int

    # ── Classification ────────────────────────────────────────────────────────
    priority:          Priority
    risk_score:        int           # 0–100
    anomaly_type:      str           # e.g. "BruteForce", "C2", "Exfil"
    mitre_tactic:      str           # e.g. "Credential Access"
    mitre_technique:   str           # e.g. "T1110"
    model_used:        str           # e.g. "ensemble", "isolation_forest"

    # ── LLM output ────────────────────────────────────────────────────────────
    explanation_th:    str           # Thai explanation (2+ sentences)
    remediation:       list[str]     # ordered remediation steps
    top_3_features:    list[str]     # top SHAP features

    # ── Quality metrics ───────────────────────────────────────────────────────
    faithfulness_score: float        # RAG faithfulness 0.0–1.0
    response_ms:        int          # LLM inference latency ms

    # ── Optional ──────────────────────────────────────────────────────────────
    mttd_s:            float | None = None   # Mean Time To Detect (seconds)
    actor_known:       bool         = False
    ioc_confidence:    float        = 0.0

    # ── Extra fields (forward-compat) ─────────────────────────────────────────
    extra:             dict[str, Any] = field(default_factory=dict)

    # ── Constructor ───────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LLMAlert":
        """
        Deserialize from Kafka message value (JSON dict).
        Raises KeyError if required fields are missing.
        Raises ValueError if priority or types are invalid.
        """
        known_fields = {
            "alert_id", "timestamp", "source_ip", "dst_port",
            "priority", "risk_score", "anomaly_type", "mitre_tactic",
            "mitre_technique", "model_used", "explanation_th",
            "remediation", "top_3_features", "faithfulness_score",
            "response_ms", "mttd_s", "actor_known", "ioc_confidence",
        }
        extra = {k: v for k, v in data.items() if k not in known_fields}

        return cls(
            alert_id          = str(data["alert_id"]),
            timestamp         = str(data["timestamp"]),
            source_ip         = str(data["source_ip"]),
            dst_port          = int(data["dst_port"]),
            priority          = Priority.from_str(data["priority"]),
            risk_score        = int(data["risk_score"]),
            anomaly_type      = str(data["anomaly_type"]),
            mitre_tactic      = str(data["mitre_tactic"]),
            mitre_technique   = str(data.get("mitre_technique", "")),
            model_used        = str(data.get("model_used", "ensemble")),
            explanation_th    = str(data["explanation_th"]),
            remediation       = list(data.get("remediation", [])),
            top_3_features    = list(data.get("top_3_features", [])),
            faithfulness_score= float(data.get("faithfulness_score", 0.0)),
            response_ms       = int(data.get("response_ms", 0)),
            mttd_s            = float(data["mttd_s"]) if data.get("mttd_s") is not None else None,
            actor_known       = bool(data.get("actor_known", False)),
            ioc_confidence    = float(data.get("ioc_confidence", 0.0)),
            extra             = extra,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize back to dict (for Elasticsearch / EventBus)."""
        return {
            "alert_id":           self.alert_id,
            "timestamp":          self.timestamp,
            "source_ip":          self.source_ip,
            "dst_port":           self.dst_port,
            "priority":           self.priority.value,
            "risk_score":         self.risk_score,
            "anomaly_type":       self.anomaly_type,
            "mitre_tactic":       self.mitre_tactic,
            "mitre_technique":    self.mitre_technique,
            "model_used":         self.model_used,
            "explanation_th":     self.explanation_th,
            "remediation":        self.remediation,
            "top_3_features":     self.top_3_features,
            "faithfulness_score": self.faithfulness_score,
            "response_ms":        self.response_ms,
            "mttd_s":             self.mttd_s,
            "actor_known":        self.actor_known,
            "ioc_confidence":     self.ioc_confidence,
            **self.extra,
        }
