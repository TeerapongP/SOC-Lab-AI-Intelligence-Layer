from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Priority(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


@dataclass
class LLMAlert:
    """
    Structured output from Llama/DeepSeek LLM (JSON · ภาษาไทย).
    Matches ml_out → llm → llm_out in the diagram.
    """
    # ── ML fields (pass-through from ML layer) ─────────────────────────────────
    risk_score:          int           # 0–100
    anomaly_type:        str
    top_3_features:      list[str]
    source_ip:           str
    dst_port:            int
    model_used:          str
    ensemble_confidence: float
    timestamp:           str

    # ── LLM structured output ─────────────────────────────────────────────────
    priority:            Priority
    explanation_th:      str           # Thai explanation
    mitre_tactic:        str
    affected_asset:      str
    remediation:         list[str]     # [step1, step2, step3]

    # ── LLM quality metrics ───────────────────────────────────────────────────
    faithfulness_score:  float = 0.0
    hallucination_rate:  float = 0.0
    response_ms:         int   = 0

    @classmethod
    def from_dict(cls, d: dict) -> "LLMAlert":
        return cls(
            risk_score          = int(d.get("risk_score", 0)),
            anomaly_type        = d.get("anomaly_type", ""),
            top_3_features      = d.get("top_3_features", []),
            source_ip           = d.get("source_ip", ""),
            dst_port            = int(d.get("dst_port", 0)),
            model_used          = d.get("model_used", ""),
            ensemble_confidence = float(d.get("ensemble_confidence", 0.0)),
            timestamp           = d.get("timestamp", ""),
            priority            = Priority(d.get("priority", "LOW")),
            explanation_th      = d.get("explanation_th", ""),
            mitre_tactic        = d.get("mitre_tactic", ""),
            affected_asset      = d.get("affected_asset", ""),
            remediation         = d.get("remediation", []),
            faithfulness_score  = float(d.get("faithfulness_score", 0.0)),
            hallucination_rate  = float(d.get("hallucination_rate", 0.0)),
            response_ms         = int(d.get("response_ms", 0)),
        )
