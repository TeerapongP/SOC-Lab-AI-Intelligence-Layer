import pytest

from notification.models.alert import LLMAlert, Priority


def _payload(**overrides):
    return {
        "alert_id": "a1",
        "timestamp": "2026-04-12T10:00:00Z",
        "source_ip": "5.5.5.5",
        "dst_port": 22,
        "priority": "MEDIUM",
        "risk_score": 85,
        "anomaly_type": "BruteForce",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110",
        "model_used": "rf",
        "explanation_th": "พบการ brute force",
        "remediation": ["block IP"],
        "top_3_features": ["failed_auth_ratio"],
        "response_ms": 1800,
        **overrides,
    }


class TestLLMAlertFromDict:
    def test_parses_all_fields(self):
        d = _payload(
            ensemble_confidence=0.88,
            affected_asset="ssh-server",
            faithfulness_score=0.85,
            hallucination_rate=0.05,
        )
        alert = LLMAlert.from_dict(d)
        assert alert.priority == Priority.MEDIUM
        assert alert.risk_score == 85
        assert alert.source_ip == "5.5.5.5"
        assert "faithfulness_score" not in alert.to_dict()
        assert "hallucination_rate" not in alert.to_dict()

    def test_defaults_on_missing_fields(self):
        payload = _payload(priority="LOW")
        payload.pop("response_ms")
        payload.pop("remediation")
        alert = LLMAlert.from_dict(payload)
        assert alert.response_ms == 0
        assert alert.remediation == []
        assert "faithfulness_score" not in alert.to_dict()


class TestPriority:
    def test_high_priority_value(self):
        assert Priority.HIGH.value == "HIGH"

    def test_priority_from_string(self):
        assert Priority("MEDIUM") == Priority.MEDIUM

    def test_invalid_priority_raises(self):
        with pytest.raises(ValueError):
            Priority("CRITICAL")
