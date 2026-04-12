from unittest.mock import MagicMock, patch
import pytest

from notification.models.alert import LLMAlert, Priority


def _make_alert(priority: str = "HIGH", risk_score: int = 80) -> LLMAlert:
    return LLMAlert(
        risk_score=risk_score, anomaly_type="C2",
        top_3_features=["ioc_confidence", "beaconing_interval", "actor_known"],
        source_ip="1.2.3.4", dst_port=443,
        model_used="ensemble", ensemble_confidence=0.92,
        timestamp="2026-04-12T11:00:00",
        priority=Priority(priority),
        explanation_th="ตรวจพบการเชื่อมต่อ C2 จาก IP ต้องสงสัย",
        mitre_tactic="command-and-control",
        affected_asset="workstation-01",
        remediation=["block IP", "isolate host", "collect forensics"],
        faithfulness_score=0.91, hallucination_rate=0.02, response_ms=2300,
    )


class TestLLMAlertFromDict:
    def test_parses_all_fields(self):
        d = {
            "risk_score": 85, "anomaly_type": "BruteForce",
            "top_3_features": ["failed_auth_ratio"],
            "source_ip": "5.5.5.5", "dst_port": 22,
            "model_used": "rf", "ensemble_confidence": 0.88,
            "timestamp": "2026-04-12T10:00:00",
            "priority": "MEDIUM",
            "explanation_th": "พบการ brute force",
            "mitre_tactic": "credential-access",
            "affected_asset": "ssh-server",
            "remediation": ["block IP"],
            "faithfulness_score": 0.85, "hallucination_rate": 0.05,
            "response_ms": 1800,
        }
        alert = LLMAlert.from_dict(d)
        assert alert.priority == Priority.MEDIUM
        assert alert.risk_score == 85
        assert alert.source_ip == "5.5.5.5"

    def test_defaults_on_missing_fields(self):
        alert = LLMAlert.from_dict({"priority": "LOW"})
        assert alert.risk_score == 0
        assert alert.remediation == []
        assert alert.faithfulness_score == 0.0


class TestPriority:
    def test_high_priority_value(self):
        assert Priority.HIGH.value == "HIGH"

    def test_priority_from_string(self):
        assert Priority("MEDIUM") == Priority.MEDIUM

    def test_invalid_priority_raises(self):
        with pytest.raises(ValueError):
            Priority("CRITICAL")


class TestLineNotifierMessage:
    def test_message_contains_ip(self):
        from notification.notifiers.line.notifier import LineNotifier
        notifier = LineNotifier()
        alert    = _make_alert("HIGH", 90)
        msg      = notifier._build_message(alert)
        assert "1.2.3.4" in msg
        assert "HIGH" in msg
        assert "command-and-control" in msg

    def test_explanation_truncated_to_2_lines(self):
        from notification.notifiers.line.notifier import LineNotifier
        notifier = LineNotifier()
        alert    = _make_alert("HIGH")
        alert.explanation_th = "line1\nline2\nline3\nline4"
        msg      = notifier._build_message(alert)
        assert "line3" not in msg
