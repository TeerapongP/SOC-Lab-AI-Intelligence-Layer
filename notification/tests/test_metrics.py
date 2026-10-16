from notification.metrics import influx
from notification.models.alert import LLMAlert


def test_influx_does_not_write_undefined_faithfulness_metrics(monkeypatch):
    recorded = {}

    class FakeWriteApi:
        def write(self, **kwargs):
            recorded.update(kwargs)

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def write_api(self, **kwargs):
            return FakeWriteApi()

    monkeypatch.setattr(influx, "InfluxDBClient", FakeClient)
    alert = LLMAlert.from_dict({
        "alert_id": "a1",
        "timestamp": "2026-04-12T10:00:00Z",
        "source_ip": "5.5.5.5",
        "dst_port": 22,
        "priority": "MEDIUM",
        "risk_score": 85,
        "anomaly_type": "BruteForce",
        "mitre_tactic": "credential-access",
        "explanation_th": "พบการ brute force",
        "remediation": ["block IP"],
        "top_3_features": ["failed_auth_ratio"],
        "faithfulness_score": 0.85,
        "hallucination_rate": 0.05,
    })

    influx.MetricsWriter().write_alert(alert)

    assert "faithfulness_score" not in recorded["record"]["fields"]
    assert "hallucination_rate" not in recorded["record"]["fields"]
    assert "faithfulness_score" not in alert.to_dict()
    assert "hallucination_rate" not in alert.to_dict()
