from datetime import datetime, timezone

from notification.models.alert import LLMAlert
from notification.scripts.generate_elastic_mock_data import _build_doc, _bulk_payload
from notification.scripts.generate_influx_mock_data import build_line_protocol
from notification.scripts.generate_thesis_dashboard_mock_data import build_lines


def test_mock_outputs_do_not_emit_paused_metrics():
    timestamp = datetime(2026, 4, 12, 10, tzinfo=timezone.utc)
    paused_metrics = {"faithfulness_score", "hallucination_rate"}

    elastic_doc = _build_doc(timestamp, 1)
    elastic_payload = _bulk_payload("soc-alerts", [elastic_doc]).decode("utf-8")
    influx_lines = build_line_protocol(
        measurement="soc_alert",
        source_tag="mockgen",
        start=timestamp,
        end=timestamp,
        step_seconds=60,
        timestamps=[timestamp],
    )
    dashboard_lines = build_lines(timestamp, timestamp, 60)

    assert paused_metrics.isdisjoint(elastic_doc)
    assert all(metric not in elastic_payload for metric in paused_metrics)
    assert all(metric not in "\n".join(influx_lines + dashboard_lines) for metric in paused_metrics)

    alert = LLMAlert.from_dict({
        "alert_id": "legacy-input",
        "timestamp": timestamp.isoformat(),
        "source_ip": "5.5.5.5",
        "dst_port": 22,
        "priority": "MEDIUM",
        "risk_score": 85,
        "anomaly_type": "BruteForce",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110",
        "explanation_th": "พบการ brute force",
        "faithfulness_score": 0.85,
        "hallucination_rate": 0.05,
    })
    assert paused_metrics.isdisjoint(alert.to_dict())
