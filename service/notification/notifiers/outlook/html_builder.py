from __future__ import annotations

from datetime import datetime, timezone

from notification.models.alert import LLMAlert

from .model.models import DigestEntry


def build_immediate_html(alert: LLMAlert) -> str:
    steps_html = "".join(f"<li>{s}</li>" for s in alert.remediation)
    features = ", ".join(alert.top_3_features)
    return f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
      <h2 style="color:#c0392b;">SOC Alert — {alert.priority.value}</h2>
      <table style="border-collapse:collapse;width:100%;">
        <tr><td style="padding:6px;color:#555;width:160px;">Risk score</td>
            <td style="padding:6px;font-weight:bold;">{alert.risk_score}/100</td></tr>
        <tr><td style="padding:6px;color:#555;">Source IP</td>
            <td style="padding:6px;">{alert.source_ip}:{alert.dst_port}</td></tr>
        <tr><td style="padding:6px;color:#555;">MITRE tactic</td>
            <td style="padding:6px;">{alert.mitre_tactic}</td></tr>
        <tr><td style="padding:6px;color:#555;">Anomaly type</td>
            <td style="padding:6px;">{alert.anomaly_type}</td></tr>
        <tr><td style="padding:6px;color:#555;">Model</td>
            <td style="padding:6px;">{alert.model_used}</td></tr>
        <tr><td style="padding:6px;color:#555;">Top features</td>
            <td style="padding:6px;">{features}</td></tr>
      </table>
      <h3>คำอธิบาย (ภาษาไทย)</h3>
      <p style="background:#f8f8f8;padding:12px;border-left:4px solid #e74c3c;">
        {alert.explanation_th}
      </p>
      <h3>Remediation steps</h3>
      <ol>{steps_html}</ol>
      <hr/>
      <small style="color:#888;">
        Timestamp: {alert.timestamp} |
        Faithfulness: {alert.faithfulness_score:.2f} |
        Response: {alert.response_ms}ms
      </small>
    </body></html>
    """


def build_digest_html(entries: list[DigestEntry], stats: dict) -> str:
    rows = "".join(
        f"""<tr>
          <td style="padding:6px;border-bottom:1px solid #eee;">{e.timestamp[:19]}</td>
          <td style="padding:6px;border-bottom:1px solid #eee;">{e.source_ip}</td>
          <td style="padding:6px;border-bottom:1px solid #eee;">{e.risk_score}</td>
          <td style="padding:6px;border-bottom:1px solid #eee;">{e.mitre_tactic}</td>
          <td style="padding:6px;border-bottom:1px solid #eee;">{e.anomaly_type}</td>
        </tr>"""
        for e in entries
    )
    mttd = stats.get("mttd_avg_s", "N/A")
    top_type = stats.get("top_attack_type", "N/A")
    count = stats.get("alert_count", len(entries))

    return f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
      <h2>SOC Daily Digest — {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d')}</h2>
      <table style="border-collapse:collapse;margin-bottom:16px;">
        <tr><td style="padding:6px;color:#555;width:200px;">Total alerts</td>
            <td style="padding:6px;font-weight:bold;">{count}</td></tr>
        <tr><td style="padding:6px;color:#555;">Top attack type</td>
            <td style="padding:6px;">{top_type}</td></tr>
        <tr><td style="padding:6px;color:#555;">Avg MTTD</td>
            <td style="padding:6px;">{mttd}s</td></tr>
      </table>
      <h3>Alert log</h3>
      <table style="border-collapse:collapse;width:100%;font-size:13px;">
        <thead>
          <tr style="background:#f0f0f0;">
            <th style="padding:6px;text-align:left;">Timestamp</th>
            <th style="padding:6px;text-align:left;">Source IP</th>
            <th style="padding:6px;text-align:left;">Risk</th>
            <th style="padding:6px;text-align:left;">MITRE</th>
            <th style="padding:6px;text-align:left;">Type</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </body></html>
    """
