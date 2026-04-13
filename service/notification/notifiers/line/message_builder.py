from __future__ import annotations

from urllib.parse import quote

from notification.models.alert import LLMAlert


def grafana_url(base_url: str, dashboard_path: str, source_ip: str) -> str:
    """Build dashboard URL with a safe source_ip query parameter."""
    return f"{base_url}{dashboard_path}?var-src_ip={quote(source_ip, safe='')}"


def build_message(
    alert: LLMAlert,
    dashboard_url: str,
    max_chars: int,
) -> tuple[str, int]:
    explanation_short = "\n".join(alert.explanation_th.splitlines()[:2])
    message = (
        f"\n[{alert.priority.value}] ตรวจพบภัยคุกคาม\n"
        f"IP: {alert.source_ip}  Port: {alert.dst_port}\n"
        f"MITRE: {alert.mitre_tactic}\n"
        f"Risk: {alert.risk_score}/100\n"
        f"{explanation_short}\n"
        f"Dashboard: {dashboard_url}"
    )
    original_length = len(message)
    return message[:max_chars], original_length
