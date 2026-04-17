from __future__ import annotations

import argparse
import math
import os
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests


@dataclass
class InfluxConfig:
    url: str
    token: str
    org: str
    bucket: str


def _load_env_file_if_exists(file_path: Path) -> None:
    if not file_path.exists():
        return

    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate thesis-style mock dashboard data for InfluxDB."
    )
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours.")
    parser.add_argument(
        "--step-seconds",
        type=int,
        default=60,
        help="Data interval in seconds.",
    )
    parser.add_argument("--seed", type=int, default=5220, help="Random seed.")
    return parser.parse_args()


def load_config() -> InfluxConfig:
    script_dir = Path(__file__).resolve().parent
    _load_env_file_if_exists(script_dir.parent / ".env")
    _load_env_file_if_exists(script_dir.parents[3] / ".env")

    url = os.getenv("INFLUX_URL", "http://localhost:8086").rstrip("/")
    token = os.getenv("INFLUX_TOKEN", "").strip()
    org = os.getenv("INFLUX_ORG", "soc").strip()
    bucket = os.getenv("INFLUX_BUCKET", "alerts").strip()

    if not token:
        raise RuntimeError("INFLUX_TOKEN is required in environment.")

    return InfluxConfig(url=url, token=token, org=org, bucket=bucket)


def _to_ns(ts: datetime) -> int:
    return int(ts.timestamp() * 1_000_000_000)


def build_lines(start: datetime, end: datetime, step_seconds: int) -> list[str]:
    lines: list[str] = []
    t = start
    i = 0

    priorities = ["LOW", "MEDIUM", "HIGH"]
    anomaly_types = ["Recon", "BruteForce", "C2", "Exfil"]
    tactics = ["reconnaissance", "credential-access", "command-and-control", "exfiltration"]
    models = ["ensemble", "rf", "xgb"]

    while t <= end:
        ns = _to_ns(t)

        # L1: ingest rate / hour with daily wave + incident spikes
        wave = 320 + 120 * (1 + math.sin(i / 90.0))
        incident_boost = 0
        if 180 <= i <= 240 or 720 <= i <= 780:
            incident_boost = random.uniform(180, 260)
        ingest_rate = max(50.0, wave + incident_boost + random.uniform(-30, 35))

        lines.append(
            "soc_pipeline,layer=L1,source=mockgen "
            f"ingest_rate={ingest_rate:.2f} {ns}"
        )

        # L2: enrichment latency + IoC match rate
        enrich_latency = max(20.0, 140 + 0.2 * ingest_rate + random.uniform(-15, 30))
        ioc_match_rate = max(0.02, min(0.95, 0.25 + random.uniform(-0.08, 0.18)))

        lines.append(
            "soc_pipeline,layer=L2,source=mockgen "
            f"enrich_latency_ms={enrich_latency:.2f},ioc_match_rate={ioc_match_rate:.4f} {ns}"
        )

        # L3 + LLM: alert metrics
        risk_wave = 30 + 25 * (1 + math.sin(i / 55.0))
        risk = max(1.0, min(99.0, risk_wave + incident_boost * 0.12 + random.uniform(-10, 10)))

        if risk >= 70:
            priority = priorities[2]
        elif risk >= 40:
            priority = priorities[1]
        else:
            priority = priorities[0]

        response_ms = int(max(200, 900 + 7 * risk + random.uniform(-180, 220)))
        faithfulness = max(0.6, min(1.0, 0.96 - risk / 600 + random.uniform(-0.03, 0.02)))
        mttd_s = max(4.0, 170 - risk + random.uniform(-18, 20))
        ioc_conf = max(0.0, min(1.0, risk / 100 + random.uniform(-0.12, 0.08)))
        actor_known = 1 if random.random() < (0.12 + risk / 220) else 0

        anomaly = random.choice(anomaly_types)
        tactic = random.choice(tactics)
        model = random.choice(models)

        lines.append(
            "soc_alert,"
            f"priority={priority},anomaly_type={anomaly},mitre_tactic={tactic},model_used={model},source=mockgen "
            f"risk_score={risk:.2f},mttd_s={mttd_s:.2f},response_ms={response_ms}i,"
            f"faithfulness_score={faithfulness:.4f},ioc_confidence={ioc_conf:.4f},actor_known={actor_known}i {ns}"
        )

        t += timedelta(seconds=step_seconds)
        i += 1

    return lines


def write_lines(config: InfluxConfig, lines: list[str]) -> None:
    endpoint = f"{config.url}/api/v2/write?org={config.org}&bucket={config.bucket}&precision=ns"
    headers = {
        "Authorization": f"Token {config.token}",
        "Content-Type": "text/plain; charset=utf-8",
    }
    payload = "\n".join(lines).encode("utf-8")

    resp = requests.post(endpoint, headers=headers, data=payload, timeout=30)
    if resp.status_code >= 300:
        raise RuntimeError(f"Influx write failed ({resp.status_code}): {resp.text[:300]}")


def main() -> None:
    args = parse_args()
    random.seed(args.seed)

    config = load_config()
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)
    lines = build_lines(start=start, end=end, step_seconds=args.step_seconds)
    write_lines(config, lines)

    print(
        f"Wrote {len(lines)} points to {config.bucket} "
        f"(soc_pipeline + soc_alert) at {config.url}"
    )


if __name__ == "__main__":
    main()
