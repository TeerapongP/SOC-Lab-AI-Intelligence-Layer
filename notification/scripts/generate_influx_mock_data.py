from __future__ import annotations

import argparse
import math
import os
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import requests


@dataclass
class InfluxConfig:
    url: str
    token: str
    org: str
    bucket: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate mock SOC alert metrics and write to InfluxDB."
    )
    parser.add_argument("--hours", type=int, default=12, help="Data lookback window in hours.")
    parser.add_argument(
        "--step-seconds",
        type=int,
        default=30,
        help="Point interval in seconds.",
    )
    parser.add_argument(
        "--measurement",
        type=str,
        default="soc_alert",
        help="Influx measurement name.",
    )
    parser.add_argument(
        "--source-tag",
        type=str,
        default="mockgen",
        help="Source tag value for generated points.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for repeatable generation.",
    )
    parser.add_argument(
        "--start-datetime",
        type=str,
        default="",
        help="Start datetime format: YYYY-MM-DD HH:MM (UTC).",
    )
    parser.add_argument(
        "--random-time-per-day",
        action="store_true",
        help="Generate one point per day at a random time instead of fixed intervals.",
    )
    return parser.parse_args()


def load_config_from_env() -> InfluxConfig:
    url = os.getenv("INFLUX_URL", "http://localhost:8086").rstrip("/")
    token = os.getenv("INFLUX_TOKEN", "").strip()
    org = os.getenv("INFLUX_ORG", "soc").strip()
    bucket = os.getenv("INFLUX_BUCKET", "alerts").strip()

    if not token:
        raise RuntimeError("INFLUX_TOKEN is required in environment.")

    return InfluxConfig(url=url, token=token, org=org, bucket=bucket)


def build_line_protocol(
    *,
    measurement: str,
    source_tag: str,
    start: datetime,
    end: datetime,
    step_seconds: int,
    timestamps: list[datetime] | None = None,
) -> list[str]:
    priorities = ["LOW", "MEDIUM", "HIGH"]
    anomalies = ["Recon", "BruteForce", "C2", "Exfil"]
    tactics = ["reconnaissance", "credential-access", "command-and-control", "exfiltration"]
    models = ["ensemble", "rf", "xgb"]

    lines: list[str] = []
    step = timedelta(seconds=step_seconds)

    if timestamps is None:
        ts_list: list[datetime] = []
        t = start
        while t <= end:
            ts_list.append(t)
            t += step
    else:
        ts_list = timestamps

    for i, t in enumerate(ts_list):
        # Smooth baseline + periodic spikes for visually interesting charts.
        wave = 20.0 * (1.0 + math.sin(i / 40.0))
        noise = random.uniform(-8.0, 8.0)

        incident = 0.0
        if 250 <= i <= 320 or 900 <= i <= 980:
            incident = random.uniform(25.0, 45.0)

        risk = max(1.0, min(99.0, wave + noise + incident))
        if risk >= 70:
            priority = priorities[2]
        elif risk >= 40:
            priority = priorities[1]
        else:
            priority = priorities[0]

        response_ms = int(max(100.0, 700.0 + 6.0 * risk + random.uniform(-120.0, 180.0)))
        faithfulness = max(0.5, min(1.0, 0.98 - risk / 500.0 + random.uniform(-0.03, 0.03)))
        ioc_conf = max(0.0, min(1.0, risk / 100.0 + random.uniform(-0.1, 0.1)))
        actor_known = 1 if random.random() < (0.15 + risk / 200.0) else 0
        mttd_s = max(3.0, 180.0 - risk + random.uniform(-20.0, 20.0))

        anomaly = random.choice(anomalies)
        tactic = random.choice(tactics)
        model = random.choice(models)

        ns = int(t.timestamp() * 1_000_000_000)
        lines.append(
            f"{measurement},priority={priority},anomaly_type={anomaly},mitre_tactic={tactic},model_used={model},source={source_tag} "
            f"risk_score={risk:.2f},response_ms={response_ms}i,faithfulness_score={faithfulness:.4f},"
            f"ioc_confidence={ioc_conf:.4f},actor_known={actor_known}i,mttd_s={mttd_s:.2f} {ns}"
        )

    return lines


def build_random_daily_timestamps(start: datetime, end: datetime) -> list[datetime]:
    points: list[datetime] = []
    current_day = start.date()
    end_day = end.date()

    while current_day <= end_day:
        random_hour = random.randint(0, 23)
        random_min = random.randint(0, 59)
        random_sec = random.randint(0, 59)
        ts = datetime(
            current_day.year,
            current_day.month,
            current_day.day,
            random_hour,
            random_min,
            random_sec,
            tzinfo=timezone.utc,
        )
        if start <= ts <= end:
            points.append(ts)
        current_day += timedelta(days=1)

    return points


def write_to_influx(config: InfluxConfig, lines: list[str]) -> None:
    endpoint = f"{config.url}/api/v2/write?org={config.org}&bucket={config.bucket}&precision=ns"
    headers = {
        "Authorization": f"Token {config.token}",
        "Content-Type": "text/plain; charset=utf-8",
    }

    payload = "\n".join(lines).encode("utf-8")
    response = requests.post(endpoint, headers=headers, data=payload, timeout=30)
    if response.status_code >= 300:
        raise RuntimeError(
            f"Influx write failed ({response.status_code}): {response.text[:300]}"
        )


def main() -> None:
    args = parse_args()
    random.seed(args.seed)

    config = load_config_from_env()

    now = datetime.now(timezone.utc)
    end = now
    if args.start_datetime:
        try:
            start = datetime.strptime(args.start_datetime, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise RuntimeError("Invalid --start-datetime format. Use: YYYY-MM-DD HH:MM") from exc
    else:
        start = end - timedelta(hours=args.hours)

    if start > end:
        end = start + timedelta(hours=max(args.hours, 1))

    ts_list = build_random_daily_timestamps(start, end) if args.random_time_per_day else None

    lines = build_line_protocol(
        measurement=args.measurement,
        source_tag=args.source_tag,
        start=start,
        end=end,
        step_seconds=args.step_seconds,
        timestamps=ts_list,
    )
    write_to_influx(config, lines)

    print(f"Wrote {len(lines)} points to {config.bucket}/{args.measurement} at {config.url}")


if __name__ == "__main__":
    main()
