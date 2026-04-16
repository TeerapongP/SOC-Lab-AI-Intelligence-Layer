from __future__ import annotations

import argparse
import json
import math
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests


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
    parser = argparse.ArgumentParser(description="Generate thesis-style mock docs in Elasticsearch.")
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours.")
    parser.add_argument("--step-seconds", type=int, default=60, help="Document interval in seconds.")
    parser.add_argument("--seed", type=int, default=5220, help="Random seed.")
    return parser.parse_args()


def _load_env() -> None:
    script_dir = Path(__file__).resolve().parent
    _load_env_file_if_exists(script_dir.parent / ".env")
    _load_env_file_if_exists(script_dir.parents[3] / ".env")


def _build_doc(ts: datetime, i: int) -> dict:
    anomaly_types = ["Recon", "BruteForce", "C2", "Exfil"]
    tactics = ["reconnaissance", "credential-access", "command-and-control", "exfiltration"]
    models = ["ensemble", "rf", "xgb"]

    wave = 28 + 22 * (1 + math.sin(i / 45.0))
    incident_boost = 0.0
    if 220 <= i <= 300 or 840 <= i <= 930:
        incident_boost = random.uniform(20.0, 35.0)

    risk = max(1.0, min(99.0, wave + incident_boost + random.uniform(-9, 11)))
    if risk >= 70:
        priority = "HIGH"
    elif risk >= 40:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    response_ms = int(max(180.0, 850.0 + 6.5 * risk + random.uniform(-140.0, 190.0)))
    faithfulness = max(0.55, min(1.0, 0.96 - risk / 620.0 + random.uniform(-0.03, 0.02)))
    ioc_conf = max(0.0, min(1.0, risk / 100.0 + random.uniform(-0.1, 0.08)))
    mttd_s = max(4.0, 170.0 - risk + random.uniform(-16.0, 22.0))

    anomaly = random.choice(anomaly_types)
    tactic = random.choice(tactics)
    model = random.choice(models)

    return {
        "alert_id": f"mock-{int(ts.timestamp())}-{i}",
        "timestamp": ts.isoformat(),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "event_type": "e2e",
        "priority": priority,
        "risk_score": round(risk, 2),
        "source_ip": f"203.0.113.{(i % 200) + 1}",
        "dst_port": random.choice([22, 53, 80, 443, 8080]),
        "anomaly_type": anomaly,
        "mitre_tactic": tactic,
        "affected_asset": f"host-{(i % 25) + 1:02d}",
        "model_used": model,
        "ensemble_confidence": round(min(0.99, max(0.3, risk / 100.0 + random.uniform(-0.08, 0.06))), 3),
        "response_ms": response_ms,
        "faithfulness_score": round(faithfulness, 4),
        "hallucination_rate": round(max(0.0, min(0.3, 0.08 - faithfulness / 10.0 + random.uniform(-0.01, 0.015))), 4),
        "ioc_confidence": round(ioc_conf, 4),
        "mttd_s": round(mttd_s, 2),
        "source": "mockgen",
        "layer": random.choice(["L1", "L2", "L3", "LLM"]),
        "explanation_th": "ข้อมูลจำลองสำหรับ dashboard ตาม thesis",
    }


def _bulk_payload(index_name: str, docs: list[dict]) -> bytes:
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index_name}}))
        lines.append(json.dumps(doc, ensure_ascii=False))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _bulk_index(url: str, api_key: str, payload: bytes) -> tuple[int, str]:
    endpoint = f"{url}/_bulk"
    headers = {"Content-Type": "application/x-ndjson"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    resp = requests.post(endpoint, headers=headers, data=payload, timeout=60)
    if resp.status_code in (401, 403) and api_key:
        # Fallback for clusters with security disabled or mismatched key.
        resp = requests.post(
            endpoint,
            headers={"Content-Type": "application/x-ndjson"},
            data=payload,
            timeout=60,
        )
    return resp.status_code, resp.text[:400]


def main() -> None:
    args = parse_args()
    random.seed(args.seed)
    _load_env()

    elastic_url = os.getenv("ELASTIC_URL", "http://localhost:9200").rstrip("/")
    elastic_api_key = os.getenv("ELASTIC_API_KEY", "").strip()
    index_name = os.getenv("ELASTIC_ALERT_INDEX", "soc-alerts").strip()

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)
    step = timedelta(seconds=args.step_seconds)

    docs: list[dict] = []
    i = 0
    ts = start
    while ts <= end:
        docs.append(_build_doc(ts, i))
        ts += step
        i += 1

    payload = _bulk_payload(index_name, docs)
    status, text = _bulk_index(elastic_url, elastic_api_key, payload)
    if status >= 300:
        raise RuntimeError(f"Elasticsearch bulk failed ({status}): {text}")

    print(f"Indexed {len(docs)} docs into {index_name} at {elastic_url}")


if __name__ == "__main__":
    main()
