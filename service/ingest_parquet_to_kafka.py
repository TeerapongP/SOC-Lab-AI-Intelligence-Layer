from __future__ import annotations

import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
from kafka import KafkaProducer

LOG = logging.getLogger("parquet_ingest")

EXCLUDED_DIR_MARKERS = (
    "dataset_cleaned_parquet_smoke",
    "run_outputs",
    "__tmp",
)

FIELD_ALIASES = {
    "src_ip": ("src_ip", "src_ip_zeek", "source_ip", "src", "source", "id_orig_h", "id.orig_h", "client_ip"),
    "dst_ip": ("dst_ip", "dest_ip_zeek", "destination_ip", "dst", "destination", "id_resp_h", "id.resp_h", "server_ip"),
    "src_port": ("src_port", "src_port_zeek", "source_port", "sport", "id_orig_p", "id.orig_p"),
    "dst_port": ("dst_port", "dest_port_zeek", "destination_port", "dport", "id_resp_p", "id.resp_p", "port"),
    "bytes_sent": ("bytes_sent", "orig_bytes", "src_bytes", "bytes"),
    "bytes_recv": ("bytes_recv", "resp_bytes", "dst_bytes"),
    "packets": ("packets", "pkts", "orig_pkts"),
    "session_duration": ("session_duration", "duration", "dur"),
    "action": ("action", "conn_state", "status"),
    "app": ("app", "service", "proto", "protocol"),
    "rule": ("rule", "label", "dataset"),
    "timestamp": ("timestamp", "time", "ts", "datetime", "date"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stream cleaned parquet records into Kafka.")
    parser.add_argument("--input-folder", required=True)
    parser.add_argument("--topic", default=os.getenv("KAFKA_INPUT_TOPIC", "pa5220.raw"))
    parser.add_argument("--bootstrap", default=os.getenv("KAFKA_BOOTSTRAP", "127.0.0.1:9092"))
    parser.add_argument("--batch-size", type=int, default=10_000)
    parser.add_argument("--max-records", type=int, default=0)
    parser.add_argument("--require-network-fields", action="store_true", default=True)
    parser.add_argument("--include-smoke", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args()


def normalise_key(key: str) -> str:
    return key.strip().lower().replace("-", "_").replace(" ", "_")


def first_value(row: dict[str, Any], aliases: tuple[str, ...], default: Any = None) -> Any:
    for alias in aliases:
        value = row.get(normalise_key(alias))
        if value is not None and value != "":
            return value
    return default


def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def to_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def normalise_record(raw: dict[str, Any], source: Path) -> dict[str, Any] | None:
    row = {normalise_key(k): v for k, v in raw.items()}
    src_ip = first_value(row, FIELD_ALIASES["src_ip"])
    dst_ip = first_value(row, FIELD_ALIASES["dst_ip"])
    if not src_ip or not dst_ip:
        return None

    bytes_sent = to_float(first_value(row, FIELD_ALIASES["bytes_sent"], 0.0))
    bytes_recv = to_float(first_value(row, FIELD_ALIASES["bytes_recv"], 0.0))
    packets = to_int(first_value(row, FIELD_ALIASES["packets"], 0))

    if packets == 0:
        packets = to_int(row.get("orig_pkts"), 0) + to_int(row.get("resp_pkts"), 0)

    return {
        "src_ip": to_text(src_ip),
        "dst_ip": to_text(dst_ip),
        "src_port": to_int(first_value(row, FIELD_ALIASES["src_port"], 0)),
        "dst_port": to_int(first_value(row, FIELD_ALIASES["dst_port"], 0)),
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "packets": packets,
        "session_duration": to_float(first_value(row, FIELD_ALIASES["session_duration"], 0.0)),
        "action": to_text(first_value(row, FIELD_ALIASES["action"], "unknown"), "unknown"),
        "app": to_text(first_value(row, FIELD_ALIASES["app"], "unknown"), "unknown"),
        "rule": to_text(first_value(row, FIELD_ALIASES["rule"], source.parent.name), source.parent.name),
        "timestamp": to_text(first_value(row, FIELD_ALIASES["timestamp"], "")),
    }


def iter_parquet_files(input_folder: Path, include_smoke: bool) -> list[Path]:
    files = []
    for path in input_folder.rglob("*.parquet"):
        parts = {part.lower() for part in path.parts}
        if not include_smoke and any(marker in part for part in parts for marker in EXCLUDED_DIR_MARKERS):
            continue
        files.append(path)
    return sorted(files)


def make_producer(bootstrap: str) -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=bootstrap,
        value_serializer=lambda value: json.dumps(value, default=str).encode("utf-8"),
        acks="all",
        retries=int(os.getenv("KAFKA_RETRIES", "3")),
        linger_ms=int(os.getenv("KAFKA_LINGER_MS", "20")),
        max_in_flight_requests_per_connection=1,
    )


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    input_folder = Path(args.input_folder).resolve()
    if not input_folder.exists():
        raise FileNotFoundError(input_folder)

    parquet_files = iter_parquet_files(input_folder, args.include_smoke)
    LOG.info("Starting parquet ingest: files=%d topic=%s bootstrap=%s", len(parquet_files), args.topic, args.bootstrap)

    producer = make_producer(args.bootstrap)
    sent = skipped = 0
    start = time.perf_counter()

    try:
        for file_index, parquet_path in enumerate(parquet_files, start=1):
            LOG.info("[%d/%d] Reading %s", file_index, len(parquet_files), parquet_path)
            parquet_file = pq.ParquetFile(parquet_path)
            for batch in parquet_file.iter_batches(batch_size=args.batch_size):
                for raw in batch.to_pylist():
                    record = normalise_record(raw, parquet_path)
                    if record is None:
                        skipped += 1
                        continue
                    producer.send(args.topic, value=record)
                    sent += 1

                    if sent % 10_000 == 0:
                        producer.flush()
                        elapsed = max(time.perf_counter() - start, 0.001)
                        LOG.info("sent=%s skipped=%s rate=%.1f rows/s", f"{sent:,}", f"{skipped:,}", sent / elapsed)

                    if args.max_records and sent >= args.max_records:
                        LOG.info("Reached max records: %s", f"{sent:,}")
                        return
    finally:
        producer.flush()
        producer.close()
        elapsed = max(time.perf_counter() - start, 0.001)
        LOG.info("Finished parquet ingest: sent=%s skipped=%s elapsed=%.1fs", f"{sent:,}", f"{skipped:,}", elapsed)


if __name__ == "__main__":
    main()
