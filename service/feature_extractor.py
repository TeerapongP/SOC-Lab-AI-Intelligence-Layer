"""
feature_extractor.py — Layer 2: Feature Engineering
====================================================
Consumes labeled records from Kafka (pa5220.labeled),
computes 9 features (5 network + 4 CTI), applies MinMaxScaler
fitted on X_train only, outputs feature_matrix.csv for ML training.

9 Features (matches diagram spec):
  Network (5):
    1. bytes_per_second      — bytes_sent / max(session_duration, 0.001)
    2. login_velocity        — failed_auth count / time window (from sliding buffer)
    3. geo_anomaly           — 1 if dst_ip country != org baseline, else 0
    4. failed_auth_ratio     — failed_auth / total_auth in session window
    5. beaconing_interval    — stddev of inter-session gaps for src_ip (low = beaconing)

  CTI (4):
    6. ioc_confidence        — pass-through from enrich.py (0.0–1.0)
    7. ioc_type_enc          — label encoded: none=0, ipv4-addr=1, domain-name=2, url=3, file=4
    8. mitre_phase_enc       — label encoded (see MITRE_PHASE_MAP)
    9. actor_known           — pass-through binary 0/1

Pipeline:
  Kafka → compute features → accumulate → fit scaler on train split →
  transform all → write feature_matrix.csv + scaler.pkl

Usage modes:
  python feature_extractor.py --mode stream   # real-time Kafka mode
  python feature_extractor.py --mode batch    # batch from pa5220.labeled dump
  python feature_extractor.py --mode fit      # fit scaler on saved CSV + write scaler.pkl

Environment:
  KAFKA_BOOTSTRAP        = localhost:9092
  KAFKA_LABELED_TOPIC    = pa5220.labeled
  KAFKA_GROUP_ID_FEAT    = feature-group
  OUTPUT_CSV             = feature_matrix.csv
  SCALER_PATH            = scaler.pkl
  COLLECT_N              = 500000   # records to collect before writing CSV
"""

import os
import json
import time
import pickle
import logging
import argparse
import collections
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from kafka import KafkaConsumer
from sklearn.preprocessing import MinMaxScaler
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP     = os.getenv("KAFKA_BOOTSTRAP",     "localhost:9092")
KAFKA_LABELED_TOPIC = os.getenv("KAFKA_LABELED_TOPIC", "pa5220.labeled")
KAFKA_GROUP_FEAT    = os.getenv("KAFKA_GROUP_ID_FEAT", "feature-group")
OUTPUT_CSV          = Path(os.getenv("OUTPUT_CSV",     "feature_matrix.csv"))
SCALER_PATH         = Path(os.getenv("SCALER_PATH",    "scaler.pkl"))
COLLECT_N           = int(os.getenv("COLLECT_N",       "500000"))

# Train/Val/Test split ratios
TRAIN_RATIO = 0.60
VAL_RATIO   = 0.20
# TEST_RATIO  = 0.20 (remainder)

# Sliding window for login_velocity + failed_auth_ratio (seconds)
AUTH_WINDOW_SEC = 60

# Beaconing: track last N inter-arrival gaps per src_ip
BEACONING_BUFFER = 10

# ── Encoding maps ─────────────────────────────────────────────────────────────
IOC_TYPE_MAP = {
    "none":        0,
    "ipv4-addr":   1,
    "domain-name": 2,
    "url":         3,
    "file":        4,
}

MITRE_PHASE_MAP = {
    "none":                  0,
    "reconnaissance":        1,
    "resource-development":  2,
    "initial-access":        3,
    "execution":             4,
    "persistence":           5,
    "privilege-escalation":  6,
    "defense-evasion":       7,
    "credential-access":     8,
    "discovery":             9,
    "lateral-movement":      10,
    "collection":            11,
    "command-and-control":   12,
    "exfiltration":          13,
    "impact":                14,
}

FEATURE_COLS = [
    "bytes_per_second",
    "login_velocity",
    "geo_anomaly",
    "failed_auth_ratio",
    "beaconing_interval",
    "ioc_confidence",
    "ioc_type_enc",
    "mitre_phase_enc",
    "actor_known",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("feature_extractor")


# ── Stateful buffers (per src_ip) ─────────────────────────────────────────────
class SessionBuffer:
    """
    Tracks per-src_ip state for sliding window features.
    Kept in memory — resets on restart (acceptable for batch mode).
    """

    def __init__(self, auth_window: int = AUTH_WINDOW_SEC,
                 beacon_buf: int = BEACONING_BUFFER):
        self.auth_window   = auth_window
        self.beacon_buf    = beacon_buf
        # src_ip → deque of (timestamp, failed_flag)
        self._auth:    dict = collections.defaultdict(collections.deque)
        # src_ip → deque of last arrival timestamps
        self._arrival: dict = collections.defaultdict(collections.deque)

    def update(self, src_ip: str, ts: float, failed: bool):
        now = ts
        dq = self._auth[src_ip]
        dq.append((now, failed))
        # Evict records outside window
        while dq and (now - dq[0][0]) > self.auth_window:
            dq.popleft()

        arr = self._arrival[src_ip]
        arr.append(now)
        if len(arr) > self.beacon_buf + 1:
            arr.popleft()

    def login_velocity(self, src_ip: str) -> float:
        """Failed auth attempts per second in the window."""
        dq = self._auth[src_ip]
        if not dq:
            return 0.0
        failed = sum(1 for _, f in dq if f)
        window = max((dq[-1][0] - dq[0][0]), 1.0)
        return round(failed / window, 6)

    def failed_auth_ratio(self, src_ip: str) -> float:
        """Ratio of failed to total auth events in window."""
        dq = self._auth[src_ip]
        if not dq:
            return 0.0
        total  = len(dq)
        failed = sum(1 for _, f in dq if f)
        return round(failed / total, 6)

    def beaconing_interval(self, src_ip: str) -> float:
        """
        Stddev of inter-arrival gaps — low value suggests beaconing.
        Normalised to 0–1: 0 = perfect beaconing, 1 = random.
        """
        arr = list(self._arrival[src_ip])
        if len(arr) < 3:
            return 1.0  # Not enough data → assume random
        gaps = [arr[i+1] - arr[i] for i in range(len(arr)-1)]
        std  = float(np.std(gaps))
        mean = float(np.mean(gaps)) or 1.0
        cv   = std / mean           # coefficient of variation
        return round(min(cv, 1.0), 6)


# ── Geo anomaly (lightweight — no external API) ───────────────────────────────
# Replace with geoip2 + MaxMind if you want real geo lookups.
# For now: flag IPs outside RFC-1918 + known TH/APAC ranges as potential anomaly.
_ORG_PREFIXES = ("10.", "172.", "192.168.", "203.150.", "49.0.", "49.228.")

def geo_anomaly(dst_ip: str) -> int:
    """
    Returns 1 if destination IP is outside expected org/region ranges.
    Extend with geoip2 for production use.
    """
    return 0 if any(dst_ip.startswith(p) for p in _ORG_PREFIXES) else 1


# ── Is auth-related session ───────────────────────────────────────────────────
_AUTH_APPS   = {"ssh", "ftp", "rdp", "smb", "ldap", "kerberos", "ntlm", "telnet"}
_AUTH_PORTS  = {21, 22, 23, 389, 445, 636, 3389, 88}

def is_auth_session(rec: dict) -> bool:
    app  = rec.get("app", "").lower()
    port = int(rec.get("dst_port", 0))
    return app in _AUTH_APPS or port in _AUTH_PORTS

def is_failed_auth(rec: dict) -> bool:
    return rec.get("action", "").lower() in {"deny", "drop", "reset-both"}


# ── Core feature computation ──────────────────────────────────────────────────
def compute_features(rec: dict, buf: SessionBuffer) -> Optional[dict]:
    """
    Compute all 9 features from a labeled record.
    Returns None if the record is malformed.
    """
    try:
        src_ip           = rec["src_ip"]
        dst_ip           = rec["dst_ip"]
        bytes_sent       = float(rec.get("bytes_sent", 0))
        bytes_recv       = float(rec.get("bytes_recv", 0))
        session_duration = max(float(rec.get("session_duration", 0)), 0.001)
        ts               = float(
            pd.Timestamp(rec.get("timestamp", "now")).timestamp()
            if rec.get("timestamp") else time.time()
        )

        # Update stateful buffer
        is_auth   = is_auth_session(rec)
        is_failed = is_failed_auth(rec) and is_auth
        buf.update(src_ip, ts, failed=is_failed)

        # ── 5 network features ──
        f1_bytes_per_second   = round((bytes_sent + bytes_recv) / session_duration, 4)
        f2_login_velocity     = buf.login_velocity(src_ip)
        f3_geo_anomaly        = geo_anomaly(dst_ip)
        f4_failed_auth_ratio  = buf.failed_auth_ratio(src_ip)
        f5_beaconing_interval = buf.beaconing_interval(src_ip)

        # ── 4 CTI features ──
        f6_ioc_confidence = float(rec.get("ioc_confidence", 0.0))
        f7_ioc_type_enc   = IOC_TYPE_MAP.get(rec.get("ioc_type", "none"), 0)
        f8_mitre_enc      = MITRE_PHASE_MAP.get(rec.get("mitre_phase", "none"), 0)
        f9_actor_known    = int(rec.get("actor_known", 0))

        return {
            "bytes_per_second":    f1_bytes_per_second,
            "login_velocity":      f2_login_velocity,
            "geo_anomaly":         f3_geo_anomaly,
            "failed_auth_ratio":   f4_failed_auth_ratio,
            "beaconing_interval":  f5_beaconing_interval,
            "ioc_confidence":      f6_ioc_confidence,
            "ioc_type_enc":        f7_ioc_type_enc,
            "mitre_phase_enc":     f8_mitre_enc,
            "actor_known":         f9_actor_known,
            # Metadata (not ML features)
            "y_label":             rec.get("y_label", "unknown"),
            "sample_weight":       float(rec.get("sample_weight", 1.0)),
            "src_ip_hash":         str(hash(src_ip) % 2**32),  # anonymized
            "timestamp":           rec.get("timestamp", ""),
        }
    except (KeyError, ValueError, TypeError) as exc:
        log.debug("Skipping malformed record: %s", exc)
        return None


# ── Scaler: fit on X_train only (no leakage) ─────────────────────────────────
def fit_and_save_scaler(df: pd.DataFrame) -> MinMaxScaler:
    """
    Fit MinMaxScaler on training split only.
    IMPORTANT: scaler.fit() is called ONLY on X_train rows.
    Val and Test rows are transformed but never used in fit().
    """
    n = len(df)
    train_end = int(n * TRAIN_RATIO)

    X_train = df.iloc[:train_end][FEATURE_COLS].values
    scaler  = MinMaxScaler()
    scaler.fit(X_train)

    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)

    log.info("Scaler fitted on %d training rows → saved to %s", train_end, SCALER_PATH)
    return scaler


def apply_scaler(df: pd.DataFrame, scaler: MinMaxScaler) -> pd.DataFrame:
    df = df.copy()
    df[FEATURE_COLS] = scaler.transform(df[FEATURE_COLS].values)
    return df


def add_split_column(df: pd.DataFrame) -> pd.DataFrame:
    """Add 'split' column: train / val / test (stratified by y_label)."""
    df = df.copy()
    df["split"] = "test"
    n = len(df)

    # Stratified split — maintain class ratios across splits
    for label in df["y_label"].unique():
        idx = df[df["y_label"] == label].index.tolist()
        n_label = len(idx)
        t_end = int(n_label * TRAIN_RATIO)
        v_end = t_end + int(n_label * VAL_RATIO)
        df.loc[idx[:t_end], "split"] = "train"
        df.loc[idx[t_end:v_end], "split"] = "val"

    split_counts = df["split"].value_counts().to_dict()
    log.info("Split: %s", split_counts)
    return df


# ── SMOTE (applied to training split only) ────────────────────────────────────
def apply_smote(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply SMOTE to training split only — never to val/test.
    Requires imbalanced-learn: pip install imbalanced-learn
    """
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError:
        log.warning("imbalanced-learn not installed — skipping SMOTE. "
                    "pip install imbalanced-learn")
        return df

    train_df  = df[df["split"] == "train"].copy()
    other_df  = df[df["split"] != "train"].copy()

    # Only apply SMOTE to binary attack/normal — exclude unknown
    mask = train_df["y_label"].isin(["attack", "normal"])
    smote_df  = train_df[mask].copy()
    nosmote_df = train_df[~mask].copy()

    X = smote_df[FEATURE_COLS].values
    y = smote_df["y_label"].values

    label_counts = pd.Series(y).value_counts()
    log.info("Before SMOTE: %s", label_counts.to_dict())

    try:
        sm = SMOTE(random_state=42, k_neighbors=min(5, label_counts.min() - 1))
        X_res, y_res = sm.fit_resample(X, y)

        resampled = pd.DataFrame(X_res, columns=FEATURE_COLS)
        resampled["y_label"]      = y_res
        resampled["sample_weight"] = 1.0
        resampled["split"]         = "train"

        log.info("After SMOTE: %s", pd.Series(y_res).value_counts().to_dict())

        return pd.concat([resampled, nosmote_df, other_df], ignore_index=True)

    except ValueError as exc:
        log.warning("SMOTE failed (possibly too few samples): %s", exc)
        return df


# ── Modes ─────────────────────────────────────────────────────────────────────
def run_stream():
    """Collect N records from Kafka, then write feature_matrix.csv."""
    consumer = KafkaConsumer(
        KAFKA_LABELED_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=KAFKA_GROUP_FEAT,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
    )

    buf     = SessionBuffer()
    rows    = []
    skipped = 0

    log.info("Collecting %d records from Kafka...", COLLECT_N)

    for message in consumer:
        rec = message.value
        features = compute_features(rec, buf)
        if features is None:
            skipped += 1
            continue
        rows.append(features)

        if len(rows) % 50_000 == 0:
            log.info("Collected %d / %d (skipped=%d)", len(rows), COLLECT_N, skipped)

        if len(rows) >= COLLECT_N:
            break

    log.info("Collection done — %d rows, %d skipped", len(rows), skipped)
    _finalize(rows)


def run_fit(csv_path: str = str(OUTPUT_CSV)):
    """Fit scaler on existing CSV and write scaler.pkl."""
    df = pd.read_csv(csv_path)
    scaler = fit_and_save_scaler(df)
    df = apply_scaler(df, scaler)
    df.to_csv(csv_path, index=False)
    log.info("Scaler applied and CSV updated: %s", csv_path)


def _finalize(rows: list):
    df = pd.DataFrame(rows)
    df = add_split_column(df)
    scaler = fit_and_save_scaler(df)
    df = apply_scaler(df, scaler)
    df = apply_smote(df)
    df.to_csv(OUTPUT_CSV, index=False)
    log.info(
        "feature_matrix.csv written → %d rows, %d columns at %s",
        len(df), len(df.columns), OUTPUT_CSV,
    )
    log.info("Label distribution:\n%s", df["y_label"].value_counts())
    log.info("Split distribution:\n%s", df.groupby(["split","y_label"]).size())


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Feature extractor — Layer 2")
    parser.add_argument(
        "--mode", choices=["stream", "fit"],
        default="stream",
        help="stream: collect from Kafka + write CSV | fit: refit scaler on existing CSV",
    )
    parser.add_argument("--csv", default=str(OUTPUT_CSV), help="Path to CSV (for fit mode)")
    args = parser.parse_args()

    if args.mode == "stream":
        run_stream()
    elif args.mode == "fit":
        run_fit(args.csv)
