from __future__ import annotations

import os
import pickle
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

import numpy as np

from enrich.config import settings
from enrich.models import EnrichedRecord
from enrich.utils.logging import get_logger

log = get_logger("feature_extractor")

# ── IOC type → ordinal encoding ───────────────────────────────────────────────
_IOC_TYPE_MAP: dict[str, int] = {
    "none":        0,
    "ipv4-addr":   1,
    "domain-name": 2,
    "url":         3,
    "file":        4,
}

# ── MITRE phase → ordinal encoding (severity proxy) ──────────────────────────
_MITRE_PHASE_MAP: dict[str, int] = {
    "none":                  0,
    "reconnaissance":        1,
    "resource-development":  1,
    "initial-access":        2,
    "execution":             3,
    "persistence":           3,
    "privilege-escalation":  4,
    "defense-evasion":       4,
    "credential-access":     5,
    "discovery":             2,
    "lateral-movement":      6,
    "collection":            6,
    "command-and-control":   7,
    "exfiltration":          8,
    "impact":                9,
}


@dataclass
class FeatureVector:
    """9-feature vector ready for ML model input."""

    # ── Network features (5) ──────────────────────────────────────────────────
    bytes_per_session:    float   # bytes_sent + bytes_recv / session_duration
    login_velocity:       float   # packets / session_duration (proxy)
    geo_anomaly:          float   # 0 or 1 — placeholder for GeoIP check
    failed_auth_ratio:    float   # 0.0–1.0 — from action=="deny" ratio (session)
    beaconing_interval:   float   # session_duration proxy for beaconing

    # ── CTI features (4) ─────────────────────────────────────────────────────
    ioc_confidence:       float   # 0.0–1.0 from OpenCTI
    ioc_type_enc:         int     # ordinal encoded ioc_type
    mitre_phase_enc:      int     # ordinal encoded mitre_phase
    actor_known:          int     # 0 or 1

    # ── Metadata (not ML features — pass-through for downstream) ─────────────
    src_ip:               str     = ""
    dst_ip:               str     = ""
    dst_port:             int     = 0
    action:               str     = ""
    timestamp:            str     = ""
    weak_label:           str     = "unknown"
    actor_name:           str     = ""
    campaign_name:        str     = ""
    threat_name:          str     = ""
    mitre_phase:          str     = "none"

    # ── Scaled values (filled after fit/transform) ────────────────────────────
    scaled: Optional[list[float]] = None


class FeatureExtractor:
    """
    Extracts and scales the 9-feature vector from an EnrichedRecord.

    Scaler lifecycle:
      - fit(records)        — fit MinMaxScaler on training set ONLY (no leakage)
      - save_scaler(path)   — persist to disk
      - load_scaler(path)   — reload for inference
      - transform(record)   — scale at inference time
    """

    _NETWORK_FEATURES = [
        "bytes_per_session",
        "login_velocity",
        "geo_anomaly",
        "failed_auth_ratio",
        "beaconing_interval",
    ]
    _CTI_FEATURES = [
        "ioc_confidence",
        "ioc_type_enc",
        "mitre_phase_enc",
        "actor_known",
    ]
    ALL_FEATURES = _NETWORK_FEATURES + _CTI_FEATURES

    def __init__(self) -> None:
        self._scaler = None
        scaler_path = Path(settings.SCALER_PATH)
        if scaler_path.exists():
            self.load_scaler(scaler_path)
            log.info("Scaler loaded from %s", scaler_path)

    # ── Public API ─────────────────────────────────────────────────────────────

    def extract(self, rec: EnrichedRecord) -> FeatureVector:
        """Extract raw (unscaled) features from an EnrichedRecord."""
        duration = max(rec.session_duration, 0.001)  # avoid div/0
        total_bytes = rec.bytes_sent + rec.bytes_recv

        fv = FeatureVector(
            bytes_per_session  = total_bytes / duration,
            login_velocity     = rec.packets / duration,
            geo_anomaly        = 0.0,           # populated by GeoIP service (future)
            failed_auth_ratio  = 1.0 if rec.action == "deny" else 0.0,
            beaconing_interval = duration,
            ioc_confidence     = rec.ioc_confidence,
            ioc_type_enc       = _IOC_TYPE_MAP.get(rec.ioc_type, 0),
            mitre_phase_enc    = _MITRE_PHASE_MAP.get(rec.mitre_phase, 0),
            actor_known        = rec.actor_known,
            src_ip             = rec.src_ip,
            dst_ip             = rec.dst_ip,
            dst_port           = rec.dst_port,
            action             = rec.action,
            timestamp          = rec.timestamp,
            weak_label         = rec.weak_label,
            actor_name         = rec.actor_name,
            campaign_name      = rec.campaign_name,
            threat_name        = rec.threat_name,
            mitre_phase        = rec.mitre_phase,
        )
        return fv

    def fit(self, records: list[EnrichedRecord]) -> "FeatureExtractor":
        """Fit MinMaxScaler on training records only (call once, never on test set)."""
        try:
            from sklearn.preprocessing import MinMaxScaler
        except ImportError:
            raise ImportError("scikit-learn is required: pip install scikit-learn")

        vectors = [self._to_array(self.extract(r)) for r in records]
        X = np.array(vectors)
        self._scaler = MinMaxScaler()
        self._scaler.fit(X)
        log.info("Scaler fitted on %d records", len(records))
        return self

    def transform(self, fv: FeatureVector) -> FeatureVector:
        """Scale a FeatureVector using the fitted scaler."""
        if self._scaler is None:
            log.warning("Scaler not fitted — returning unscaled features")
            fv.scaled = self._to_array(fv)
            return fv
        raw = np.array([self._to_array(fv)])
        fv.scaled = self._scaler.transform(raw)[0].tolist()
        return fv

    def save_scaler(self, path: str | Path) -> None:
        if self._scaler is None:
            raise RuntimeError("Scaler not fitted yet")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self._scaler, f)
        log.info("Scaler saved to %s", path)

    def load_scaler(self, path: str | Path) -> None:
        with open(path, "rb") as f:
            self._scaler = pickle.load(f)

    # ── Private ────────────────────────────────────────────────────────────────

    def _to_array(self, fv: FeatureVector) -> list[float]:
        return [
            fv.bytes_per_session,
            fv.login_velocity,
            fv.geo_anomaly,
            fv.failed_auth_ratio,
            fv.beaconing_interval,
            fv.ioc_confidence,
            float(fv.ioc_type_enc),
            float(fv.mitre_phase_enc),
            float(fv.actor_known),
        ]


def to_dict(fv: FeatureVector) -> dict:
    d = asdict(fv)
    d.pop("scaled", None)
    return d
