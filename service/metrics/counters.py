from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class PipelineMetrics:
    """
    Thread-safe in-process counters for the enrichment pipeline.
    Logged periodically by the runner; can be extended to push
    to Prometheus/StatsD later without touching pipeline logic.
    """

    _lock:      threading.Lock = field(default_factory=threading.Lock, repr=False)
    _start_time: float         = field(default_factory=time.monotonic,  repr=False)

    processed:  int = 0
    skipped:    int = 0
    errors:     int = 0
    cti_hits:   int = 0   # lookups that returned confidence > 0
    cti_misses: int = 0   # lookups that returned confidence == 0
    dlq_sent:   int = 0   # messages sent to dead-letter topic

    def inc(self, counter: str, amount: int = 1) -> None:
        with self._lock:
            current = getattr(self, counter, None)
            if current is None:
                raise AttributeError(f"Unknown counter: {counter!r}")
            setattr(self, counter, current + amount)

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = max(time.monotonic() - self._start_time, 1)
            return {
                "processed":  self.processed,
                "skipped":    self.skipped,
                "errors":     self.errors,
                "cti_hits":   self.cti_hits,
                "cti_misses": self.cti_misses,
                "dlq_sent":   self.dlq_sent,
                "throughput_per_sec": round(self.processed / elapsed, 2),
                "error_rate_pct": round(
                    100 * self.errors / max(self.processed + self.errors, 1), 2
                ),
                "cti_hit_rate_pct": round(
                    100 * self.cti_hits / max(self.cti_hits + self.cti_misses, 1), 2
                ),
            }
