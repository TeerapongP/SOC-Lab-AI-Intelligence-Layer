from __future__ import annotations

import signal
import time

from enrich.config import settings
from enrich.utils.logging import get_logger, setup_logging
from rag.store import HybridVectorStore

setup_logging()
log = get_logger("rag.reindexer")

_RUNNING = True


def _handle_stop(signum, frame):
    global _RUNNING
    log.info("Shutdown signal received")
    _RUNNING = False


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    store = HybridVectorStore()
    interval_s = settings.RAG_REINDEX_HOURS * 3600

    log.info("RAG reindexer started — interval=%dh", settings.RAG_REINDEX_HOURS)

    while _RUNNING:
        try:
            store._build_index()
        except Exception as exc:
            log.error("Reindex failed: %s", exc)

        log.info("Next reindex in %dh", settings.RAG_REINDEX_HOURS)
        deadline = time.time() + interval_s
        while _RUNNING and time.time() < deadline:
            time.sleep(30)

    log.info("RAG reindexer stopped")


if __name__ == "__main__":
    main()
