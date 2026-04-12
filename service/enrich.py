from __future__ import annotations

import sys
import types
from pathlib import Path

# Make `enrich.*` imports work when running this file as a script.
# `enrich.config` lives under service/config, while `enrich.enricher`
# lives under service/enrich/enricher.py, so expose both roots.
_SERVICE_ROOT = Path(__file__).resolve().parent
_ENRICH_DIR = _SERVICE_ROOT / "enrich"

pkg = sys.modules.get("enrich")
if pkg is None:
    pkg = types.ModuleType("enrich")
    sys.modules["enrich"] = pkg

pkg.__path__ = [str(_SERVICE_ROOT), str(_ENRICH_DIR)]

from enrich.config import settings
from enrich.cti.client import CTIClient
from enrich.kafka.factory import make_consumer, make_producer
from enrich.metrics.counters import PipelineMetrics
from enrich.pipeline.dlq import DeadLetterQueue
from enrich.pipeline.runner import EnrichmentPipeline
from enrich.utils.logging import get_logger, setup_logging

setup_logging()
log = get_logger("enrich")


def main() -> None:
    cti      = CTIClient(settings.OPENCTI_URL, settings.OPENCTI_TOKEN, settings.OPENCTI_CACHE_SIZE)
    consumer = make_consumer()
    producer = make_producer()
    dlq      = DeadLetterQueue(source_topic=settings.KAFKA_INPUT_TOPIC)
    metrics  = PipelineMetrics()

    pipeline = EnrichmentPipeline(
        consumer=consumer,
        producer=producer,
        cti=cti,
        dlq=dlq,
        metrics=metrics,
    )
    pipeline.run()


if __name__ == "__main__":
    main()
