from __future__ import annotations

import logging

from notification.config import settings


def setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    logging.getLogger("kafka").setLevel(
        getattr(logging, settings.LOG_KAFKA_LEVEL, logging.WARNING)
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
