from __future__ import annotations

import json

import pika
import pika.exceptions

from notification.config import settings
from notification.models.alert import LLMAlert
from notification.logging_utils import get_logger

log = get_logger("dashboard.eventbus")


class EventBus:
    """
    Publishes alert events to RabbitMQ (reuse opencti-rabbitmq).
    Topic routing key: alert.<priority>   e.g. alert.HIGH
    """

    def __init__(self) -> None:
        self._conn:    pika.BlockingConnection | None = None
        self._channel: pika.channel.Channel | None   = None
        self._connect()

    def _connect(self) -> None:
        try:
            params = pika.URLParameters(settings.RABBITMQ_URL)
            self._conn    = pika.BlockingConnection(params)
            self._channel = self._conn.channel()
            self._channel.exchange_declare(
                exchange      = settings.RABBITMQ_EXCHANGE,
                exchange_type = "topic",
                durable       = True,
            )
            log.info("EventBus connected — exchange=%s", settings.RABBITMQ_EXCHANGE)
        except pika.exceptions.AMQPConnectionError as exc:
            log.error("RabbitMQ connection failed: %s", exc, exc_info=True)
            self._conn    = None
            self._channel = None

    def publish_alert(self, alert: LLMAlert) -> None:
        if self._channel is None:
            log.warning("EventBus not connected — skipping publish for %s", alert.alert_id)
            return

        routing_key = f"alert.{alert.priority.value}"
        body        = json.dumps(alert.to_dict()).encode()

        try:
            self._channel.basic_publish(
                exchange     = settings.RABBITMQ_EXCHANGE,
                routing_key  = routing_key,
                body         = body,
                properties   = pika.BasicProperties(
                    delivery_mode = 2,          # persistent
                    content_type  = "application/json",
                ),
            )
            log.debug("Published %s → %s", alert.alert_id, routing_key)
        except pika.exceptions.AMQPError as exc:
            log.error("Publish failed for %s: %s", alert.alert_id, exc, exc_info=True)
            # attempt reconnect for next message
            self._connect()

    def close(self) -> None:
        try:
            if self._conn and self._conn.is_open:
                self._conn.close()
                log.info("EventBus connection closed")
        except Exception as exc:
            log.warning("EventBus close error: %s", exc)
