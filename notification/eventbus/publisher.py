from __future__ import annotations

import json
import time

import pika
import pika.exceptions

from notification.config import settings
from notification.logging_utils import get_logger
from notification.models.alert import LLMAlert

log = get_logger("dashboard.eventbus")


class EventBus:
    """
    Publishes alert events to RabbitMQ.
    Topic routing key: alert.<priority>, for example alert.HIGH.
    """

    def __init__(self) -> None:
        self._conn: pika.BlockingConnection | None = None
        self._channel: pika.channel.Channel | None = None
        self._connect()

    def _connect(self) -> None:
        try:
            params = pika.URLParameters(settings.RABBITMQ_URL)
            params.heartbeat = 30
            params.blocked_connection_timeout = 30
            params.socket_timeout = 10

            self._conn = pika.BlockingConnection(params)
            self._channel = self._conn.channel()
            self._channel.exchange_declare(
                exchange=settings.RABBITMQ_EXCHANGE,
                exchange_type="topic",
                durable=True,
            )
            log.info("EventBus connected - exchange=%s", settings.RABBITMQ_EXCHANGE)
        except pika.exceptions.AMQPConnectionError as exc:
            log.warning("RabbitMQ connection failed: %s", exc)
            self._conn = None
            self._channel = None

    def publish_alert(self, alert: LLMAlert) -> None:
        if not self._ensure_connected():
            log.warning("EventBus not connected - skipping publish for %s", alert.alert_id)
            return

        routing_key = f"alert.{alert.priority.value}"
        body = json.dumps(alert.to_dict()).encode("utf-8")

        if self._publish(routing_key, body, alert.alert_id):
            return

        log.warning("EventBus publish failed for %s; reconnecting and retrying once", alert.alert_id)
        self._connect()
        if not self._ensure_connected() or not self._publish(routing_key, body, alert.alert_id):
            log.error("EventBus publish permanently failed for %s", alert.alert_id)

    def _ensure_connected(self) -> bool:
        if self._conn and self._conn.is_open and self._channel and self._channel.is_open:
            return True
        self._connect()
        return bool(self._conn and self._conn.is_open and self._channel and self._channel.is_open)

    def _publish(self, routing_key: str, body: bytes, alert_id: str) -> bool:
        try:
            assert self._channel is not None
            self._channel.basic_publish(
                exchange=settings.RABBITMQ_EXCHANGE,
                routing_key=routing_key,
                body=body,
                properties=pika.BasicProperties(
                    delivery_mode=2,
                    content_type="application/json",
                ),
            )
            log.debug("Published %s -> %s", alert_id, routing_key)
            return True
        except (pika.exceptions.AMQPError, OSError) as exc:
            log.warning("RabbitMQ publish attempt failed for %s: %s", alert_id, exc)
            self._channel = None
            self._conn = None
            time.sleep(0.2)
            return False

    def close(self) -> None:
        try:
            if self._conn and self._conn.is_open:
                self._conn.close()
                log.info("EventBus connection closed")
        except Exception as exc:
            log.warning("EventBus close error: %s", exc)
