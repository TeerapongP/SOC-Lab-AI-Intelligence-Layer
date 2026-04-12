from __future__ import annotations

import json

import pika

from notification.config import settings
from notification.models.alert import LLMAlert, Priority
from notification.logging_utils import get_logger

log = get_logger("dashboard.eventbus")


class EventBus:
    """
    Publishes alert events to RabbitMQ with topic routing.

    Exchange: soc.events (topic)
    Routing keys:
      HIGH   → alert.high
      MEDIUM → alert.medium
      LOW    → alert.low
      metrics → metrics.layer
    """

    def __init__(self) -> None:
        self._connection = None
        self._channel    = None
        self._connect()

    def _connect(self) -> None:
        params = pika.URLParameters(settings.RABBITMQ_URL)
        self._connection = pika.BlockingConnection(params)
        self._channel    = self._connection.channel()
        self._channel.exchange_declare(
            exchange=settings.RABBITMQ_EXCHANGE,
            exchange_type="topic",
            durable=True,
        )
        log.info("Connected to RabbitMQ exchange=%s", settings.RABBITMQ_EXCHANGE)

    def publish_alert(self, alert: LLMAlert) -> None:
        routing_key = self._routing_key(alert.priority)
        body = json.dumps({
            "priority":       alert.priority.value,
            "risk_score":     alert.risk_score,
            "source_ip":      alert.source_ip,
            "dst_port":       alert.dst_port,
            "mitre_tactic":   alert.mitre_tactic,
            "anomaly_type":   alert.anomaly_type,
            "affected_asset": alert.affected_asset,
            "explanation_th": alert.explanation_th,
            "remediation":    alert.remediation,
            "timestamp":      alert.timestamp,
            "model_used":     alert.model_used,
        }).encode()

        self._channel.basic_publish(
            exchange=settings.RABBITMQ_EXCHANGE,
            routing_key=routing_key,
            body=body,
            properties=pika.BasicProperties(
                delivery_mode=2,   # persistent
                content_type="application/json",
            ),
        )
        log.debug("Published alert routing_key=%s risk=%d", routing_key, alert.risk_score)

    def publish_metrics(self, layer: str, metrics: dict) -> None:
        body = json.dumps({"layer": layer, **metrics}).encode()
        self._channel.basic_publish(
            exchange=settings.RABBITMQ_EXCHANGE,
            routing_key=settings.RABBITMQ_METRICS_ROUTING,
            body=body,
            properties=pika.BasicProperties(
                delivery_mode=2,
                content_type="application/json",
            ),
        )

    def close(self) -> None:
        if self._connection and not self._connection.is_closed:
            self._connection.close()

    @staticmethod
    def _routing_key(priority: Priority) -> str:
        return {
            Priority.HIGH:   settings.RABBITMQ_HIGH_ROUTING,
            Priority.MEDIUM: settings.RABBITMQ_MEDIUM_ROUTING,
            Priority.LOW:    settings.RABBITMQ_LOW_ROUTING,
        }[priority]
