# Thesis SOC Runbook Without LLM, ML, Or Outlook

This runbook starts and tests the currently enabled layers only:

- Data and Kafka ingest plumbing
- Service layer enrichment / feature services
- OpenCTI and Elasticsearch
- Observability with InfluxDB, Kibana, Logstash, Grafana
- Notification dispatcher with LINE, RabbitMQ, InfluxDB, Elasticsearch, and Kafka DLQ

## Start Order

Run from `E:\thesis`.

```powershell
docker compose -f network\docker-compose.network.yml up -d
docker compose -f grafana\docker-compose.yml up -d
docker compose -f opencti\docker-compose.yml up -d
docker compose -f observability\docker-compose.yml up -d
docker compose -f service\docker-compose.yml up -d kafka-init
docker compose -f service\docker-compose.yml up -d enrich feature-extractor rag-reindexer
docker compose -f notification\docker-compose.yml up -d --build
```

## URLs

- OpenCTI: `http://localhost:8082`
- Kibana: `http://localhost:5601`
- Kafka UI: `http://localhost:8083`
- Grafana: `http://localhost:3000`
- InfluxDB: `http://localhost:8086`
- Elasticsearch: `http://localhost:9200`

Grafana default local login is `admin` / `admin` unless overridden with `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD`.

## Smoke Test Notification Only

This bypasses LLM and ML by writing a valid alert directly to `pa5220.llm_output`, then verifies:

- Notification consumes the alert
- Elasticsearch receives the alert document
- Malformed JSON is routed to `pa5220.llm_output.dlq`

```powershell
docker compose -f notification\docker-compose.yml run --rm alert-dispatcher `
  python -m notification.scripts.smoke_notification_pipeline
```

Expected output:

```text
notification smoke ok
alert_id=smoke-notification-...
dlq_stage=parse
dlq_error_type=JSONDecodeError
```

## Health Checks

```powershell
docker compose -f notification\docker-compose.yml ps
docker compose -f notification\docker-compose.yml logs --tail=80 alert-dispatcher
docker compose -f grafana\docker-compose.yml ps
docker compose -f observability\docker-compose.yml ps
docker compose -f opencti\docker-compose.yml ps
```

## Kafka Topics

```powershell
docker exec grafana-kafka-broker-1 kafka-topics --bootstrap-server localhost:9092 --list
```

Required topics:

- `pa5220.raw`
- `pa5220.enriched`
- `pa5220.features`
- `pa5220.llm_output`
- `pa5220.llm_output.dlq`
- `pa5220.raw.dlq`

## Notes

- Outlook integration is intentionally disabled for now.
- LLM and ML layers are intentionally bypassed in this smoke test.
- Elasticsearch security is enabled locally without TLS. Rotate secrets and enable TLS before production use.
