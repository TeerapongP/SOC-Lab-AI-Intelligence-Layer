# SOC-Lab AI Intelligence Layer

This repository contains a SOC-focused intelligence pipeline that enriches Palo Alto PA-5220 network logs with OpenCTI intelligence, assigns weak labels for downstream ML, extracts model-ready features, and supports hybrid retrieval with a RAG index.

## Repository Structure

- `service/`: Main Python enrichment and feature extraction services.
- `opencti/`: OpenCTI stack (platform, worker, connectors) via Docker Compose.
- `grafana/`: Kafka broker and Kafka UI stack via Docker Compose.
- `network/`: Shared and segmented Docker networks.
- `diagrams/`: Architecture and dataflow diagrams for thesis/project design.
- `UWF-ZeekData24_clean.ipynb`: Dataset cleaning notebook for UWF Zeek data.

## High-Level Flow

1. Raw PA-5220 events arrive on Kafka topic `pa5220.raw`.
2. `service/enrich.py` consumes records and queries OpenCTI for IOC context.
3. Events are enriched with IOC confidence, type, MITRE phase, and actor/campaign context.
4. Weak labels are assigned by heuristic rules (`attack`, `normal`, `unknown`).
5. Enriched records are produced to Kafka topic `pa5220.enriched`.
6. Feature extractor consumes `pa5220.enriched`, builds 9-feature vectors, and publishes to `pa5220.features`.
7. Optional RAG indexing pulls indicators from OpenCTI into a hybrid BM25 + vector store.

## Service Components

### 1) Enrichment Pipeline

Core entrypoint:

- `service/enrich.py`

Main classes/modules:

- `service/cti/client.py`
  - Wraps `pycti.OpenCTIApiClient`.
  - Caches lookups using in-process FIFO cache (`FifoCache`).
  - Resolves indicator confidence, IOC type, MITRE phase, and related entities.
- `service/enrich/enricher.py`
  - Converts raw Kafka records to `EnrichedRecord`.
  - Performs routable IP filtering (`dst_ip` first, then `src_ip`).
  - Applies weak labeling rules.
- `service/label/builder.py`
  - Heuristic rules driven by confidence thresholds and MITRE phase.
- `service/pipeline/runner.py`
  - Orchestrates consume -> enrich -> publish loop.
  - Tracks counters and graceful shutdown.
- `service/pipeline/dlq.py`
  - Sends failing messages to `<input-topic>.dlq` with traceback metadata.
- `service/metrics/counters.py`
  - Thread-safe counters for processed/skipped/errors/CTI hit rate.

Data models:

- `service/enrich/models.py`
  - `EnrichedRecord`: raw fields + CTI fields + weak label.
  - `CTIResult`: normalized OpenCTI lookup output.

### 2) Feature Extractor

Modules:

- `service/feature_extractor/extractor.py`
  - Extracts 9 features:
    - Network: `bytes_per_session`, `login_velocity`, `geo_anomaly`, `failed_auth_ratio`, `beaconing_interval`
    - CTI: `ioc_confidence`, `ioc_type_enc`, `mitre_phase_enc`, `actor_known`
  - Supports scaler fit/transform/save/load (`MinMaxScaler`).
  - Loads scaler from `service/models/minmax_scaler.pkl` if present.
- `service/feature_extractor/service.py`
  - Kafka consumer for `pa5220.enriched`.
  - Produces extracted features to `pa5220.features`.

Tests:

- `service/test_feature_extractor.py`
  - Unit tests for feature calculations, encoding behavior, metadata passthrough, and transform behavior.

### 3) RAG Store and Reindexer

Modules:

- `service/rag/store.py`
  - Builds hybrid retrieval index from OpenCTI indicators.
  - BM25 (`rank_bm25`) + dense embeddings (`sentence-transformers`) in ChromaDB.
  - Weighted fusion score:
    - hybrid = BM25_WEIGHT * bm25 + DENSE_WEIGHT * dense
- `service/rag/reindexer.py`
  - Periodically rebuilds index every `RAG_REINDEX_HOURS`.

## Configuration

Main settings file:

- `service/config/settings.py`

Environment files loaded in order:

1. `service/.env`
2. workspace root `.env`

Required variable:

- `OPENCTI_TOKEN`

Important configurable keys:

- Kafka:
  - `KAFKA_BOOTSTRAP`, `KAFKA_INPUT_TOPIC`, `KAFKA_OUTPUT_TOPIC`, `KAFKA_FEATURES_TOPIC`
  - `KAFKA_GROUP_ID`, `KAFKA_FEATURES_GROUP_ID`, `KAFKA_AUTO_OFFSET`
- OpenCTI:
  - `OPENCTI_URL`, `OPENCTI_TOKEN`, `OPENCTI_CACHE_SIZE`
- Label thresholds:
  - `CONF_ATTACK_MIN`, `CONF_NORMAL_MAX`
- Feature extraction:
  - `SCALER_PATH`, `FEATURE_COLUMNS`
- RAG:
  - `CHROMA_HOST`, `CHROMA_PORT`, `CHROMA_COLLECTION`
  - `EMBED_MODEL`, `RAG_TOP_K`, `RAG_REINDEX_HOURS`
  - `BM25_WEIGHT`, `DENSE_WEIGHT`
- Logging:
  - `LOG_LEVEL`, `LOG_KAFKA_LEVEL`

## Infrastructure (Docker Compose)

### Network Layer

File:

- `network/docker-compose.network.yml`

Defines segmented networks including:

- `targets_zone`
- `monitoring_zone`
- `storage_zone`
- `soc_shared`
- `soc_mgmt`

Also includes an `app` (nginx) service for sample/utility exposure.

### Kafka Layer

File:

- `grafana/docker-compose.yml`

Includes:

- `kafka-broker` (KRaft mode, no Zookeeper)
- `kafka-ui`

Exposes:

- Broker host port `9092`
- Kafka UI host port `8083`

### OpenCTI Layer

File:

- `opencti/docker-compose.yml`

Includes:

- Core services: Redis, Elasticsearch, MinIO, RabbitMQ, OpenCTI Platform, OpenCTI Worker
- Connectors (examples): MITRE, AlienVault OTX, Abuse SSL, URLhaus, VirusTotal, AbuseIPDB, IPInfo, Shodan

Platform notes:

- Tuned for Apple Silicon (ARM64) with selected AMD64 OpenCTI images.
- Uses external shared network `soc_shared`.

## Quick Start

### 1) Create and start networks

From repository root:

```bash
docker compose -f network/docker-compose.network.yml up -d
```

### 2) Start Kafka stack

```bash
docker compose -f grafana/docker-compose.yml up -d
```

### 3) Prepare OpenCTI environment

Create `.env` (either root or `service/.env`) and set required OpenCTI and connector values, at minimum:

```bash
OPENCTI_TOKEN=your_opencti_admin_token
OPENCTI_URL=http://localhost:8082
KAFKA_BOOTSTRAP=127.0.0.1:9092
```

Then start OpenCTI:

```bash
docker compose -f opencti/docker-compose.yml up -d
```

### 4) Install Python dependencies

```bash
cd service
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 5) Run enrichment pipeline

```bash
cd service
python enrich.py
```

### 6) Run feature extraction service

In another terminal:

```bash
cd service
python feature_extractor/service.py
```

### 7) Optional: run periodic RAG reindexer

```bash
cd service
python rag/reindexer.py
```

## Topics and Outputs

Default Kafka topics:

- Input: `pa5220.raw`
- Enriched output: `pa5220.enriched`
- Feature output: `pa5220.features`
- Dead letter queue: `pa5220.raw.dlq`

## Logging and Reliability

- Kafka connection retries for consumer startup.
- DLQ fallback for unhandled processing failures.
- In-memory CTI cache to reduce OpenCTI query load.
- Periodic pipeline metrics snapshots include throughput and CTI hit rate.

## Dataset Notebook

Notebook:

- `UWF-ZeekData24_clean.ipynb`

Purpose:

- Cleans UWF Zeek dataset for thesis analysis.
- Includes steps such as type conversion, missing value handling, outlier removal, column normalization, and label cleanup.

## Diagrams and Design Assets

Design files live in `diagrams/` and include project dataflow and SOC architecture draw.io files.

## Security Notes

- Do not commit secrets. `.gitignore` already excludes `.env`, keys, and common sensitive artifacts.
- Keep OpenCTI tokens and connector API keys outside version control.

## Development Notes

- Language: Python 3.11+ recommended.
- Main dependencies: `kafka-python`, `pycti`, `scikit-learn`, `chromadb`, `sentence-transformers`, `rank-bm25`.
- VS Code workspace setting enables terminal auto-approval for Docker Compose commands.
