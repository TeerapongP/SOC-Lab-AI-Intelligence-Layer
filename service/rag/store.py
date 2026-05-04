from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Optional

import requests

from enrich.config import settings
from enrich.utils.logging import get_logger

log = get_logger("rag.store")


@dataclass
class StixChunk:
    """Approximate 500-token STIX text chunk ready for embedding."""

    chunk_id: str
    text: str
    ioc_value: str
    ioc_type: str
    mitre_phase: str
    actor_name: str
    source: str


@dataclass
class RetrievalResult:
    chunk: StixChunk
    bm25_score: float
    dense_score: float

    @property
    def hybrid_score(self) -> float:
        return settings.BM25_WEIGHT * self.bm25_score + settings.DENSE_WEIGHT * self.dense_score


class HybridVectorStore:
    """
    Hybrid RAG store: BM25 exact-ish match plus dense vector semantic search.
    """

    def __init__(self) -> None:
        self._collection = None
        self._bm25 = None
        self._chunks: list[StixChunk] = []
        self._last_index = 0.0
        self._embed_model = None

    def ensure_indexed(self) -> None:
        hours_since = (time.time() - self._last_index) / 3600
        if self._collection is None or hours_since >= settings.RAG_REINDEX_HOURS:
            self._build_index()

    def retrieve(self, query: str, top_k: int | None = None) -> list[RetrievalResult]:
        self.ensure_indexed()
        k = top_k or settings.RAG_TOP_K

        if not self._chunks:
            log.warning("No chunks indexed; returning empty results")
            return []

        bm25_scores = self._bm25_score(query)
        dense_scores = self._dense_score(query, k * 3)

        results: dict[str, RetrievalResult] = {}
        for i, score in enumerate(bm25_scores):
            if score > 0:
                chunk = self._chunks[i]
                results[chunk.chunk_id] = RetrievalResult(chunk, float(score), 0.0)

        for chunk_id, score in dense_scores:
            if chunk_id in results:
                results[chunk_id].dense_score = score
            else:
                chunk = self._get_chunk(chunk_id)
                if chunk:
                    results[chunk_id] = RetrievalResult(chunk, 0.0, score)

        ranked = sorted(results.values(), key=lambda r: r.hybrid_score, reverse=True)
        return ranked[:k]

    def retrieve_for_alert(self, ioc_value: str, mitre_phase: str, actor_name: str) -> list[StixChunk]:
        query = f"{ioc_value} {mitre_phase} {actor_name}".strip()
        return [r.chunk for r in self.retrieve(query)]

    def _build_index(self) -> None:
        log.info("Building RAG index from OpenCTI...")
        chunks = self._fetch_stix_chunks()
        if not chunks:
            log.warning("No STIX chunks fetched from OpenCTI")
            return

        self._chunks = chunks
        self._init_bm25(chunks)
        self._init_chroma(chunks)
        self._last_index = time.time()
        log.info("RAG index built; chunks=%d", len(chunks))

    def _fetch_stix_chunks(self) -> list[StixChunk]:
        try:
            response = requests.post(
                settings.OPENCTI_URL.rstrip("/") + "/graphql",
                headers={
                    "Authorization": f"Bearer {settings.OPENCTI_TOKEN}",
                    "Content-Type": "application/json",
                },
                json={
                    "query": """
                    query RAGIndicators {
                      indicators(first: 500) {
                        edges {
                          node {
                            id
                            name
                            pattern
                            confidence
                            indicator_types
                            killChainPhases { edges { node { phase_name } } }
                            objectLabel { edges { node { value } } }
                          }
                        }
                      }
                    }
                    """
                },
                timeout=60,
            )
            response.raise_for_status()
            payload = response.json()
            if payload.get("errors"):
                raise RuntimeError(payload["errors"][0].get("message", payload["errors"]))
            indicators = payload.get("data", {}).get("indicators", {})
        except Exception as exc:
            log.error("OpenCTI fetch failed: %s", exc)
            return []

        chunks: list[StixChunk] = []
        for edge in indicators.get("edges", []):
            chunk = self._node_to_chunk(edge.get("node", {}))
            if chunk:
                chunks.append(chunk)
        return chunks

    def _node_to_chunk(self, node: dict) -> Optional[StixChunk]:
        value = node.get("name") or node.get("pattern", "")
        if not value:
            return None

        pattern = node.get("pattern", "")
        types = node.get("indicator_types") or []
        ioc_type = types[0] if types else self._infer_ioc_type(pattern)
        kc_edges = node.get("killChainPhases", {}).get("edges", [])
        phase = kc_edges[0]["node"].get("phase_name", "none") if kc_edges else "none"
        labels = [e["node"]["value"] for e in node.get("objectLabel", {}).get("edges", [])]
        confidence = node.get("confidence", 0) or 0

        text = (
            f"Indicator: {value}\n"
            f"Pattern: {pattern or 'none'}\n"
            f"Type: {ioc_type}\n"
            f"MITRE phase: {phase}\n"
            f"Confidence: {confidence}/100\n"
            f"Labels: {', '.join(labels) or 'none'}\n"
        )

        chunk_id = node.get("id") or hashlib.md5(value.encode()).hexdigest()
        return StixChunk(chunk_id, text, value, ioc_type, phase, "", "opencti")

    def _infer_ioc_type(self, pattern: str) -> str:
        for marker in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "file"):
            if marker in pattern:
                return marker
        return "none"

    def _init_bm25(self, chunks: list[StixChunk]) -> None:
        try:
            from rank_bm25 import BM25Okapi
        except ImportError:
            log.warning("rank_bm25 not installed; BM25 disabled")
            return
        self._bm25 = BM25Okapi([c.text.lower().split() for c in chunks])

    def _bm25_score(self, query: str) -> list[float]:
        if self._bm25 is None:
            return [0.0] * len(self._chunks)
        scores = self._bm25.get_scores(query.lower().split())
        max_s = max(scores) if scores.max() > 0 else 1.0
        return (scores / max_s).tolist()

    def _init_chroma(self, chunks: list[StixChunk]) -> None:
        try:
            import chromadb
            from sentence_transformers import SentenceTransformer
        except ImportError:
            log.warning("chromadb or sentence-transformers not installed; dense search disabled")
            return

        client = chromadb.HttpClient(host=settings.CHROMA_HOST, port=settings.CHROMA_PORT)
        try:
            client.delete_collection(settings.CHROMA_COLLECTION)
        except Exception:
            pass

        self._collection = client.get_or_create_collection(settings.CHROMA_COLLECTION)
        self._embed_model = SentenceTransformer(settings.EMBED_MODEL)

        batch_size = 100
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i : i + batch_size]
            texts = [c.text for c in batch]
            ids = [c.chunk_id for c in batch]
            metas = [{"ioc_value": c.ioc_value, "mitre_phase": c.mitre_phase} for c in batch]
            embs = self._embed_model.encode(texts).tolist()
            self._collection.add(documents=texts, embeddings=embs, ids=ids, metadatas=metas)
            log.info("Indexed RAG batch %d-%d/%d", i + 1, min(i + batch_size, len(chunks)), len(chunks))

        log.info("ChromaDB collection populated with %d chunks", len(chunks))

    def _dense_score(self, query: str, top_k: int) -> list[tuple[str, float]]:
        if self._collection is None or self._embed_model is None:
            return []
        emb = self._embed_model.encode([query]).tolist()
        results = self._collection.query(query_embeddings=emb, n_results=top_k)
        ids = results.get("ids", [[]])[0]
        distances = results.get("distances", [[]])[0]
        return [(cid, 1.0 - dist) for cid, dist in zip(ids, distances)]

    def _get_chunk(self, chunk_id: str) -> Optional[StixChunk]:
        return next((c for c in self._chunks if c.chunk_id == chunk_id), None)
