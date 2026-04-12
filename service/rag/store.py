from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Optional

from enrich.config import settings
from enrich.utils.logging import get_logger

log = get_logger("rag.store")


@dataclass
class StixChunk:
    """~500-token STIX text chunk ready for embedding."""
    chunk_id:    str
    text:        str
    ioc_value:   str
    ioc_type:    str
    mitre_phase: str
    actor_name:  str
    source:      str   # e.g. "opencti"


@dataclass
class RetrievalResult:
    chunk:       StixChunk
    bm25_score:  float
    dense_score: float

    @property
    def hybrid_score(self) -> float:
        return (
            settings.BM25_WEIGHT  * self.bm25_score +
            settings.DENSE_WEIGHT * self.dense_score
        )


class HybridVectorStore:
    """
    Hybrid RAG store: BM25 (exact match) + Dense vector (semantic).

    Indexing:
      - Pulls STIX indicator chunks from OpenCTI via pycti
      - Embeds using sentence-transformers
      - Stores in ChromaDB
      - Re-indexes every RAG_REINDEX_HOURS

    Retrieval:
      - BM25 score from rank_bm25
      - Dense cosine similarity from ChromaDB
      - Weighted hybrid fusion → top-k chunks
    """

    def __init__(self) -> None:
        self._collection = None
        self._bm25       = None
        self._chunks:    list[StixChunk] = []
        self._last_index: float = 0.0
        self._embed_model = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def ensure_indexed(self) -> None:
        """Index if collection is empty or re-index interval has passed."""
        hours_since = (time.time() - self._last_index) / 3600
        if self._collection is None or hours_since >= settings.RAG_REINDEX_HOURS:
            self._build_index()

    def retrieve(self, query: str, top_k: int | None = None) -> list[RetrievalResult]:
        """
        Retrieve top-k STIX chunks for a query string.
        Returns sorted list by hybrid_score descending.
        """
        self.ensure_indexed()
        k = top_k or settings.RAG_TOP_K

        if not self._chunks:
            log.warning("No chunks indexed — returning empty results")
            return []

        bm25_scores  = self._bm25_score(query)
        dense_scores = self._dense_score(query, k * 3)

        results: dict[str, RetrievalResult] = {}

        for i, score in enumerate(bm25_scores):
            if score > 0:
                chunk = self._chunks[i]
                results[chunk.chunk_id] = RetrievalResult(
                    chunk=chunk, bm25_score=float(score), dense_score=0.0
                )

        for chunk_id, score in dense_scores:
            if chunk_id in results:
                results[chunk_id].dense_score = score
            else:
                chunk = self._get_chunk(chunk_id)
                if chunk:
                    results[chunk_id] = RetrievalResult(
                        chunk=chunk, bm25_score=0.0, dense_score=score
                    )

        ranked = sorted(results.values(), key=lambda r: r.hybrid_score, reverse=True)
        return ranked[:k]

    def retrieve_for_alert(self, ioc_value: str, mitre_phase: str, actor_name: str) -> list[StixChunk]:
        """Convenience method — build query from alert fields and retrieve."""
        query = f"{ioc_value} {mitre_phase} {actor_name}".strip()
        results = self.retrieve(query)
        return [r.chunk for r in results]

    # ── Indexing ────────────────────────────────────────────────────────────────

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
        log.info("RAG index built — %d chunks", len(chunks))

    def _fetch_stix_chunks(self) -> list[StixChunk]:
        """Fetch indicators from OpenCTI and convert to ~500-token text chunks."""
        try:
            from pycti import OpenCTIApiClient
        except ImportError:
            log.error("pycti not installed")
            return []

        try:
            client = OpenCTIApiClient(settings.OPENCTI_URL, settings.OPENCTI_TOKEN, log_level="error")
            indicators = client.indicator.list(
                first=500,
                customAttributes="""
                    id value confidence indicator_types
                    killChainPhases { edges { node { phase_name } } }
                    objectLabel { edges { node { value } } }
                """,
            )
        except Exception as exc:
            log.error("OpenCTI fetch failed: %s", exc)
            return []

        chunks: list[StixChunk] = []
        for edge in (indicators or {}).get("edges", []):
            node = edge.get("node", {})
            chunk = self._node_to_chunk(node)
            if chunk:
                chunks.append(chunk)
        return chunks

    def _node_to_chunk(self, node: dict) -> Optional[StixChunk]:
        value      = node.get("value", "")
        if not value:
            return None

        types      = node.get("indicator_types") or []
        ioc_type   = types[0] if types else "none"
        kc_edges   = node.get("killChainPhases", {}).get("edges", [])
        phase      = kc_edges[0]["node"].get("phase_name", "none") if kc_edges else "none"
        labels     = [e["node"]["value"] for e in node.get("objectLabel", {}).get("edges", [])]
        confidence = node.get("confidence", 0) or 0

        text = (
            f"Indicator: {value}\n"
            f"Type: {ioc_type}\n"
            f"MITRE phase: {phase}\n"
            f"Confidence: {confidence}/100\n"
            f"Labels: {', '.join(labels) or 'none'}\n"
        )

        chunk_id = hashlib.md5(value.encode()).hexdigest()
        return StixChunk(
            chunk_id=chunk_id, text=text,
            ioc_value=value, ioc_type=ioc_type,
            mitre_phase=phase, actor_name="",
            source="opencti",
        )

    # ── BM25 ────────────────────────────────────────────────────────────────────

    def _init_bm25(self, chunks: list[StixChunk]) -> None:
        try:
            from rank_bm25 import BM25Okapi
        except ImportError:
            log.warning("rank_bm25 not installed — BM25 disabled")
            return
        tokenized = [c.text.lower().split() for c in chunks]
        self._bm25 = BM25Okapi(tokenized)

    def _bm25_score(self, query: str) -> list[float]:
        if self._bm25 is None:
            return [0.0] * len(self._chunks)
        scores = self._bm25.get_scores(query.lower().split())
        max_s  = max(scores) if scores.max() > 0 else 1.0
        return (scores / max_s).tolist()

    # ── Dense / ChromaDB ────────────────────────────────────────────────────────

    def _init_chroma(self, chunks: list[StixChunk]) -> None:
        try:
            import chromadb
            from sentence_transformers import SentenceTransformer
        except ImportError:
            log.warning("chromadb or sentence-transformers not installed — dense search disabled")
            return

        client = chromadb.HttpClient(host=settings.CHROMA_HOST, port=settings.CHROMA_PORT)
        try:
            client.delete_collection(settings.CHROMA_COLLECTION)
        except Exception:
            pass

        self._collection  = client.get_or_create_collection(settings.CHROMA_COLLECTION)
        self._embed_model = SentenceTransformer(settings.EMBED_MODEL)

        batch_size = 100
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i: i + batch_size]
            texts = [c.text for c in batch]
            ids   = [c.chunk_id for c in batch]
            metas = [{"ioc_value": c.ioc_value, "mitre_phase": c.mitre_phase} for c in batch]
            embs  = self._embed_model.encode(texts).tolist()
            self._collection.add(documents=texts, embeddings=embs, ids=ids, metadatas=metas)

        log.info("ChromaDB collection populated with %d chunks", len(chunks))

    def _dense_score(self, query: str, top_k: int) -> list[tuple[str, float]]:
        if self._collection is None or self._embed_model is None:
            return []
        emb     = self._embed_model.encode([query]).tolist()
        results = self._collection.query(query_embeddings=emb, n_results=top_k)
        ids      = results.get("ids",      [[]])[0]
        distances = results.get("distances", [[]])[0]
        return [(cid, 1.0 - dist) for cid, dist in zip(ids, distances)]

    def _get_chunk(self, chunk_id: str) -> Optional[StixChunk]:
        return next((c for c in self._chunks if c.chunk_id == chunk_id), None)
