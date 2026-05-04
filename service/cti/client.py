from __future__ import annotations

import requests

from enrich.models import CTIResult
from enrich.utils.cache import FifoCache
from enrich.utils.logging import get_logger

log = get_logger("enrich.cti")

_RELATION_TYPES = {"attributed-to", "indicates"}


class CTIClient:
    """
    OpenCTI GraphQL client with an in-process FIFO cache.

    The direct GraphQL calls keep this service compatible with the local
    OpenCTI 5.12 schema instead of relying on a pycti client version match.
    """

    def __init__(self, url: str, token: str, cache_size: int = 5_000) -> None:
        self._graphql_url = url.rstrip("/") + "/graphql"
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self._cache: FifoCache[CTIResult] = FifoCache(maxsize=cache_size)
        log.info("Connected to OpenCTI at %s", url)

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def lookup(self, ip: str) -> CTIResult:
        """
        Query OpenCTI for an IP indicator.
        Returns a CTIResult with zero/none defaults on miss.
        """
        if ip in self._cache:
            return self._cache.get(ip)  # type: ignore[return-value]

        result = CTIResult()

        try:
            data = self._graphql(
                """
                query LookupIndicator($filters: FilterGroup) {
                  indicators(first: 1, filters: $filters) {
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
                """,
                {
                    "filters": {
                        "mode": "and",
                        "filters": [{"key": "name", "values": [ip]}],
                        "filterGroups": [],
                    }
                },
            )

            edges = data.get("indicators", {}).get("edges", [])
            if not edges:
                self._cache.set(ip, result)
                return result

            node = edges[0]["node"]
            result = self._parse_indicator(node)
            result = self._enrich_with_relations(node.get("id", ""), result)

        except Exception as exc:
            log.warning("OpenCTI lookup failed for %s: %s", ip, exc)

        self._cache.set(ip, result)
        return result

    def _graphql(self, query: str, variables: dict | None = None) -> dict:
        response = requests.post(
            self._graphql_url,
            headers=self._headers,
            json={"query": query, "variables": variables or {}},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("errors"):
            raise RuntimeError(payload["errors"][0].get("message", payload["errors"]))
        return payload.get("data") or {}

    def _parse_indicator(self, node: dict) -> CTIResult:
        conf_raw = node.get("confidence", 0) or 0
        confidence = round(min(conf_raw / 100.0, 1.0), 4)

        types = node.get("indicator_types") or []
        ioc_type = types[0] if types else self._infer_ioc_type(node.get("pattern", ""))

        mitre_phase = "none"
        edges = node.get("killChainPhases", {}).get("edges", [])
        if edges:
            mitre_phase = edges[0].get("node", {}).get("phase_name") or "none"

        return CTIResult(confidence=confidence, ioc_type=ioc_type, mitre_phase=mitre_phase)

    def _infer_ioc_type(self, pattern: str) -> str:
        for marker in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "file"):
            if marker in pattern:
                return marker
        return "none"

    def _enrich_with_relations(self, indicator_id: str, result: CTIResult) -> CTIResult:
        if not indicator_id:
            return result

        try:
            data = self._graphql(
                """
                query IndicatorRelations($filters: FilterGroup) {
                  stixCoreRelationships(first: 10, filters: $filters) {
                    edges {
                      node {
                        relationship_type
                        to {
                          ... on BasicObject { id entity_type }
                          ... on AttackPattern { name }
                          ... on Campaign { name }
                          ... on Malware { name }
                          ... on ThreatActor { name }
                        }
                      }
                    }
                  }
                }
                """,
                {
                    "filters": {
                        "mode": "and",
                        "filters": [{"key": "fromId", "values": [indicator_id]}],
                        "filterGroups": [],
                    }
                },
            )
        except Exception as exc:
            log.warning("Relation walk failed for %s: %s", indicator_id, exc)
            return result

        edges = data.get("stixCoreRelationships", {}).get("edges", [])
        for edge in edges:
            node = edge.get("node", {})
            if node.get("relationship_type") not in _RELATION_TYPES:
                continue

            related = node.get("to", {})
            entity_type = related.get("entity_type", "")
            name = related.get("name", "")

            if entity_type == "Threat-Actor":
                result.actor_known = 1
                result.actor_name = name
            elif entity_type == "Campaign":
                result.campaign_name = name
            elif entity_type == "Malware":
                result.threat_name = name

        return result
