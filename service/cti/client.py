from __future__ import annotations

from pycti import OpenCTIApiClient

from enrich.models import CTIResult
from enrich.utils.cache import FifoCache
from enrich.utils.logging import get_logger

log = get_logger("enrich.cti")

# Relationship types that link an indicator to a threat actor / campaign / malware
_RELATION_TYPES = ["attributed-to", "indicates"]

# Entity types we care about when walking the graph
_ENTITY_MAP = {
    "Threat-Actor": "actor",
    "Campaign":     "campaign",
    "Malware":      "malware",
}


class CTIClient:
    """
    Thin wrapper around pycti OpenCTIApiClient with an in-process FIFO cache.

    The cache prevents hammering OpenCTI for repeated IPs — PA-5220 logs
    typically repeat the same src_ip thousands of times per hour.
    """

    def __init__(self, url: str, token: str, cache_size: int = 5_000) -> None:
        self._client = OpenCTIApiClient(url, token, log_level="error")
        self._cache: FifoCache[CTIResult] = FifoCache(maxsize=cache_size)
        log.info("Connected to OpenCTI at %s", url)

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def lookup(self, ip: str) -> CTIResult:
        """
        Query OpenCTI for an IP indicator.
        Returns a CTIResult (all fields default to zero/none on miss).
        """
        if ip in self._cache:
            return self._cache.get(ip)  # type: ignore[return-value]

        result = CTIResult()

        try:
            indicators = self._client.indicator.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [ip]}],
                    "filterGroups": [],
                },
                first=1,
                customAttributes="""
                    id
                    confidence
                    indicator_types
                    killChainPhases {
                        edges {
                            node {
                                phase_name
                                phaseName
                            }
                        }
                    }
                """,
            )

            if not indicators or not indicators.get("edges"):
                self._cache.set(ip, result)
                return result

            node = indicators["edges"][0]["node"]
            result = self._parse_indicator(node)
            result = self._enrich_with_relations(node.get("id", ""), result)

        except Exception as exc:
            log.warning("OpenCTI lookup failed for %s: %s", ip, exc)

        self._cache.set(ip, result)
        return result

    # ── Private helpers ────────────────────────────────────────────────────────

    def _parse_indicator(self, node: dict) -> CTIResult:
        conf_raw = node.get("confidence", 0) or 0
        confidence = round(min(conf_raw / 100.0, 1.0), 4)

        types = node.get("indicator_types") or []
        ioc_type = types[0] if types else "none"

        mitre_phase = "none"
        edges = node.get("killChainPhases", {}).get("edges", [])
        if edges:
            kc = edges[0].get("node", {})
            mitre_phase = kc.get("phase_name") or kc.get("phaseName") or "none"

        return CTIResult(confidence=confidence, ioc_type=ioc_type, mitre_phase=mitre_phase)

    def _enrich_with_relations(self, indicator_id: str, result: CTIResult) -> CTIResult:
        if not indicator_id:
            return result

        try:
            relations = self._client.stix_core_relationship.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "fromId",             "values": [indicator_id]},
                        {"key": "relationship_type",  "values": _RELATION_TYPES},
                    ],
                    "filterGroups": [],
                },
                first=3,
            )
        except Exception as exc:
            log.warning("Relation walk failed for %s: %s", indicator_id, exc)
            return result

        if not relations or not relations.get("edges"):
            return result

        for edge in relations["edges"]:
            related      = edge["node"].get("to", {})
            entity_type  = related.get("entity_type", "")
            name         = related.get("name", "")

            if entity_type == "Threat-Actor":
                result.actor_known  = 1
                result.actor_name   = name
            elif entity_type == "Campaign":
                result.campaign_name = name
            elif entity_type == "Malware":
                result.threat_name  = name

        return result
