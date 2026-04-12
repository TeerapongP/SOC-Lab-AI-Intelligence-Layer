from __future__ import annotations

from enum import Enum

from enrich.config.settings import CONF_ATTACK_MIN, CONF_NORMAL_MAX
from enrich.models import EnrichedRecord


class WeakLabel(str, Enum):
    ATTACK  = "attack"
    NORMAL  = "normal"
    UNKNOWN = "unknown"


# ── Heuristic rules ────────────────────────────────────────────────────────────
# Each rule is a (predicate, label) pair evaluated in order.
# First match wins. Rules can be extended without touching the core logic.

def _rule_high_confidence(rec: EnrichedRecord) -> WeakLabel | None:
    if rec.ioc_confidence >= CONF_ATTACK_MIN:
        return WeakLabel.ATTACK
    return None


def _rule_known_actor(rec: EnrichedRecord) -> WeakLabel | None:
    if rec.actor_known == 1:
        return WeakLabel.ATTACK
    return None


def _rule_mitre_phase(rec: EnrichedRecord) -> WeakLabel | None:
    """Flag phases that are almost always malicious."""
    malicious_phases = {
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "lateral-movement",
        "collection",
        "exfiltration",
        "impact",
        "command-and-control",
    }
    if rec.mitre_phase in malicious_phases:
        return WeakLabel.ATTACK
    return None


def _rule_low_confidence(rec: EnrichedRecord) -> WeakLabel | None:
    if rec.ioc_confidence <= CONF_NORMAL_MAX and rec.actor_known == 0:
        return WeakLabel.NORMAL
    return None


_RULES = [
    _rule_high_confidence,
    _rule_known_actor,
    _rule_mitre_phase,
    _rule_low_confidence,
]


# ── Public API ─────────────────────────────────────────────────────────────────

def assign_label(rec: EnrichedRecord) -> WeakLabel:
    """
    Apply heuristic rules in priority order and return the first match.
    Falls back to UNKNOWN for grey-zone records (unsupervised ML territory).
    """
    for rule in _RULES:
        result = rule(rec)
        if result is not None:
            return result
    return WeakLabel.UNKNOWN


def apply_label(rec: EnrichedRecord) -> EnrichedRecord:
    """Mutate rec.weak_label in-place and return it."""
    rec.weak_label = assign_label(rec).value
    return rec
