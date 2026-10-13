"""Shared constants and helpers for CloudGuard AI.

Everything here is deterministic and dependency-free so that every other
module can import it safely.
"""
from __future__ import annotations

import json
from typing import Any

SCHEMA_VERSION = "1.0"
MAX_UPLOAD_BYTES = 1_000_000
ID_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

# Weights must sum to 1.0. Each factor is normalised to 0-100 before weighting.
DEFAULT_WEIGHTS = {
    "exposure": 0.35,
    "sensitivity": 0.30,
    "privilege_breadth": 0.20,
    "evidence_quality": 0.15,
}

# Lower bound of each band, checked from highest to lowest.
SCORE_BANDS = [(80, "Critical"), (60, "High"), (40, "Medium"), (20, "Low"), (0, "Informational")]

REVIEW_STATUS = "PROPOSED — HUMAN APPROVAL REQUIRED"
SIMULATION_LABEL = "LOCAL SIMULATION — NOT A REAL CLOUD CHANGE"
SOURCE_CONFIG = "configuration"
SOURCE_AUDIT = "audit"


def band_for_score(score: float) -> str:
    """Map a 0-100 score to a severity band."""
    for threshold, name in SCORE_BANDS:
        if score >= threshold:
            return name
    return "Informational"


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    """Clamp a number into [low, high]."""
    return max(low, min(high, float(value)))


def make_finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    resource_id: str | None = None,
    identity_id: str | None = None,
    evidence: list[str] | None = None,
    why_it_matters: str = "",
    potential_impact: str = "",
    limitations: list[str] | None = None,
    recommended_action: str = "",
    remediation_available: bool = False,
    source: str = SOURCE_CONFIG,
    factors: dict[str, float] | None = None,
    finding_key: str | None = None,
    status: str = "open",
) -> dict[str, Any]:
    """Build a finding dict with a stable, human-readable ID.

    The ID is derived from the rule and the affected assets, so the same issue
    always gets the same ID. This is what makes before/after comparison work.
    """
    key = finding_key or f"{rule_id}:{identity_id or '-'}:{resource_id or '-'}"
    return {
        "id": key,
        "rule_id": rule_id,
        "title": title,
        "category": category,
        "severity": None,
        "score": None,
        "status": status,
        "confidence": None,
        "resource_id": resource_id,
        "identity_id": identity_id,
        "evidence": list(evidence or []),
        "why_it_matters": why_it_matters,
        "potential_impact": potential_impact,
        "limitations": list(limitations or []),
        "recommended_action": recommended_action,
        "remediation_available": remediation_available,
        "source": source,
        "factors": dict(factors or {}),
        "score_breakdown": {},
    }


def canonical_json(obj: Any) -> str:
    """Serialise deterministically (sorted keys) for hashing and comparison."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
