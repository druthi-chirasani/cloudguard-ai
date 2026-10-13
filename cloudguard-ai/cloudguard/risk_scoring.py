"""Transparent, deterministic prioritisation heuristic.

The score is a PRIORITISATION HEURISTIC. It is NOT a probability of compromise.

score = round(sum(weight_i * factor_i)), where each factor is 0-100:
  exposure          how reachable the asset is (public entry, public access)
  sensitivity       how sensitive the affected data is (sensitive flag)
  privilege_breadth how wide the granted permissions are
  evidence_quality  how well the claim is supported by supplied evidence

Rules:
  * A score is capped at 59 when evidence_quality < 30, so an arbitrary high
    factor cannot override missing evidence.
  * Confidence is derived from evidence_quality (>=80 high, >=50 medium, else low).
"""
from __future__ import annotations

from typing import Any

from .models import DEFAULT_WEIGHTS, band_for_score, clamp

EVIDENCE_CAP_THRESHOLD = 30
EVIDENCE_CAP_SCORE = 59
AUDIT_INDICATOR_CAP = 79  # audit events are indicators, never Critical on their own


def validate_weights(weights: dict[str, float]) -> None:
    """Raise ValueError if weights are malformed or do not sum to 1."""
    if set(weights) != set(DEFAULT_WEIGHTS):
        raise ValueError(f"weights must have exactly these keys: {sorted(DEFAULT_WEIGHTS)}")
    if any((not isinstance(v, (int, float))) or v < 0 for v in weights.values()):
        raise ValueError("weights must be non-negative numbers")
    if abs(sum(weights.values()) - 1.0) > 1e-6:
        raise ValueError("weights must sum to 1.0")


def confidence_for(evidence_quality: float) -> str:
    if evidence_quality >= 80:
        return "high"
    if evidence_quality >= 50:
        return "medium"
    return "low"


def compute_score(factors: dict[str, float], weights: dict[str, float] | None = None) -> tuple[int, dict[str, Any]]:
    """Return (score 0-100, per-factor breakdown). Deterministic."""
    w = dict(weights or DEFAULT_WEIGHTS)
    validate_weights(w)
    breakdown: dict[str, Any] = {}
    total = 0.0
    for name, weight in w.items():
        value = clamp(factors.get(name, 0.0))
        contribution = value * weight
        total += contribution
        breakdown[name] = {"value": round(value, 1), "weight": weight,
                           "contribution": round(contribution, 2)}
    score = int(clamp(total) + 0.5)
    evidence_value = clamp(factors.get("evidence_quality", 0.0))
    if evidence_value < EVIDENCE_CAP_THRESHOLD:
        score = min(score, EVIDENCE_CAP_SCORE)
        breakdown["cap_applied"] = f"Score capped at {EVIDENCE_CAP_SCORE} because evidence_quality is below {EVIDENCE_CAP_THRESHOLD}."
    return score, breakdown


def score_finding(finding: dict[str, Any], weights: dict[str, float] | None = None) -> dict[str, Any]:
    """Attach score, severity, confidence and breakdown to a finding (in place)."""
    score, breakdown = compute_score(finding.get("factors", {}), weights)
    if finding.get("source") == "audit" and score > AUDIT_INDICATOR_CAP:
        score = AUDIT_INDICATOR_CAP
        breakdown["cap_applied"] = f"Audit indicator capped at {AUDIT_INDICATOR_CAP}: events are indicators, not proof."
    finding["score"] = score
    finding["severity"] = band_for_score(score)
    finding["confidence"] = confidence_for(clamp(finding.get("factors", {}).get("evidence_quality", 0.0)))
    finding["score_breakdown"] = breakdown
    return finding


def score_findings(findings: list[dict[str, Any]], weights: dict[str, float] | None = None) -> list[dict[str, Any]]:
    """Score every finding and return them sorted by score (highest first), then id."""
    for f in findings:
        score_finding(f, weights)
    return sorted(findings, key=lambda f: (-f["score"], f["id"]))
