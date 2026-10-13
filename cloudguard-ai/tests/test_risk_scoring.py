import pytest

from cloudguard.models import band_for_score
from cloudguard.risk_scoring import compute_score, score_finding, validate_weights

FULL = {"exposure": 100, "sensitivity": 100, "privilege_breadth": 100, "evidence_quality": 100}


def test_score_is_deterministic():
    factors = {"exposure": 60, "sensitivity": 90, "privilege_breadth": 40, "evidence_quality": 80}
    assert compute_score(factors)[0] == compute_score(factors)[0]


def test_score_is_bounded_even_with_out_of_range_inputs():
    score, _ = compute_score({"exposure": 500, "sensitivity": -50, "privilege_breadth": 100, "evidence_quality": 100})
    assert 0 <= score <= 100


def test_breakdown_contributions_sum_to_score():
    factors = {"exposure": 60, "sensitivity": 90, "privilege_breadth": 40, "evidence_quality": 80}
    score, bd = compute_score(factors)
    total = sum(bd[k]["contribution"] for k in ("exposure", "sensitivity", "privilege_breadth", "evidence_quality"))
    assert abs(total - score) <= 1


def test_low_evidence_caps_score():
    score, bd = compute_score({"exposure": 100, "sensitivity": 100, "privilege_breadth": 100, "evidence_quality": 10})
    assert score <= 59
    assert "cap_applied" in bd


def test_invalid_weights_rejected():
    with pytest.raises(ValueError):
        validate_weights({"exposure": 0.5, "sensitivity": 0.5, "privilege_breadth": 0.5, "evidence_quality": 0.5})
    with pytest.raises(ValueError):
        validate_weights({"exposure": 1.0})


def test_score_finding_sets_severity_and_confidence():
    f = {"factors": {"exposure": 100, "sensitivity": 100, "privilege_breadth": 0, "evidence_quality": 100}}
    score_finding(f)
    assert f["score"] == 80 and f["severity"] == "Critical" and f["confidence"] == "high"


def test_band_boundaries():
    assert band_for_score(0) == "Informational"
    assert band_for_score(20) == "Low"
    assert band_for_score(59) == "Medium"
    assert band_for_score(60) == "High"
    assert band_for_score(100) == "Critical"


def test_audit_indicator_capped_below_critical():
    f = {"source": "audit", "factors": FULL}
    score_finding(f)
    assert f["score"] <= 79
