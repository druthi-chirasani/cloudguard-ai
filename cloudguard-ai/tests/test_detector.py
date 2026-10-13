import copy

from cloudguard.detector import run_config_detection
from cloudguard.parser import validate_config


def _run(raw):
    return run_config_detection(validate_config(raw)["config"])


def _ids(findings):
    return {f["id"] for f in findings}


def test_public_sensitive_storage_detected(config):
    findings = _run(config)
    assert "PUBLIC_SENSITIVE_RESOURCE:-:bucket-customer-data" in _ids(findings)


def test_restricted_storage_not_flagged_as_public(config):
    findings = _run(config)
    assert not any(f["rule_id"].startswith("PUBLIC") and f["resource_id"] == "bucket-internal-logs"
                   for f in findings)


def test_missing_public_access_is_unknown_not_safe(config):
    findings = _run(config)
    unknown = next(f for f in findings if f["resource_id"] == "bucket-partner-reports")
    assert unknown["rule_id"] == "UNKNOWN_PUBLIC_ACCESS_SENSITIVE"
    assert unknown["status"] == "unknown"


def test_excess_iam_permissions_flagged_with_evidence(config):
    f = next(x for x in _run(config) if x["rule_id"] == "IAM_EXCESS_PRIVILEGE" and x["identity_id"] == "app-service-role")
    assert any("PutObject" in e and "excess" in e for e in f["evidence"])


def test_explicit_deny_is_not_a_grant(config):
    f = next(x for x in _run(config) if x["identity_id"] == "deploy-role")
    text = " ".join(f["evidence"] + f["limitations"])
    assert "DeleteBucket" in text  # reported as a denied action
    assert f["rule_id"] == "IAM_WILDCARD_SCOPE"


def test_explicit_deny_removes_exact_action_from_excess(config):
    bad = copy.deepcopy(config)
    bad["identities"][0]["permissions"].append(
        {"effect": "Deny", "actions": ["PutObject", "DeleteObject", "ListBucket"], "resources": ["*"], "conditions": {}})
    f = next(x for x in _run(bad) if x["identity_id"] == "app-service-role")
    assert "PutObject" not in " ".join(f["evidence"]).split("excess_actions=")[-1]


def test_conditions_are_preserved_and_noted(config):
    f = next(x for x in _run(config) if x["identity_id"] == "analytics-role")
    assert any("Conditions are recorded" in lim for lim in f["limitations"])
    assert f["factors"]["evidence_quality"] == 60


def test_missing_required_actions_produces_unknown_not_excess(config):
    bad = copy.deepcopy(config)
    del bad["identities"][0]["required_actions"]
    iam = [x for x in _run(bad) if x["identity_id"] == "app-service-role"
           and x["rule_id"].startswith("IAM_")]
    assert [x["rule_id"] for x in iam] == ["IAM_REQUIREMENTS_UNDECLARED"]
    assert iam[0]["remediation_available"] is False


def test_findings_are_deduplicated_by_stable_id(config):
    findings = _run(config)
    ids = [f["id"] for f in findings]
    assert len(ids) == len(set(ids))


def test_verified_exposure_path_is_reported(config):
    assert any(f["rule_id"] == "EXPOSED_PATH_TO_SENSITIVE" for f in _run(config))


def test_unvalidated_relationship_is_possible_not_verified(config):
    findings = _run(config)
    possible = [f for f in findings if f["rule_id"] == "POSSIBLE_RELATIONSHIP_UNVERIFIED"]
    assert possible and all(f["status"] == "unknown" for f in possible)
    assert not any(f["rule_id"] == "EXPOSED_PATH_TO_SENSITIVE" and f["resource_id"] == "bucket-internal-logs"
                   for f in findings)
