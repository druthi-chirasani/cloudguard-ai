import copy

from cloudguard.audit import analyze_audit_events
from cloudguard.parser import validate_audit_logs, validate_config


def _findings(config_raw, audit_raw):
    cfg = validate_config(config_raw)["config"]
    events = validate_audit_logs(audit_raw)["events"]
    return analyze_audit_events(events, cfg)


def test_denied_request_is_not_a_successful_access(config, audit):
    findings = _findings(config, audit)
    denied = [f for f in findings if f["rule_id"] == "AUDIT_DENIED_REQUEST"]
    assert {f["id"] for f in denied} >= {"AUDIT_DENIED_REQUEST:evt-0003"}
    assert all("NOT successful" in " ".join(f["evidence"]) for f in denied)
    assert not any(f["rule_id"] == "AUDIT_UNDECLARED_ACTOR_SENSITIVE" and "evt-0003" in f["id"] for f in findings)


def test_policy_change_is_indicator_not_configuration_finding(config, audit):
    findings = _findings(config, audit)
    change = next(f for f in findings if f["rule_id"] == "AUDIT_PUBLIC_ACCESS_CHANGE")
    assert change["source"] == "audit"
    assert change["category"] == "Audit Indicator"


def test_missing_actor_creates_context_gap(config, audit):
    findings = _findings(config, audit)
    gap = next(f for f in findings if f["rule_id"] == "AUDIT_MISSING_CONTEXT")
    assert "evt-0005" in gap["id"]
    assert gap["status"] == "open"


def test_read_only_rule_does_not_fire_on_policy_change(config, audit):
    findings = _findings(config, audit)
    assert not any(f["rule_id"] == "AUDIT_UNDECLARED_ACTOR_SENSITIVE" and "evt-0001" in f["id"]
                   for f in findings)


def test_permission_change_recorded_for_exposed_identity(config, audit):
    findings = _findings(config, audit)
    assert any(f["rule_id"] == "AUDIT_PERMISSION_CHANGE" and f["resource_id"] == "app-service-role"
               for f in findings)


def test_missing_timestamp_is_warned_not_invented(audit):
    result = validate_audit_logs(audit)
    evt = next(e for e in result["events"] if e["id"] == "evt-0005")
    assert evt["timestamp"] is None


def test_event_without_action_is_skipped(audit):
    bad = copy.deepcopy(audit)
    bad["events"].append({"id": "evt-x", "outcome": "success"})
    result = validate_audit_logs(bad)
    assert all(e["id"] != "evt-x" for e in result["events"])
    assert any("no action" in w for w in result["warnings"])
