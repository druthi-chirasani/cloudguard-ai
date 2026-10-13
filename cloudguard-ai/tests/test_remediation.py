import copy
import json

from cloudguard.models import REVIEW_STATUS
from cloudguard.detector import run_config_detection
from cloudguard.parser import validate_config
from cloudguard.remediation import apply_patch, propose_remediation


def _finding(cfg, rule_id, **match):
    findings = run_config_detection(cfg)
    return next(f for f in findings if f["rule_id"] == rule_id and all(f.get(k) == v for k, v in match.items()))


def test_public_access_patch_is_exact_and_valid_json(config):
    cfg = validate_config(config)["config"]
    f = _finding(cfg, "PUBLIC_SENSITIVE_RESOURCE")
    p = propose_remediation(cfg, f)
    assert p["type"] == "exact_patch"
    assert p["status"] == REVIEW_STATUS
    assert p["validation"]["json_valid"] is True
    assert p["validation"]["passed"] is True
    json.loads(json.dumps(p["proposed"]))
    assert p["proposed"]["public_access"] is False


def test_missing_required_actions_returns_checklist_not_policy(config):
    bad = copy.deepcopy(config)
    del bad["identities"][0]["required_actions"]
    cfg = validate_config(bad)["config"]
    f = _finding(cfg, "IAM_REQUIREMENTS_UNDECLARED", identity_id="app-service-role")
    p = propose_remediation(cfg, f)
    assert p["type"] == "checklist"
    assert p["patch"] is None and p["proposed"] is None


def test_wildcard_without_concrete_requirements_returns_checklist(config):
    bad = copy.deepcopy(config)
    bad["identities"][2]["required_actions"] = ["*"]
    cfg = validate_config(bad)["config"]
    f = _finding(cfg, "IAM_WILDCARD_SCOPE", identity_id="deploy-role")
    assert propose_remediation(cfg, f)["type"] == "checklist"


def test_deny_statements_and_conditions_preserved(config):
    cfg = validate_config(config)["config"]
    f = _finding(cfg, "IAM_EXCESS_PRIVILEGE", identity_id="analytics-role")
    p = propose_remediation(cfg, f)
    assert p["type"] == "exact_patch"
    assert p["proposed"]["permissions"][0]["conditions"] == cfg["identities"][1]["permissions"][0]["conditions"]
    deploy = validate_config(config)["config"]
    f2 = _finding(deploy, "IAM_WILDCARD_SCOPE", identity_id="deploy-role")
    p2 = propose_remediation(deploy, f2)
    deny = [x for x in p2["proposed"]["permissions"] if x["effect"] == "Deny"]
    assert deny == [x for x in deploy["identities"][2]["permissions"] if x["effect"] == "Deny"]
    assert all(c["ok"] for c in p2["validation"]["checks"])


def test_apply_patch_never_mutates_original(config):
    cfg = validate_config(config)["config"]
    before = json.dumps(cfg, sort_keys=True)
    f = _finding(cfg, "PUBLIC_SENSITIVE_RESOURCE")
    new = apply_patch(cfg, propose_remediation(cfg, f))
    assert json.dumps(cfg, sort_keys=True) == before
    assert new["resources"][0]["public_access"] is False
