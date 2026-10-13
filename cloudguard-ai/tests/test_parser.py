import copy

from cloudguard.parser import read_json_text, validate_audit_logs, validate_config
from cloudguard.models import MAX_UPLOAD_BYTES


def test_malformed_json_gives_useful_error():
    data, errors = read_json_text('{"schema_version": "1.0",')
    assert data is None
    assert errors and "Invalid JSON at line" in errors[0]


def test_empty_and_oversize_inputs_rejected():
    assert read_json_text("   ")[1] == ["Input is empty."]
    big = "x" * (MAX_UPLOAD_BYTES + 1)
    assert "exceeds" in read_json_text(big)[1][0]


def test_valid_config_normalises_without_errors(config):
    v = validate_config(config)
    assert v["errors"] == []
    assert v["config"] is not None


def test_missing_top_level_list_is_error(config):
    bad = copy.deepcopy(config)
    del bad["resources"]
    v = validate_config(bad)
    assert v["config"] is None
    assert any("resources" in e for e in v["errors"])


def test_duplicate_ids_rejected(config):
    bad = copy.deepcopy(config)
    bad["identities"][0]["id"] = "bucket-customer-data"
    v = validate_config(bad)
    assert any("Duplicate id" in e for e in v["errors"])


def test_invalid_permission_effect_rejected(config):
    bad = copy.deepcopy(config)
    bad["identities"][0]["permissions"][0]["effect"] = "Maybe"
    assert any("effect" in e for e in validate_config(bad)["errors"])


def test_empty_action_string_rejected(config):
    bad = copy.deepcopy(config)
    bad["identities"][0]["permissions"][0]["actions"] = [""]
    assert any("empty or non-string action" in e for e in validate_config(bad)["errors"])


def test_dangling_relationship_is_excluded_with_warning(config):
    bad = copy.deepcopy(config)
    bad["relationships"].append({"source": "ghost", "target": "bucket-customer-data", "validated": True})
    v = validate_config(bad)
    assert v["config"] is not None
    assert all(r["source"] != "ghost" for r in v["config"]["relationships"])
    assert any("unknown id" in w for w in v["warnings"])


def test_missing_public_access_is_unknown_not_false(config):
    bad = copy.deepcopy(config)
    for r in bad["resources"]:
        if r["id"] == "bucket-partner-reports":
            r.pop("public_access", None)
    norm = validate_config(bad)["config"]
    res = next(r for r in norm["resources"] if r["id"] == "bucket-partner-reports")
    assert res["public_access"] is None


def test_missing_validated_flag_defaults_to_not_validated(config):
    bad = copy.deepcopy(config)
    del bad["relationships"][0]["validated"]
    norm = validate_config(bad)["config"]
    assert norm["relationships"][0]["validated"] is False


def test_audit_missing_context_is_recorded(audit):
    result = validate_audit_logs(audit)
    missing_event = next(e for e in result["events"] if e["id"] == "evt-0005")
    assert "actor" in missing_event["missing"] and "timestamp" in missing_event["missing"]
    assert any("evt-0005" in w for w in result["warnings"])
