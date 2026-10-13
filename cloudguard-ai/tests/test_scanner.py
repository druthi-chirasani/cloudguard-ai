import copy
import json

from cloudguard.explanations import build_llm_payload, generate_explanation, validate_llm_output
from cloudguard.exports import findings_to_csv, findings_to_json, findings_to_dataframe, report_markdown
from cloudguard.scanner import compare_scans, run_scan, simulate_remediation


def test_scanner_runs_with_no_llm_credentials(config, audit):
    r = run_scan(config, audit)
    assert r["status"] == "OK"
    assert r["decision"] in {"GO", "WATCH", "STOP"}
    assert all(f["explanation"]["mode"] == "template" for f in r["findings"])


def test_invalid_config_is_reported_not_crashed(config):
    bad = copy.deepcopy(config)
    del bad["resources"]
    r = run_scan(bad)
    assert r["status"] == "INVALID"
    assert r["findings"] == []
    assert r["validation"]["errors"]


def test_simulation_uses_real_scan_and_leaves_original_unchanged(config, audit):
    before_json = json.dumps(config, sort_keys=True)
    sim = simulate_remediation(config, "PUBLIC_SENSITIVE_RESOURCE:-:bucket-customer-data", audit)
    assert sim["status"] == "SIMULATED"
    assert sim["original_unchanged"] is True
    assert json.dumps(config, sort_keys=True) == before_json
    assert "PUBLIC_SENSITIVE_RESOURCE:-:bucket-customer-data" in sim["comparison"]["disappeared"]


def test_simulation_updates_only_relevant_findings(config, audit):
    sim = simulate_remediation(config, "PUBLIC_SENSITIVE_RESOURCE:-:bucket-customer-data", audit)
    remaining = set(sim["comparison"]["not_addressed"])
    assert "EXPOSED_PATH_TO_SENSITIVE:public-web-app>app-service-role>bucket-customer-data" in remaining
    assert sim["comparison"]["note"].startswith("One finding disappearing")


def test_checklist_only_finding_does_not_simulate(config, audit):
    sim = simulate_remediation(config, "UNKNOWN_PUBLIC_ACCESS_SENSITIVE:-:bucket-partner-reports", audit)
    assert sim["status"] == "CHECKLIST_ONLY"


def test_broken_llm_response_falls_back_to_template(config):
    r = run_scan(config)
    f = r["findings"][0]
    out = generate_explanation(f, use_llm=True, llm_client=lambda payload: "this is not json")
    assert out["mode"] == "template"
    assert "rejected" in out["fallback_reason"]


def test_llm_exception_falls_back_to_template(config):
    r = run_scan(config)
    f = r["findings"][0]

    def boom(_):
        raise TimeoutError("simulated timeout")
    out = generate_explanation(f, use_llm=True, llm_client=boom)
    assert out["mode"] == "template" and "TimeoutError" in out["fallback_reason"]


def test_llm_wrong_finding_id_is_rejected():
    parsed, errors = validate_llm_output(json.dumps({"finding_id": "other", "explanation": "x"}), "expected")
    assert parsed is None and errors


def test_llm_payload_redacts_secret_like_evidence(config):
    f = run_scan(config)["findings"][0]
    f["evidence"].append("api_key=AKIA1234567890ABCD")
    payload = build_llm_payload(f)
    assert all("AKIA" not in e for e in payload["evidence"])


def test_exports_have_expected_columns(config, audit):
    r = run_scan(config, audit)
    df = findings_to_dataframe(r["findings"])
    assert list(df.columns) == ["id", "rule_id", "title", "category", "severity", "score", "status",
                                "confidence", "source", "identity_id", "resource_id"]
    header = findings_to_csv(r["findings"]).splitlines()[0]
    assert header.startswith("id,rule_id,title")
    parsed = json.loads(findings_to_json(r["findings"]))
    assert len(parsed) == len(r["findings"])
    assert "# CloudGuard AI scan report" in report_markdown(r)


def test_compare_scans_detects_no_change_on_identical_input(config, audit):
    a = run_scan(config, audit)
    b = run_scan(config, audit)
    cmp = compare_scans(a, b)
    assert cmp["disappeared"] == [] and cmp["new"] == [] and cmp["changed"] == []
