"""Central scan pipeline. The UI consumes this output and holds no second implementation."""
from __future__ import annotations

import hashlib
from typing import Any

from .attack_paths import build_graph, find_exposure_paths, graph_summary
from .audit import analyze_audit_events
from .detector import run_config_detection
from .explanations import generate_explanation
from .models import (SCHEMA_VERSION, SEVERITY_ORDER, SIMULATION_LABEL, canonical_json)
from .parser import validate_audit_logs, validate_config
from .remediation import apply_patch, propose_remediation
from .risk_scoring import score_findings
from .risk_story import build_risk_story


def decide(findings: list[dict[str, Any]]) -> str:
    """Advisory GO / WATCH / STOP. Not a probability of compromise."""
    if any(f["score"] >= 60 and f["confidence"] == "high" for f in findings):
        return "STOP"
    if any(f["score"] >= 20 or f["status"] == "unknown" for f in findings):
        return "WATCH"
    return "GO"


DECISION_TEXT = {
    "STOP": "A policy threshold is met by sufficient evidence. Recommend containment or corrective action.",
    "WATCH": "Evidence is incomplete or suspicious. Investigate before deciding.",
    "GO": "No relevant risk was detected by the available checks. This is not a guarantee of safety.",
}


def run_scan(config_input: Any, audit_logs: Any = None, source_label: str = "Uploaded input",
             weights: dict[str, float] | None = None, use_llm: bool = False,
             llm_client: Any = None) -> dict[str, Any]:
    """Run the full pipeline and return a stable result dictionary."""
    input_hash = hashlib.sha256(canonical_json(config_input).encode("utf-8")).hexdigest()[:16]
    v = validate_config(config_input)
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": source_label,
        "input_sha256": input_hash,
        "dataset_name": (config_input or {}).get("dataset_name") if isinstance(config_input, dict) else None,
        "synthetic": bool((config_input or {}).get("synthetic")) if isinstance(config_input, dict) else False,
        "validation": {"errors": list(v["errors"]), "warnings": list(v["warnings"]),
                       "limitations": list(v["limitations"])},
        "audit_status": "not provided",
    }
    if v["errors"]:
        result.update(status="INVALID", decision=None, findings=[], counts={}, verified_paths=[],
                      incomplete_paths=[], risk_story=None, graph_summary=None, normalized_config=None,
                      limitations=[])
        return result

    config = v["config"]
    audit_events: list[dict[str, Any]] = []
    if audit_logs is not None:
        av = validate_audit_logs(audit_logs)
        result["validation"]["errors"] += av["errors"]
        result["validation"]["warnings"] += av["warnings"]
        if av["errors"]:
            result.update(status="INVALID", decision=None, findings=[], counts={}, verified_paths=[],
                          incomplete_paths=[], risk_story=None, graph_summary=None, normalized_config=None,
                          limitations=[])
            return result
        audit_events = av["events"]
        result["audit_status"] = f"{len(audit_events)} event(s) analysed"

    cfg_findings = run_config_detection(config)
    audit_findings = analyze_audit_events(audit_events, config) if audit_events else []
    findings = score_findings(cfg_findings + audit_findings, weights)
    for f in findings:
        f["explanation"] = generate_explanation(f, use_llm=use_llm, llm_client=llm_client)

    graph = build_graph(config)
    paths = find_exposure_paths(config, graph)
    story = build_risk_story(config, paths, findings)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    limitations: list[str] = list(v["limitations"])
    for f in findings:
        for lim in f["limitations"]:
            if lim not in limitations:
                limitations.append(lim)

    decision = decide(findings)
    result.update({
        "status": "OK",
        "decision": decision,
        "decision_text": DECISION_TEXT[decision],
        "counts": counts,
        "config_finding_count": sum(1 for f in findings if f["source"] == "configuration"),
        "audit_indicator_count": sum(1 for f in findings if f["source"] == "audit"),
        "unknown_count": sum(1 for f in findings if f["status"] == "unknown"),
        "findings": findings,
        "verified_paths": paths["verified"],
        "incomplete_paths": paths["incomplete"],
        "risk_story": story,
        "graph_summary": graph_summary(graph),
        "limitations": limitations,
        "normalized_config": config,
        "audit_events": audit_events,
    })
    return result


def compare_scans(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two scan results by stable finding id."""
    b = {f["id"]: f for f in before["findings"]}
    a = {f["id"]: f for f in after["findings"]}
    disappeared = sorted(i for i in b if i not in a)
    new = sorted(i for i in a if i not in b)
    changed = []
    remaining = []
    for fid in sorted(set(b) & set(a)):
        if b[fid]["score"] != a[fid]["score"] or b[fid]["severity"] != a[fid]["severity"]:
            changed.append({"id": fid, "before_score": b[fid]["score"], "after_score": a[fid]["score"],
                            "before_severity": b[fid]["severity"], "after_severity": a[fid]["severity"]})
        else:
            remaining.append(fid)
    return {"disappeared": disappeared, "new": new, "changed": changed, "not_addressed": remaining,
            "before_count": len(b), "after_count": len(a),
            "before_decision": before.get("decision"), "after_decision": after.get("decision"),
            "note": "One finding disappearing does not make the environment secure."}


def simulate_remediation(config_input: Any, finding_id: str, audit_logs: Any = None,
                         weights: dict[str, float] | None = None) -> dict[str, Any]:
    """Local simulation: patch a COPY, rescan with the same functions, compare."""
    before = run_scan(config_input, audit_logs, weights=weights)
    if before["status"] != "OK":
        return {"label": SIMULATION_LABEL, "status": "ERROR", "message": "Input is invalid; fix validation errors first."}
    finding = next((f for f in before["findings"] if f["id"] == finding_id), None)
    if finding is None:
        return {"label": SIMULATION_LABEL, "status": "ERROR", "message": f"No finding with id {finding_id!r}."}
    proposal = propose_remediation(before["normalized_config"], finding)
    if proposal["type"] != "exact_patch":
        return {"label": SIMULATION_LABEL, "status": "CHECKLIST_ONLY", "proposal": proposal,
                "message": "No exact safe patch can be established; simulation not run."}

    snapshot = canonical_json(config_input)
    simulated = apply_patch(before["normalized_config"], proposal)
    after = run_scan(simulated, audit_logs, source_label="Simulated copy", weights=weights)
    original_unchanged = canonical_json(config_input) == snapshot
    return {"label": SIMULATION_LABEL, "status": "SIMULATED", "proposal": proposal,
            "original_unchanged": original_unchanged,
            "comparison": compare_scans(before, after),
            "before_scan_status": before["status"], "after_scan_status": after["status"]}
