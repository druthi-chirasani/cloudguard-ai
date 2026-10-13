"""Export helpers: findings to JSON/CSV, proposals to JSON, and a Markdown report."""
from __future__ import annotations

import json
from typing import Any

import pandas as pd

from .models import REVIEW_STATUS, SIMULATION_LABEL

CSV_COLUMNS = ["id", "rule_id", "title", "category", "severity", "score", "status", "confidence",
               "source", "identity_id", "resource_id"]


def findings_to_dataframe(findings: list[dict[str, Any]]) -> pd.DataFrame:
    """Flat table of findings with a fixed column set (empty input gives empty columns)."""
    rows = [{c: f.get(c) for c in CSV_COLUMNS} for f in findings]
    return pd.DataFrame(rows, columns=CSV_COLUMNS)


def findings_to_csv(findings: list[dict[str, Any]]) -> str:
    return findings_to_dataframe(findings).to_csv(index=False)


def findings_to_json(findings: list[dict[str, Any]]) -> str:
    return json.dumps(findings, indent=2, default=str)


def proposal_to_json(proposal: dict[str, Any]) -> str:
    return json.dumps(proposal, indent=2, default=str)


def report_markdown(scan: dict[str, Any]) -> str:
    """Compact Markdown report. Every line is labelled as synthetic or local where relevant."""
    lines = [
        "# CloudGuard AI scan report",
        "",
        f"- Data source: {scan.get('source')}",
        f"- Dataset: {scan.get('dataset_name')}" + (" (SYNTHETIC DEMO DATA)" if scan.get("synthetic") else ""),
        f"- Input SHA-256 (first 16 chars): {scan.get('input_sha256')}",
        f"- Status: {scan.get('status')}",
    ]
    if scan.get("status") != "OK":
        lines += ["", "## Validation errors"] + [f"- {e}" for e in scan["validation"]["errors"]]
        return "\n".join(lines) + "\n"
    lines += [f"- Advisory decision: {scan['decision']} — {scan['decision_text']}",
              f"- Configuration findings: {scan['config_finding_count']}",
              f"- Audit indicators: {scan['audit_indicator_count']}",
              f"- Findings with UNKNOWN status: {scan['unknown_count']}",
              f"- Risk Story: {scan['risk_story']['overall_status']}",
              "", "## Findings"]
    for f in scan["findings"]:
        lines.append(f"- [{f['severity']} {f['score']}] {f['title']} (`{f['id']}`, confidence {f['confidence']})")
    lines += ["", "## Limitations"] + [f"- {x}" for x in scan["limitations"]]
    lines += ["", "> CloudGuard AI scores are prioritisation heuristics, not probabilities of compromise."]
    return "\n".join(lines) + "\n"


def simulation_report_header() -> str:
    return f"{SIMULATION_LABEL}. Proposals require {REVIEW_STATUS}."
