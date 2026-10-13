"""Evidence-based explanations.

The deterministic template engine always works and needs no API key. The
optional LLM path is OFF by default. Its output is validated, can never change
scores, severity, findings, graph, or policy, and falls back to templates on
any failure.
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

KNOWLEDGE_PATH = Path(__file__).resolve().parent.parent / "data" / "security_knowledge.json"
SECRET_PATTERN = re.compile(r"(secret|token|password|passwd|api[_-]?key|credential|akia[0-9a-z]{8,})", re.I)
LLM_MAX_CHARS = 1200


@lru_cache(maxsize=1)
def load_knowledge(path: str | None = None) -> dict[str, Any]:
    """Load the rule knowledge base (cached)."""
    with open(path or KNOWLEDGE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def rule_text(rule_id: str) -> dict[str, Any]:
    """Return rule text, with a neutral fallback for unknown rules."""
    kb = load_knowledge()
    if rule_id in kb:
        return kb[rule_id]
    return {"title": rule_id.replace("_", " ").title(), "category": "Other",
            "why_it_matters": "This rule has no knowledge-base entry.",
            "potential_impact": "Impact not described.",
            "recommended_action": "Review the evidence manually.",
            "limitations": ["No knowledge-base text for this rule."]}


def severity_rationale(finding: dict[str, Any]) -> str:
    """Explain the score in plain English from the factor breakdown."""
    bd = finding.get("score_breakdown", {})
    parts = []
    for name in ("exposure", "sensitivity", "privilege_breadth", "evidence_quality"):
        if name in bd:
            parts.append(f"{name.replace('_', ' ')} {bd[name]['value']:.0f}/100 (weight {bd[name]['weight']:.2f})")
    text = f"Score {finding.get('score')} ({finding.get('severity')}) from: " + "; ".join(parts) + "."
    if "cap_applied" in bd:
        text += " " + bd["cap_applied"]
    return text


def explain_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Deterministic, beginner-friendly explanation for one finding."""
    rt = rule_text(finding["rule_id"])
    affected = " and ".join(x for x in (
        f"identity '{finding['identity_id']}'" if finding.get("identity_id") else None,
        f"resource '{finding['resource_id']}'" if finding.get("resource_id") else None) if x) or "no specific asset"
    return {
        "mode": "template",
        "what_was_detected": rt["title"] + ".",
        "affected": f"Affected: {affected}.",
        "evidence": list(finding.get("evidence", [])),
        "why_it_matters": rt["why_it_matters"],
        "potential_impact": rt["potential_impact"],
        "severity_rationale": severity_rationale(finding),
        "confidence_and_limitations": (f"Confidence: {finding.get('confidence')}. "
                                       + " ".join(finding.get("limitations", []) + rt["limitations"])),
        "recommended_next_action": rt["recommended_action"],
    }


# ---------- Optional LLM path (off by default) ----------

def llm_enabled() -> bool:
    """LLM mode requires an explicit flag AND a key. Absent either, templates are used."""
    return os.getenv("CLOUDGUARD_LLM_ENABLED", "false").lower() == "true" and bool(os.getenv("OPENAI_API_KEY"))


def build_llm_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Minimum evidence for one finding. Secret-like strings are removed."""
    def clean(s: str) -> str:
        return "[redacted]" if SECRET_PATTERN.search(s) else s
    return {
        "finding_id": finding["id"],
        "rule_id": finding["rule_id"],
        "title": finding["title"],
        "severity": finding.get("severity"),
        "evidence": [clean(str(e)) for e in finding.get("evidence", [])][:10],
        "limitations": [clean(str(x)) for x in finding.get("limitations", [])][:5],
    }


def validate_llm_output(text: str, expected_finding_id: str) -> tuple[dict | None, list[str]]:
    """Accept only well-formed JSON whose finding_id matches the request."""
    errors: list[str] = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None, ["Model output is not valid JSON."]
    if not isinstance(data, dict):
        return None, ["Model output must be a JSON object."]
    if data.get("finding_id") != expected_finding_id:
        errors.append("finding_id does not match the requested finding.")
    explanation = data.get("explanation")
    if not isinstance(explanation, str) or not explanation.strip():
        errors.append("explanation must be a non-empty string.")
    elif len(explanation) > LLM_MAX_CHARS:
        errors.append(f"explanation exceeds {LLM_MAX_CHARS} characters.")
    return (None, errors) if errors else ({"explanation": explanation.strip()}, [])


def generate_explanation(finding: dict[str, Any], use_llm: bool = False,
                         llm_client: Callable[[dict[str, Any]], str] | None = None) -> dict[str, Any]:
    """Return a template explanation, or a validated LLM explanation with fallback.

    llm_client receives the minimal payload and returns the raw model text.
    The model only explains; it never changes the finding.
    """
    template = explain_finding(finding)
    if not use_llm:
        return template
    if llm_client is None:
        return {**template, "fallback_reason": "LLM not configured; template explanation shown."}
    try:
        raw = llm_client(build_llm_payload(finding))
        parsed, errors = validate_llm_output(raw, finding["id"])
        if errors:
            return {**template, "fallback_reason": "Model output rejected: " + "; ".join(errors)}
        return {**template, "mode": "llm", "llm_explanation": parsed["explanation"]}
    except Exception as exc:  # any API, timeout or network error falls back safely
        return {**template, "fallback_reason": f"LLM call failed ({type(exc).__name__}); template shown."}
