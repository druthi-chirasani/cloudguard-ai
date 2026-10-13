"""Configuration security detection rules.

Each rule returns findings with evidence and factor inputs. Scoring happens
later in risk_scoring.py. Absence of data is reported as UNKNOWN, never SAFE.
"""
from __future__ import annotations

from typing import Any

from .attack_paths import build_graph, find_exposure_paths
from .explanations import rule_text
from .models import make_finding
from .models import clamp


def _finding(rule_id: str, *, factors: dict[str, float], evidence: list[str],
             resource_id: str | None = None, identity_id: str | None = None,
             limitations: list[str] | None = None, remediation: bool = False,
             status: str = "open", key: str | None = None) -> dict[str, Any]:
    t = rule_text(rule_id)
    return make_finding(
        rule_id=rule_id, title=t["title"], category=t["category"],
        resource_id=resource_id, identity_id=identity_id, evidence=evidence,
        why_it_matters=t["why_it_matters"], potential_impact=t["potential_impact"],
        limitations=list(t["limitations"]) + list(limitations or []),
        recommended_action=t["recommended_action"], remediation_available=remediation,
        factors=factors, finding_key=key, status=status,
    )


def identity_grants(identity: dict[str, Any]) -> dict[str, Any]:
    """Summarise an identity's Allow and Deny statements conservatively.

    Deny statements remove only exact action strings. This is not full IAM evaluation.
    """
    allows = [p for p in identity["permissions"] if p["effect"] == "Allow"]
    denies = [p for p in identity["permissions"] if p["effect"] == "Deny"]
    granted: set[str] = set()
    reach: set[str] = set()
    wildcard_action = wildcard_resource = False
    for p in allows:
        for a in p["actions"]:
            if a == "*" or a.endswith("*"):
                wildcard_action = True
            else:
                granted.add(a)
        if "*" in p["resources"]:
            wildcard_resource = True
        reach.update(p["resources"])
    denied = {a for p in denies for a in p["actions"]}
    return {
        "has_allow": bool(allows),
        "granted": sorted(granted - denied),
        "denied_actions": sorted(denied),
        "denied_and_granted": sorted(granted & denied),
        "wildcard_action": wildcard_action,
        "wildcard_resource": wildcard_resource,
        "reach": sorted(reach),
        "all_conditional": bool(allows) and all(bool(p["conditions"]) for p in allows),
    }


def identity_breadth(identity: dict[str, Any]) -> tuple[float, list[str] | None, dict[str, Any]]:
    """Return (breadth factor 0-100, excess actions or None if undeclared, grants)."""
    g = identity_grants(identity)
    required = identity.get("required_actions")
    excess = None if required is None else sorted(set(g["granted"]) - set(required))
    breadth = clamp(20 + 15 * len(excess or []) + (25 if g["wildcard_action"] else 0)
                    + (25 if g["wildcard_resource"] else 0))
    return breadth, excess, g


def detect_public_exposure(config: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for r in config["resources"]:
        rid, pa, sensitive = r["id"], r.get("public_access"), r.get("sensitive")
        if pa is True and sensitive is True:
            findings.append(_finding(
                "PUBLIC_SENSITIVE_RESOURCE", resource_id=rid, remediation=True,
                evidence=["resource.sensitive=true", "resource.public_access=true"],
                factors={"exposure": 100, "sensitivity": 100, "privilege_breadth": 0, "evidence_quality": 100},
            ))
        elif pa is True and sensitive is not True:
            findings.append(_finding(
                "PUBLIC_NON_SENSITIVE_RESOURCE", resource_id=rid,
                evidence=["resource.public_access=true",
                          f"resource.sensitive={'false' if sensitive is False else 'UNKNOWN'}"],
                factors={"exposure": 100, "sensitivity": 20 if sensitive is False else 50,
                         "privilege_breadth": 0, "evidence_quality": 100 if sensitive is False else 60},
                limitations=[] if sensitive is False else ["Sensitivity not stated; treated as moderate."],
            ))
        elif sensitive is True and pa is None:
            findings.append(_finding(
                "UNKNOWN_PUBLIC_ACCESS_SENSITIVE", resource_id=rid, status="unknown",
                evidence=["resource.sensitive=true", "resource.public_access=absent (UNKNOWN)"],
                factors={"exposure": 50, "sensitivity": 100, "privilege_breadth": 0, "evidence_quality": 20},
            ))
    return findings


def detect_identity_findings(config: dict[str, Any], exposed_identities: set[str],
                             sensitive_ids: set[str]) -> list[dict[str, Any]]:
    findings = []
    for ident in config["identities"]:
        iid = ident["id"]
        breadth, excess, g = identity_breadth(ident)
        if not g["has_allow"]:
            continue
        required = ident.get("required_actions")
        reaches = sensitive_ids if g["wildcard_resource"] else (set(g["reach"]) & sensitive_ids)
        linked = iid in exposed_identities
        factors = {
            "exposure": 60 if linked else 20,
            "sensitivity": 100 if reaches else 40,
            "privilege_breadth": breadth,
            "evidence_quality": 60 if g["all_conditional"] else 100,
        }
        evidence = [
            f"identity.granted_actions={g['granted'] or ['(wildcard only)']}",
            f"identity.required_actions={required if required is not None else 'NOT DECLARED'}",
            f"identity.reaches_sensitive_resources={sorted(reaches) or 'none'}",
            f"identity.linked_to_exposed_entry_point={linked}",
        ]
        limits = []
        if g["all_conditional"]:
            limits.append("Conditions are recorded as evidence but are not evaluated against live request context.")
        if g["denied_actions"]:
            limits.append(f"Explicit Deny applies only to exact action strings: {g['denied_actions']}.")
        if g["denied_and_granted"]:
            limits.append(f"Denied actions also appear as Allow: {g['denied_and_granted']}.")
        if g["wildcard_action"] and g["denied_actions"]:
            limits.append("A wildcard grant may still cover actions not named in the Deny.")

        if required is None:
            if g["wildcard_action"] or g["granted"] or g["wildcard_resource"]:
                factors["evidence_quality"] = min(factors["evidence_quality"], 20)
                findings.append(_finding(
                    "IAM_REQUIREMENTS_UNDECLARED", identity_id=iid, status="unknown",
                    evidence=evidence, factors=factors,
                    limitations=limits + ["required_actions not declared; excess privilege not assessed."],
                ))
            continue
        remediation = len(required) > 0 and not any(a == "*" or a.endswith("*") for a in required)
        if g["wildcard_action"]:
            rule = "IAM_WILDCARD_SCOPE"
        elif excess:
            rule = "IAM_EXCESS_PRIVILEGE"
            evidence.append(f"identity.excess_actions={excess}")
        elif g["wildcard_resource"] and g["all_conditional"]:
            rule = "IAM_CONDITIONAL_BROAD_SCOPE"
        elif g["wildcard_resource"]:
            rule = "IAM_WILDCARD_SCOPE"
        else:
            continue
        findings.append(_finding(rule, identity_id=iid, evidence=evidence, factors=factors,
                                 limitations=limits, remediation=remediation))
    return findings


def detect_relationship_findings(config: dict[str, Any], graph, breadth_map: dict[str, float],
                                 sensitive_ids: set[str]) -> list[dict[str, Any]]:
    findings = []
    paths = find_exposure_paths(config, graph)
    for p in paths["verified"]:
        ident = p["identity_id"]
        evidence = [f"{e['from']} -[{e['type']}]-> {e['to']} validated=True: {e['evidence']}" for e in p["edges"]]
        findings.append(_finding(
            "EXPOSED_PATH_TO_SENSITIVE", identity_id=ident, resource_id=p["resource_id"],
            evidence=[f"entry_point={p['entry_id']} publicly_exposed=true"] + evidence,
            factors={"exposure": 100, "sensitivity": 100,
                     "privilege_breadth": breadth_map.get(ident, 0.0), "evidence_quality": 100},
            limitations=["Verified configuration path only; not an exploitability proof."],
            key=f"EXPOSED_PATH_TO_SENSITIVE:{p['entry_id']}>{ident}>{p['resource_id']}",
        ))
    for rel in config["relationships"]:
        if rel["validated"] or rel["target"] not in sensitive_ids:
            continue
        src = rel["source"]
        if src not in breadth_map:
            continue
        findings.append(_finding(
            "POSSIBLE_RELATIONSHIP_UNVERIFIED", identity_id=src, resource_id=rel["target"],
            status="unknown",
            evidence=[f"relationship {src} -> {rel['target']} validated=False", f"evidence text: {rel['evidence']}"],
            factors={"exposure": 30, "sensitivity": 100,
                     "privilege_breadth": breadth_map.get(src, 0.0), "evidence_quality": 30},
            limitations=["Unvalidated relationship; excluded from verified paths."],
            key=f"POSSIBLE_RELATIONSHIP_UNVERIFIED:{src}>{rel['target']}",
        ))
    return findings


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out = []
    for f in findings:
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        out.append(f)
    return out


def run_config_detection(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Run every configuration rule and deduplicate by stable finding id."""
    graph = build_graph(config)
    sensitive_ids = {r["id"] for r in config["resources"] if r.get("sensitive") is True}
    exposed_identities = {e["uses_identity"] for e in config["entry_points"]
                          if e.get("publicly_exposed") is True and e.get("uses_identity")}
    breadth_map = {i["id"]: identity_breadth(i)[0] for i in config["identities"]}
    findings = []
    findings += detect_public_exposure(config)
    findings += detect_identity_findings(config, exposed_identities, sensitive_ids)
    findings += detect_relationship_findings(config, graph, breadth_map, sensitive_ids)
    return _dedupe(findings)
