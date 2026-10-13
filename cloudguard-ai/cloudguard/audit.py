"""Audit-event analysis.

Outputs are INDICATORS, kept distinct from configuration findings
(source="audit"). A policy-change event is not proof of compromise, and a
denied request is never treated as a successful access.
"""
from __future__ import annotations

from typing import Any

from .models import SOURCE_AUDIT, make_finding
from .explanations import rule_text

PUBLIC_ACCESS_ACTIONS = {"PutBucketPolicy", "PutBucketAcl", "PutPublicAccessBlock", "SetPublicAccess"}
PERMISSION_CHANGE_ACTIONS = {"AttachRolePolicy", "PutRolePolicy", "UpdateAssumeRolePolicy",
                             "CreatePolicyVersion", "AttachUserPolicy", "PutUserPolicy"}
READ_ACTIONS = {"GetObject", "ListBucket", "GetObjectVersion"}


def _identity_context(config: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    declared = {i["id"] for i in config.get("identities", [])}
    sensitive = {r["id"] for r in config.get("resources", []) if r.get("sensitive") is True}
    exposed_identities = {e["uses_identity"] for e in config.get("entry_points", [])
                          if e.get("publicly_exposed") is True and e.get("uses_identity")}
    return declared, sensitive, exposed_identities


def _event_finding(rule_id: str, event: dict[str, Any], **kw: Any) -> dict[str, Any]:
    text = rule_text(rule_id)
    return make_finding(
        rule_id=rule_id,
        title=text["title"],
        category=text["category"],
        resource_id=event.get("resource"),
        identity_id=kw.pop("identity_id", None),
        evidence=kw.pop("evidence", []),
        why_it_matters=text["why_it_matters"],
        potential_impact=text["potential_impact"],
        limitations=list(text["limitations"]) + kw.pop("extra_limitations", []),
        recommended_action=text["recommended_action"],
        remediation_available=False,
        source=SOURCE_AUDIT,
        factors=kw.pop("factors"),
        finding_key=f"{rule_id}:{event['id']}",
    )


def analyze_audit_events(events: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    """Produce audit indicator findings from normalised events."""
    declared, sensitive, exposed_identities = _identity_context(config)
    findings: list[dict[str, Any]] = []
    for ev in events:
        eid = ev["id"]
        outcome = ev["outcome"]
        success = outcome == "success"
        resource = ev.get("resource")
        is_sensitive = resource in sensitive
        details_text = str(ev.get("details", {})).lower()
        evidence = [f"event.id={eid}", f"event.action={ev['action']}", f"event.outcome={outcome}"]
        if ev.get("timestamp"):
            evidence.append(f"event.timestamp={ev['timestamp']}")
        if ev.get("actor"):
            evidence.append(f"event.actor={ev['actor']}")
        context_complete = not ev.get("missing")

        # Successful change that adds public access.
        if ev["action"] in PUBLIC_ACCESS_ACTIONS and success and "public" in details_text:
            findings.append(_event_finding(
                "AUDIT_PUBLIC_ACCESS_CHANGE", ev, evidence=evidence + ["event.details mentions public access"],
                factors={"exposure": 80,
                         "sensitivity": 100 if is_sensitive else 40,
                         "privilege_breadth": 0,
                         "evidence_quality": 70 if context_complete else 40},
                extra_limitations=["Actor authorisation is not verified by this prototype."],
            ))

        # Successful permission modification.
        if ev["action"] in PERMISSION_CHANGE_ACTIONS and success:
            target = resource
            exposed = target in exposed_identities
            reaches_sensitive = target in exposed_identities or target in declared
            findings.append(_event_finding(
                "AUDIT_PERMISSION_CHANGE", ev, identity_id=target if target in declared else None,
                evidence=evidence + [f"target identity exposed via entry point={exposed}"],
                factors={"exposure": 70 if exposed else 30,
                         "sensitivity": 100 if reaches_sensitive else 40,
                         "privilege_breadth": 80 if "wildcard" in details_text else 50,
                         "evidence_quality": 70 if context_complete else 40},
                extra_limitations=["The change content is taken from the event details only."],
            ))

        # Denied request: recorded as a denial, never as access.
        if outcome == "denied":
            findings.append(_event_finding(
                "AUDIT_DENIED_REQUEST", ev,
                evidence=evidence + ["outcome=denied; the request was NOT successful"],
                factors={"exposure": 0,
                         "sensitivity": 50 if is_sensitive else 10,
                         "privilege_breadth": 0,
                         "evidence_quality": 90 if context_complete else 50},
            ))

        # Successful access to sensitive resource by an undeclared actor.
        if (success and is_sensitive and ev["action"] in READ_ACTIONS
                and ev.get("actor") and ev["actor"] not in declared):
            findings.append(_event_finding(
                "AUDIT_UNDECLARED_ACTOR_SENSITIVE", ev,
                evidence=evidence + ["actor not present in declared identities"],
                factors={"exposure": 50, "sensitivity": 100, "privilege_breadth": 0,
                         "evidence_quality": 60},
                extra_limitations=["The declared identity list may be incomplete."],
            ))

        # Missing context lowers confidence and is reported as an evidence gap.
        if ev.get("missing"):
            findings.append(_event_finding(
                "AUDIT_MISSING_CONTEXT", ev,
                evidence=evidence + [f"missing={','.join(ev['missing'])}"],
                factors={"exposure": 0, "sensitivity": 0, "privilege_breadth": 0,
                         "evidence_quality": 20},
            ))
    return findings
