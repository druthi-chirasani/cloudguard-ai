"""Policy-as-code remediation PROPOSALS for human review.

Nothing here changes live infrastructure. An exact patch is produced only when
the input supplies enough context. Otherwise a checklist is returned.
"""
from __future__ import annotations

import copy
import json
from typing import Any

from .models import REVIEW_STATUS

ALLOWED_RESOURCE_CHANGES = {"public_access"}


def _find(items: list[dict], item_id: str | None) -> dict | None:
    return next((i for i in items if i["id"] == item_id), None)


def _checklist(finding: dict[str, Any], items: list[str], reasoning: str) -> dict[str, Any]:
    return {
        "finding_id": finding["id"], "rule_id": finding["rule_id"], "status": REVIEW_STATUS,
        "type": "checklist", "patch": None, "original": None, "proposed": None,
        "reasoning": reasoning, "assumptions": [], "side_effects": [],
        "human_checks": items, "validation": {"json_valid": None, "checks": [], "passed": None},
    }


def _validate(original: Any, proposed: Any, rule_id: str) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    try:
        json.loads(json.dumps(proposed, sort_keys=True))
        json_ok = True
    except (TypeError, ValueError):
        json_ok = False
    checks.append({"name": "proposed JSON round-trips", "ok": json_ok})
    if isinstance(proposed, dict) and "permissions" in proposed:
        allow_ok = all(p["actions"] for p in proposed["permissions"] if p["effect"] == "Allow")
        deny_before = [p for p in original["permissions"] if p["effect"] == "Deny"]
        deny_after = [p for p in proposed["permissions"] if p["effect"] == "Deny"]
        checks.append({"name": "every Allow statement keeps at least one action", "ok": allow_ok})
        checks.append({"name": "explicit Deny statements unchanged", "ok": deny_before == deny_after})
        checks.append({"name": "conditions preserved", "ok": [p["conditions"] for p in original["permissions"]]
                       == [p["conditions"] for p in proposed["permissions"]]})
    if isinstance(proposed, dict) and "public_access" in proposed:
        checks.append({"name": "public_access is boolean", "ok": isinstance(proposed["public_access"], bool)})
    return {"json_valid": json_ok, "checks": checks, "passed": all(c["ok"] for c in checks)}


def propose_remediation(config: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    """Build a proposal for one finding. Returns exact patch or checklist."""
    rule = finding["rule_id"]

    if rule == "PUBLIC_SENSITIVE_RESOURCE":
        res = _find(config["resources"], finding.get("resource_id"))
        if res is None or res.get("public_access") is not True:
            return _checklist(finding, ["Re-scan: the resource no longer shows public access."],
                              "The finding does not match the current configuration.")
        proposed = copy.deepcopy(res)
        proposed["public_access"] = False
        return {
            "finding_id": finding["id"], "rule_id": rule, "status": REVIEW_STATUS, "type": "exact_patch",
            "patch": {"target": "resource", "id": res["id"], "changes": {"public_access": False}},
            "original": copy.deepcopy(res), "proposed": proposed,
            "reasoning": "The resource is marked sensitive and public_access is true. Setting public_access to false removes the explicit public flag.",
            "assumptions": ["Public access is not intended for this resource.",
                            "No approved consumer relies on anonymous reads."],
            "side_effects": ["Any client that reads this resource anonymously will stop working."],
            "human_checks": ["Confirm no approved public consumer depends on this resource.",
                             "Check any provider-level public-access block separately."],
            "validation": _validate(res, proposed, rule),
        }

    if rule in ("IAM_EXCESS_PRIVILEGE", "IAM_WILDCARD_SCOPE"):
        ident = _find(config["identities"], finding.get("identity_id"))
        required = ident.get("required_actions") if ident else None
        if not required or any(a == "*" or a.endswith("*") for a in required):
            return _checklist(finding, [
                "Declare a concrete required_actions list for this identity; no exact policy is generated without it.",
                "Review each granted action with the application owner.",
                "Narrow resource scope manually once the documented resources are known.",
            ], "Required actions are missing or contain wildcards, so an exact safe policy cannot be established.")
        new_actions = sorted(set(required))
        proposed = copy.deepcopy(ident)
        for perm in proposed["permissions"]:
            if perm["effect"] == "Allow":
                perm["actions"] = list(new_actions)
        removed = sorted({a for p in ident["permissions"] if p["effect"] == "Allow" for a in p["actions"]}
                         - set(new_actions) - {"*"})
        return {
            "finding_id": finding["id"], "rule_id": rule, "status": REVIEW_STATUS, "type": "exact_patch",
            "patch": {"target": "identity", "id": ident["id"], "replace_allow_actions": new_actions},
            "original": copy.deepcopy(ident), "proposed": proposed,
            "reasoning": f"Allow statements are narrowed to the declared required actions {new_actions}. Deny statements and conditions are preserved.",
            "assumptions": ["required_actions is complete for this identity.",
                            "Resource scope is NOT changed by this proposal."],
            "side_effects": [f"Actions removed from the grant: {removed or 'none'}. Unlisted workflows may fail."],
            "human_checks": ["Confirm required_actions with the application owner.",
                             "Review resource scope separately; wildcard resources remain unchanged."],
            "validation": _validate(ident, proposed, rule),
        }

    return _checklist(finding, [finding.get("recommended_action") or "Review the evidence manually.",
                                "Confirm the supplied evidence before any change."],
                      "This rule has no exact safe patch. A checklist is returned instead of fabricated policy.")


def apply_patch(config: dict[str, Any], proposal: dict[str, Any]) -> dict[str, Any]:
    """Return a NEW configuration with the proposal applied. The input is never mutated."""
    if proposal.get("type") != "exact_patch" or not proposal.get("patch"):
        raise ValueError("Proposal has no exact patch to apply.")
    new = copy.deepcopy(config)
    patch = proposal["patch"]
    if patch["target"] == "resource":
        if set(patch["changes"]) - ALLOWED_RESOURCE_CHANGES:
            raise ValueError("Patch changes a field that is not allowed.")
        res = _find(new["resources"], patch["id"])
        if res is None:
            raise ValueError(f"Unknown resource {patch['id']!r}")
        res.update(patch["changes"])
    elif patch["target"] == "identity":
        ident = _find(new["identities"], patch["id"])
        if ident is None:
            raise ValueError(f"Unknown identity {patch['id']!r}")
        for perm in ident["permissions"]:
            if perm["effect"] == "Allow":
                perm["actions"] = list(patch["replace_allow_actions"])
    else:
        raise ValueError("Unknown patch target.")
    return new
