"""Risk Story: connects evidence-backed findings into one narrative.

Only explicitly supplied, validated edges form the VERIFIED chain. Missing
links are shown, and the story is never described as a proven attack.
"""
from __future__ import annotations

from typing import Any

DISCLAIMER = ("This is a verified configuration path, not proof of exploitability. "
              "Scores are prioritisation aids and are not summed across related findings.")


def _name(config: dict[str, Any], node_id: str | None) -> str:
    if not node_id:
        return "(none)"
    for coll in ("resources", "identities", "entry_points"):
        for item in config.get(coll, []):
            if item["id"] == node_id:
                return item.get("name", node_id)
    return node_id


def _story_for_path(config: dict[str, Any], path: dict[str, Any], findings: list[dict[str, Any]],
                    verified: bool) -> dict[str, Any]:
    nodes = set(path["path"])
    steps: list[dict[str, Any]] = []
    entry = next(e for e in config["entry_points"] if e["id"] == path["entry_id"])
    steps.append({"step": 1, "kind": "entry_point", "status": "verified",
                  "statement": f"'{_name(config, entry['id'])}' is publicly exposed.",
                  "evidence": ["entry_points.publicly_exposed=true"],
                  "impact": "Anything reachable from this entry point may be in scope."})
    for n, e in enumerate(path["edges"], start=2):
        status = "verified" if e["validated"] else "unknown"
        steps.append({"step": n, "kind": "relationship", "status": status,
                      "statement": f"'{_name(config, e['from'])}' is linked to '{_name(config, e['to'])}' ({e['type']}).",
                      "evidence": [e["evidence"]] if e["evidence"] else [],
                      "impact": "Establishes that the first node can act on the second."})
    res_id = path["resource_id"]
    resource = next(r for r in config["resources"] if r["id"] == res_id)
    steps.append({"step": len(steps) + 1, "kind": "resource", "status": "verified",
                  "statement": f"'{_name(config, res_id)}' is marked sensitive.",
                  "evidence": ["resource.sensitive=true",
                               f"resource.public_access={resource.get('public_access')}"],
                  "impact": "Sensitive data is the potential consequence if the path were misused."})
    related = [f["id"] for f in findings if f.get("identity_id") in nodes or f.get("resource_id") in nodes]
    return {
        "status": "VERIFIED CONFIGURATION PATH" if verified else "INCOMPLETE EVIDENCE",
        "entry_id": path["entry_id"], "identity_id": path.get("identity_id"), "resource_id": res_id,
        "steps": steps,
        "missing_links": path.get("missing_links", []),
        "related_finding_ids": sorted(set(related)),
        "narrative": " ".join(s["statement"] for s in steps),
        "limitations": ["Configuration input only; runtime controls are not modelled."],
    }


def build_risk_story(config: dict[str, Any], paths: dict[str, list], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the Risk Story from exposure paths (verified and incomplete)."""
    stories = [_story_for_path(config, p, findings, True) for p in paths["verified"]]
    stories += [_story_for_path(config, p, findings, False) for p in paths["incomplete"]]
    if paths["verified"]:
        overall = "VERIFIED CONFIGURATION PATH"
    elif paths["incomplete"]:
        overall = "INCOMPLETE EVIDENCE"
    else:
        overall = "NO VERIFIED PATH"
    if overall == "NO VERIFIED PATH":
        narrative = ("No exposed entry point has a verified path to a sensitive resource in the supplied input. "
                     "No path has been invented.")
    else:
        narrative = " ".join(s["narrative"] for s in stories[:1])
    return {"overall_status": overall, "stories": stories, "narrative": narrative,
            "disclaimer": DISCLAIMER}
