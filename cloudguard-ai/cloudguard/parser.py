"""Input loading and validation for CloudGuard AI.

All uploads are treated as untrusted data. Nothing here executes content.
Missing information is recorded as UNKNOWN (None), never as safe/false.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any

from .models import ID_PATTERN, MAX_UPLOAD_BYTES, SCHEMA_VERSION

ALLOWED_RESOURCE_TYPES = {"storage", "database", "compute", "other"}
ALLOWED_EFFECTS = {"Allow", "Deny"}
ALLOWED_OUTCOMES = {"success", "denied", "failed", "unknown"}
_ID_RE = re.compile(ID_PATTERN)


def read_json_text(data: str | bytes | None) -> tuple[Any, list[str]]:
    """Parse JSON text safely. Returns (parsed_or_None, errors)."""
    if data is None:
        return None, ["No input was provided."]
    if isinstance(data, bytes):
        if len(data) > MAX_UPLOAD_BYTES:
            return None, [f"File is {len(data)} bytes; the limit is {MAX_UPLOAD_BYTES} bytes."]
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            return None, ["File is not valid UTF-8 text."]
    if not isinstance(data, str):
        return None, ["Input must be text or bytes."]
    if len(data.encode("utf-8")) > MAX_UPLOAD_BYTES:
        return None, [f"File exceeds the {MAX_UPLOAD_BYTES} byte limit."]
    if not data.strip():
        return None, ["Input is empty."]
    try:
        return json.loads(data), []
    except json.JSONDecodeError as exc:
        return None, [f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}."]


def _normalize_permission(owner: str, idx: int, perm: Any, errors: list[str]) -> dict | None:
    where = f"identity '{owner}' permissions[{idx}]"
    if not isinstance(perm, dict):
        errors.append(f"{where} must be an object.")
        return None
    effect = perm.get("effect")
    if effect not in ALLOWED_EFFECTS:
        errors.append(f"{where} has effect {effect!r}; expected 'Allow' or 'Deny'.")
        return None
    actions = perm.get("actions")
    if not isinstance(actions, list) or not actions:
        errors.append(f"{where} must have a non-empty 'actions' list.")
        return None
    if not all(isinstance(a, str) and a.strip() for a in actions):
        errors.append(f"{where} contains an empty or non-string action.")
        return None
    resources = perm.get("resources")
    if not isinstance(resources, list) or not all(isinstance(r, str) and r.strip() for r in resources):
        errors.append(f"{where} must have a 'resources' list of non-empty strings.")
        return None
    conditions = perm.get("conditions", {})
    if not isinstance(conditions, dict):
        errors.append(f"{where} 'conditions' must be an object.")
        return None
    return {
        "effect": effect,
        "actions": [a.strip() for a in actions],
        "resources": [r.strip() for r in resources],
        "conditions": copy.deepcopy(conditions),
    }


def validate_config(data: Any) -> dict[str, Any]:
    """Validate and normalise a configuration document.

    Returns a dict with keys: config (normalised dict or None), errors,
    warnings, limitations. If errors is non-empty, config is None.
    """
    errors: list[str] = []
    warnings: list[str] = []
    limitations: list[str] = []

    def done(cfg: dict | None) -> dict[str, Any]:
        return {"config": cfg if not errors else None, "errors": errors,
                "warnings": warnings, "limitations": limitations}

    if not isinstance(data, dict):
        errors.append("Top-level JSON must be an object.")
        return done(None)

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be '{SCHEMA_VERSION}' (found {data.get('schema_version')!r}).")

    for key in ("resources", "identities"):
        if key not in data:
            errors.append(f"Missing required top-level list '{key}'.")
        elif not isinstance(data[key], list):
            errors.append(f"'{key}' must be a list.")
    for key in ("relationships", "entry_points"):
        if key in data and not isinstance(data[key], list):
            errors.append(f"'{key}' must be a list when present.")
    if errors:
        return done(None)

    ids: dict[str, str] = {}

    def register(kind: str, idx: int, item: Any) -> str | None:
        if not isinstance(item, dict):
            errors.append(f"{kind}[{idx}] must be an object.")
            return None
        rid = item.get("id")
        if not isinstance(rid, str) or not _ID_RE.match(rid):
            errors.append(f"{kind}[{idx}] has an invalid or missing id {rid!r}.")
            return None
        if rid in ids:
            errors.append(f"Duplicate id '{rid}' (already used by a {ids[rid]}).")
            return None
        ids[rid] = kind
        return rid

    resources: list[dict] = []
    for i, item in enumerate(data["resources"]):
        rid = register("resource", i, item)
        if rid is None:
            continue
        r = copy.deepcopy(item)
        r.setdefault("name", rid)
        if r.get("type") not in ALLOWED_RESOURCE_TYPES:
            warnings.append(f"resource '{rid}' has unexpected type {r.get('type')!r}; treated as 'other'.")
            r["type"] = "other"
        sensitive = r.get("sensitive")
        if sensitive is not None and not isinstance(sensitive, bool):
            errors.append(f"resource '{rid}' field 'sensitive' must be true, false, or absent.")
        if "sensitive" not in item:
            limitations.append(f"resource '{rid}': sensitivity not stated; treated as UNKNOWN.")
            r["sensitive"] = None
        pa = r.get("public_access")
        if pa is not None and not isinstance(pa, bool):
            errors.append(f"resource '{rid}' field 'public_access' must be true, false, or absent.")
        if "public_access" not in item:
            limitations.append(f"resource '{rid}': public_access not stated; state is UNKNOWN, not SAFE.")
            r["public_access"] = None
        resources.append(r)

    identities: list[dict] = []
    for i, item in enumerate(data["identities"]):
        iid = register("identity", i, item)
        if iid is None:
            continue
        perms_raw = item.get("permissions", [])
        if not isinstance(perms_raw, list):
            errors.append(f"identity '{iid}' 'permissions' must be a list.")
            continue
        perms = []
        for j, perm in enumerate(perms_raw):
            norm = _normalize_permission(iid, j, perm, errors)
            if norm is not None:
                perms.append(norm)
        required = item.get("required_actions")
        if required is None:
            limitations.append(f"identity '{iid}': required_actions not declared; excess privilege not assessed.")
        elif not isinstance(required, list) or not all(isinstance(a, str) for a in required):
            errors.append(f"identity '{iid}' 'required_actions' must be a list of strings.")
            required = None
        identities.append({
            "id": iid,
            "type": item.get("type", "other"),
            "name": item.get("name", iid),
            "permissions": perms,
            "required_actions": list(required) if isinstance(required, list) else None,
        })

    entry_points: list[dict] = []
    for i, item in enumerate(data.get("entry_points", [])):
        eid = register("entry_point", i, item)
        if eid is None:
            continue
        exposed = item.get("publicly_exposed")
        if exposed is not None and not isinstance(exposed, bool):
            errors.append(f"entry_point '{eid}' field 'publicly_exposed' must be true, false, or absent.")
        if exposed is None:
            limitations.append(f"entry_point '{eid}': publicly_exposed not stated; treated as UNKNOWN.")
        uses = item.get("uses_identity")
        if uses is not None and uses not in ids:
            warnings.append(f"entry_point '{eid}' references unknown identity {uses!r}; link excluded.")
            uses = None
        entry_points.append({
            "id": eid, "type": item.get("type", "other"), "name": item.get("name", eid),
            "publicly_exposed": exposed if isinstance(exposed, bool) else None,
            "uses_identity": uses,
        })

    relationships: list[dict] = []
    for i, rel in enumerate(data.get("relationships", [])):
        if not isinstance(rel, dict):
            errors.append(f"relationships[{i}] must be an object.")
            continue
        src, tgt = rel.get("source"), rel.get("target")
        if src not in ids or tgt not in ids:
            warnings.append(f"relationships[{i}] references unknown id(s) {src!r} -> {tgt!r}; excluded.")
            continue
        validated = rel.get("validated", False)
        if not isinstance(validated, bool):
            errors.append(f"relationships[{i}] field 'validated' must be true or false.")
            continue
        relationships.append({
            "source": src, "target": tgt,
            "type": rel.get("type", "has_access"),
            "evidence": str(rel.get("evidence") or "No evidence text supplied."),
            "validated": validated,
        })

    if not resources:
        warnings.append("No resources supplied; resource-level checks will report nothing.")
    if not identities:
        warnings.append("No identities supplied; identity-level checks will report nothing.")

    normalized = {
        "schema_version": SCHEMA_VERSION,
        "dataset_name": str(data.get("dataset_name", "Unnamed dataset")),
        "synthetic": bool(data.get("synthetic", False)),
        "resources": resources,
        "identities": identities,
        "relationships": relationships,
        "entry_points": entry_points,
    }
    return done(normalized)


def validate_audit_logs(data: Any, config_ids: set[str] | None = None) -> dict[str, Any]:
    """Validate and normalise audit events. Missing context is recorded, not invented."""
    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict] = []
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        errors.append("Audit logs must be an object with an 'events' list.")
        return {"events": [], "errors": errors, "warnings": warnings}

    seen: set[str] = set()
    for idx, ev in enumerate(data["events"]):
        if not isinstance(ev, dict):
            warnings.append(f"events[{idx}] is not an object; skipped.")
            continue
        action = ev.get("action")
        if not isinstance(action, str) or not action.strip():
            warnings.append(f"events[{idx}] has no action; skipped.")
            continue
        eid = ev.get("id")
        if not isinstance(eid, str) or not eid.strip():
            eid = f"evt-unassigned-{idx}"
            warnings.append(f"events[{idx}] has no id; assigned '{eid}'.")
        if eid in seen:
            warnings.append(f"Duplicate audit event id '{eid}'.")
        seen.add(eid)
        ts = ev.get("timestamp")
        ts = ts if isinstance(ts, str) and ts.strip() else None
        actor = ev.get("actor") if isinstance(ev.get("actor"), str) and ev.get("actor").strip() else None
        resource = ev.get("resource") if isinstance(ev.get("resource"), str) and ev.get("resource").strip() else None
        outcome = ev.get("outcome")
        if outcome not in ALLOWED_OUTCOMES:
            warnings.append(f"event '{eid}' has unexpected outcome {outcome!r}; treated as 'unknown'.")
            outcome = "unknown"
        missing = [name for name, val in (("timestamp", ts), ("actor", actor), ("resource", resource)) if val is None]
        if missing:
            warnings.append(f"event '{eid}' is missing: {', '.join(missing)}.")
        details = ev.get("details") if isinstance(ev.get("details"), dict) else {}
        events.append({
            "id": eid, "timestamp": ts, "actor": actor, "action": action.strip(),
            "resource": resource, "outcome": outcome,
            "source_ip": ev.get("source_ip") if isinstance(ev.get("source_ip"), str) else None,
            "details": details, "missing": missing,
        })
    return {"events": events, "errors": errors, "warnings": warnings}
