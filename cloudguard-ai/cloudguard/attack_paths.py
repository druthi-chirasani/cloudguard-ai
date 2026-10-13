"""Identity and resource relationship graph (NetworkX).

Edges come only from explicit input: validated relationships and the
entry_point.uses_identity link. Nothing is inferred from co-location.
A path is a verified configuration path, not proof of exploitability.
"""
from __future__ import annotations

from typing import Any

import networkx as nx

MAX_PATHS = 50


def build_graph(config: dict[str, Any]) -> nx.DiGraph:
    """Build a directed graph of entry points, identities and resources."""
    g = nx.DiGraph()
    for r in config.get("resources", []):
        g.add_node(r["id"], kind="resource", name=r.get("name", r["id"]),
                   sensitive=r.get("sensitive"), public_access=r.get("public_access"))
    for i in config.get("identities", []):
        g.add_node(i["id"], kind="identity", name=i.get("name", i["id"]))
    for e in config.get("entry_points", []):
        g.add_node(e["id"], kind="entry_point", name=e.get("name", e["id"]),
                   publicly_exposed=e.get("publicly_exposed"))
        if e.get("uses_identity"):
            g.add_edge(e["id"], e["uses_identity"], type="uses_identity", validated=True,
                       evidence="Declared in entry_points: uses_identity")
    for rel in config.get("relationships", []):
        g.add_edge(rel["source"], rel["target"], type=rel.get("type", "has_access"),
                   validated=bool(rel.get("validated")), evidence=rel.get("evidence", ""))
    return g


def _check_nodes(graph: nx.DiGraph, *node_ids: str) -> None:
    for node_id in node_ids:
        if node_id not in graph:
            raise ValueError(f"Unknown node id: {node_id!r}")


def find_paths(graph: nx.DiGraph, source_id: str, target_id: str,
               max_depth: int = 6, verified_only: bool = True) -> list[list[str]]:
    """Find simple paths from source to target, bounded by max_depth.

    With verified_only=True, only validated edges are used.
    """
    _check_nodes(graph, source_id, target_id)
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    view = graph
    if verified_only:
        view = nx.DiGraph()
        view.add_nodes_from(graph.nodes(data=True))
        view.add_edges_from((u, v, d) for u, v, d in graph.edges(data=True) if d.get("validated"))
    if source_id not in view or target_id not in view:
        return []
    paths: list[list[str]] = []
    for path in nx.all_simple_paths(view, source_id, target_id, cutoff=max_depth):
        paths.append(list(path))
        if len(paths) >= MAX_PATHS:
            break
    return paths


def explain_path(graph: nx.DiGraph, path: list[str]) -> list[dict[str, Any]]:
    """Return one explanation dict per edge along a path."""
    _check_nodes(graph, *path)
    out = []
    for u, v in zip(path, path[1:]):
        if not graph.has_edge(u, v):
            raise ValueError(f"No edge between {u!r} and {v!r}")
        d = graph.edges[u, v]
        out.append({"from": u, "to": v, "type": d.get("type"),
                    "validated": bool(d.get("validated")), "evidence": d.get("evidence", "")})
    return out


def find_exposure_paths(config: dict[str, Any], graph: nx.DiGraph | None = None,
                        max_depth: int = 6) -> dict[str, list[dict[str, Any]]]:
    """Find exposed-entry-to-sensitive-resource paths.

    Returns {"verified": [...], "incomplete": [...]}. Incomplete entries use
    unvalidated edges and are never presented as verified.
    """
    g = graph if graph is not None else build_graph(config)
    sensitive = [r["id"] for r in config.get("resources", []) if r.get("sensitive") is True]
    exposed = [e["id"] for e in config.get("entry_points", []) if e.get("publicly_exposed") is True]
    verified, incomplete = [], []
    for entry in exposed:
        for target in sensitive:
            for path in find_paths(g, entry, target, max_depth, verified_only=True):
                verified.append({"entry_id": entry, "resource_id": target,
                                 "identity_id": _identity_on_path(g, path),
                                 "path": path, "edges": explain_path(g, path)})
            if not any(v["entry_id"] == entry and v["resource_id"] == target for v in verified):
                for path in find_paths(g, entry, target, max_depth, verified_only=False):
                    edges = explain_path(g, path)
                    if all(e["validated"] for e in edges):
                        continue
                    incomplete.append({"entry_id": entry, "resource_id": target,
                                       "identity_id": _identity_on_path(g, path),
                                       "path": path, "edges": edges,
                                       "missing_links": [f"{e['from']} -> {e['to']}" for e in edges
                                                         if not e["validated"]]})
    return {"verified": verified, "incomplete": incomplete}


def _identity_on_path(g: nx.DiGraph, path: list[str]) -> str | None:
    for node in path:
        if g.nodes[node].get("kind") == "identity":
            return node
    return None


def graph_summary(graph: nx.DiGraph) -> dict[str, Any]:
    """Counts of nodes and edges by kind, plus validated versus unvalidated edges."""
    kinds: dict[str, int] = {}
    for _, data in graph.nodes(data=True):
        kinds[data.get("kind", "unknown")] = kinds.get(data.get("kind", "unknown"), 0) + 1
    validated = sum(1 for _, _, d in graph.edges(data=True) if d.get("validated"))
    total = graph.number_of_edges()
    return {"nodes": graph.number_of_nodes(), "edges": total, "node_kinds": kinds,
            "validated_edges": validated, "unvalidated_edges": total - validated}
