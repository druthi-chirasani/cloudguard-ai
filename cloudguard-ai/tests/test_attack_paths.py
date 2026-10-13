import copy

import pytest

from cloudguard.attack_paths import build_graph, explain_path, find_exposure_paths, find_paths, graph_summary
from cloudguard.parser import validate_config


def _graph(raw):
    return build_graph(validate_config(raw)["config"])


def test_valid_identity_path_is_found(config):
    g = _graph(config)
    paths = find_paths(g, "public-web-app", "bucket-customer-data", max_depth=6)
    assert ["public-web-app", "app-service-role", "bucket-customer-data"] in paths


def test_path_not_invented_when_relationship_missing(config):
    bad = copy.deepcopy(config)
    for rel in bad["relationships"]:
        rel["validated"] = False
    result = find_exposure_paths(validate_config(bad)["config"])
    assert result["verified"] == []
    assert result["incomplete"], "unvalidated path should be reported as incomplete"
    assert result["incomplete"][0]["missing_links"]


def test_no_path_between_unlinked_nodes(config):
    g = _graph(config)
    assert find_paths(g, "internal-batch-job", "bucket-customer-data") == []


def test_unknown_node_raises_value_error(config):
    with pytest.raises(ValueError):
        find_paths(_graph(config), "public-web-app", "does-not-exist")


def test_cycles_do_not_hang(config):
    bad = copy.deepcopy(config)
    bad["relationships"].append({"source": "bucket-customer-data", "target": "app-service-role",
                                 "validated": True, "evidence": "synthetic cycle"})
    paths = find_paths(_graph(bad), "public-web-app", "bucket-customer-data", max_depth=10)
    assert paths and all(len(p) == len(set(p)) for p in paths)


def test_max_depth_is_respected(config):
    g = _graph(config)
    assert find_paths(g, "public-web-app", "bucket-customer-data", max_depth=1) == []


def test_explain_path_shows_edge_evidence(config):
    g = _graph(config)
    edges = explain_path(g, ["public-web-app", "app-service-role", "bucket-customer-data"])
    assert all(e["validated"] for e in edges)
    assert edges[1]["evidence"] == "Synthetic verified policy relationship"


def test_graph_summary_counts(config):
    s = graph_summary(_graph(config))
    assert s["nodes"] == 8  # 3 resources, 3 identities, 2 entry points
    assert s["validated_edges"] >= 2
