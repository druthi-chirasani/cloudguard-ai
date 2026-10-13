# CloudGuard AI team plan (four members)

## Agreed function signatures and data contracts

| Module | Signature | Contract |
|---|---|---|
| `parser.py` | `validate_config(data) -> {config, errors, warnings, limitations}` | `config` is None when `errors` is non-empty |
| `parser.py` | `validate_audit_logs(data, config_ids=None) -> {events, errors, warnings}` | Missing fields are None, never invented |
| `detector.py` | `run_config_detection(config) -> list[finding]` | Deduplicated by stable ID |
| `audit.py` | `analyze_audit_events(events, config) -> list[finding]` | `source="audit"` |
| `risk_scoring.py` | `score_findings(findings, weights=None) -> list[finding]` | Adds `score`, `severity`, `confidence`, `score_breakdown` |
| `attack_paths.py` | `build_graph`, `find_paths`, `explain_path`, `find_exposure_paths`, `graph_summary` | Edges only from explicit input |
| `risk_story.py` | `build_risk_story(config, paths, findings) -> dict` | Verified and incomplete stories |
| `remediation.py` | `propose_remediation(config, finding)`, `apply_patch(config, proposal)` | `apply_patch` never mutates its input |
| `scanner.py` | `run_scan(config_input, audit_logs=None, ...) -> dict`, `simulate_remediation(...)` | UI consumes these only |

A finding is a dict with: `id`, `rule_id`, `title`, `category`, `severity`, `score`, `status`, `confidence`, `resource_id`, `identity_id`, `evidence`, `why_it_matters`, `potential_impact`, `limitations`, `recommended_action`, `remediation_available`, `source`, `factors`, `score_breakdown`.

## Member roles

**Member 1: parser and detection.** Owns `parser.py`, `detector.py`, `data/sample_config.json`, `tests/test_parser.py`, `tests/test_detector.py`.

**Member 2: audit and graph.** Owns `audit.py`, `attack_paths.py`, `risk_story.py`, `data/sample_audit_logs.json`, `tests/test_audit.py`, `tests/test_attack_paths.py`.

**Member 3: risk, explanations and remediation.** Owns `risk_scoring.py`, `explanations.py`, `remediation.py`, `data/security_knowledge.json`, `tests/test_risk_scoring.py`, `tests/test_remediation.py`.

**Member 4: dashboard and integration.** Owns `app.py`, `scanner.py`, `exports.py`, `tests/test_scanner.py`, `scripts/smoke_test.py`, README, presentation and demo.

For a three-person team, combine Members 2 and 3, or give Member 1's parser work to Member 2. One person owns final integration.

## Integration order

1. Member 1 lands `models.py` and `parser.py` with tests.
2. Member 1 lands `detector.py` against the sample config.
3. Member 2 lands `attack_paths.py`, then `audit.py`, then `risk_story.py`.
4. Member 3 lands `risk_scoring.py`, then `remediation.py`, then `explanations.py`.
5. Member 4 lands `scanner.py`, then `app.py`, then runs `python -m pytest -q` and `python scripts/smoke_test.py`.

## Merge checklist

- [ ] `python -m pytest -q` passes on the branch
- [ ] `python scripts/smoke_test.py` passes
- [ ] No module imports the UI or Streamlit
- [ ] No new dependency added without an update to `requirements.txt`
- [ ] Sample data remains fictional
- [ ] Finding IDs are unchanged for existing rules
- [ ] Documentation matches behaviour
