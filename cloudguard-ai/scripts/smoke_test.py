"""End-to-end smoke test: scanner on demo data, then the real Streamlit app via AppTest.

Run with:  python scripts/smoke_test.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from streamlit.testing.v1 import AppTest  # noqa: E402

from cloudguard.scanner import run_scan, simulate_remediation  # noqa: E402


def scanner_check() -> None:
    cfg = json.loads((ROOT / "data" / "sample_config.json").read_text(encoding="utf-8"))
    aud = json.loads((ROOT / "data" / "sample_audit_logs.json").read_text(encoding="utf-8"))
    result = run_scan(cfg, aud)
    assert result["status"] == "OK", result["validation"]
    assert result["decision"] == "STOP"
    assert result["risk_story"]["overall_status"] == "VERIFIED CONFIGURATION PATH"
    sim = simulate_remediation(cfg, "PUBLIC_SENSITIVE_RESOURCE:-:bucket-customer-data", aud)
    assert sim["original_unchanged"] is True
    print(f"[scanner] status={result['status']} decision={result['decision']} counts={result['counts']}")
    print(f"[scanner] simulation disappeared={sim['comparison']['disappeared']}")


def app_check() -> None:
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    assert not at.exception, [e.value for e in at.exception]
    at.sidebar.button[0].click().run()  # Load Demo Dataset
    assert not at.exception, [e.value for e in at.exception]
    run_btn = next(b for b in at.sidebar.button if b.label == "Run Scan")
    run_btn.click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert len(at.tabs) == 7, "expected 7 dashboard tabs"
    metric_labels = [m.label for m in at.metric]
    assert "Advisory decision" in metric_labels
    print(f"[app] tabs={[t.label for t in at.tabs]}")
    print(f"[app] metrics={[(m.label, m.value) for m in at.metric][:6]}")
    # Remediation: select the public-sensitive-resource finding and preview the simulation.
    at.selectbox(key="rem_pick").select("PUBLIC_SENSITIVE_RESOURCE:-:bucket-customer-data").run()
    preview = next(b for b in at.button if b.label == "Preview Remediation")
    preview.click().run()
    assert not at.exception, [e.value for e in at.exception]
    sim_state = at.session_state["sim"]
    assert sim_state["status"] == "SIMULATED", sim_state
    assert "PUBLIC_SENSITIVE_RESOURCE:-:bucket-customer-data" in sim_state["comparison"]["disappeared"]
    assert sim_state["original_unchanged"] is True
    print("[app] Preview Remediation executed the real simulation.")
    print("[app] Streamlit app ran end to end with no exceptions.")


if __name__ == "__main__":
    scanner_check()
    app_check()
    print("SMOKE TEST PASSED")
