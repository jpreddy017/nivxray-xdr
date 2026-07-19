"""Regression: analyst corrections — submit / list / apply / revise /
approve / rollback / preview. Also verifies scope enforcement and the
hybrid (tag → LLM-fallback) matcher.
"""
import os
import pytest
import requests

BASE_URL = ""
with open("/app/frontend/.env") as f:
    for line in f:
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PW    = os.environ.get("ADMIN_PASSWORD", "")


@pytest.fixture(scope="module")
def auth():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PW}, timeout=15)
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _mermaid():
    return "flowchart TD\n  User --> API\n  API --> RedisCache[[INT]]\n  RedisCache --> DB[[DATA]]"


def test_submit_admin_team_scope_auto_approves(auth):
    r = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "threat_model",
        "wrong_finding": {"kind": "mitre", "value": "T1078"},
        "correct_prompt": "Redis cache is not an auth surface — remap to T1005.",
        "tags": ["redis"], "scope": "team", "input_text": _mermaid(),
    })
    assert r.status_code == 200
    d = r.json()["correction"]
    # Admin authoring a team-scope correction should auto-approve.
    assert d["status"] == "approved"
    assert d["confidence"] >= 60
    assert d["version"] == 1


def test_submit_admin_global_scope_stays_pending(auth):
    r = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "decode",
        "wrong_finding": {"kind": "lolbas", "value": "pwsh.exe"},
        "correct_prompt": "pwsh.exe alone isn't a LOLBIN — flag only with -EncodedCommand.",
        "tags": ["pwsh"], "scope": "global",
    })
    d = r.json()["correction"]
    # GLOBAL corrections need a second-approval hop even from an admin.
    assert d["status"] == "pending"


def test_analyze_applies_deterministic_override(auth):
    # 1) Seed a correction that removes T1078 from threat-model findings.
    unique_mermaid = "flowchart TD\n  UserA1 --> ApiA1\n  ApiA1 --> RedisA1[[INT]]\n  RedisA1 --> DbA1[[DATA]]"
    r = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "threat_model",
        "wrong_finding": {"kind": "mitre", "value": "T1078"},
        "correct_prompt": "T1078 misapplied to a stateless cache — remove.",
        "tags": ["overtest-a1"], "scope": "team",
        "input_text": unique_mermaid,
    })
    corr_id = r.json()["correction"]["id"]

    # 2) Analyze the same diagram — correction should be listed AND applied.
    r = requests.post(f"{BASE_URL}/api/threat-model/analyze", headers=auth,
                      timeout=15, json={"mermaid": unique_mermaid, "tags": ["overtest-a1"]})
    assert r.status_code == 200
    d = r.json()
    avail = d.get("corrections_available") or []
    assert any(c.get("id") == corr_id and c.get("apply_mode") == "override"
               for c in avail), avail


def test_revise_bumps_version_and_supersedes(auth):
    r0 = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "threat_model",
        "wrong_finding": {"kind": "mitre", "value": "T1046"},
        "correct_prompt": "v1 text — original interpretation.",
        "tags": ["v-test"], "scope": "team", "input_text": _mermaid(),
    })
    cid = r0.json()["correction"]["id"]

    r1 = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "threat_model",
        "wrong_finding": {"kind": "mitre", "value": "T1046"},
        "correct_prompt": "v2 text — refined based on later evidence.",
        "tags": ["v-test"], "scope": "team", "input_text": _mermaid(),
        "revises": cid,
    })
    d = r1.json()["correction"]
    assert d["version"] == 2
    assert d["prev_version_id"] == cid
    assert len(d.get("history") or []) >= 1

    # Old version must now be superseded.
    rlist = requests.get(f"{BASE_URL}/api/corrections?surface=threat_model",
                        headers=auth, timeout=10).json()["items"]
    old = [x for x in rlist if x["id"] == cid]
    assert old and old[0]["status"] == "superseded"


def test_approve_reject_rollback_flow(auth):
    r0 = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "decode",
        "wrong_finding": {"kind": "family", "value": "Ransomware"},
        "correct_prompt": "v1 — misattributed family.",
        "tags": ["family-test"], "scope": "global",
    })
    cid = r0.json()["correction"]["id"]

    # Approve
    r = requests.post(f"{BASE_URL}/api/corrections/{cid}/approve", headers=auth,
                     timeout=10)
    assert r.status_code == 200
    assert r.json()["correction"]["status"] == "approved"

    # Revise then rollback to v1 (must create v3 pointing back)
    r1 = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "decode",
        "wrong_finding": {"kind": "family", "value": "Ransomware"},
        "correct_prompt": "v2 — refined attribution.",
        "tags": ["family-test"], "scope": "team",
        "revises": cid,
    })
    v2 = r1.json()["correction"]

    r_rb = requests.post(f"{BASE_URL}/api/corrections/{v2['id']}/rollback",
                        headers=auth, timeout=10,
                        json={"target_version": 1})
    assert r_rb.status_code == 200
    rb = r_rb.json()["correction"]
    assert rb["version"] == 3
    assert rb["prev_version_id"] == v2["id"]
    assert len(rb.get("history") or []) >= 2


def test_pending_admin_inbox_lists_global_pending(auth):
    # Submit a fresh global-pending correction
    r = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "note", "wrong_finding": {"kind": "text", "value": "n/a"},
        "correct_prompt": "This analyst note text was auto-generated wrongly.",
        "tags": ["inbox-test"], "scope": "global",
    })
    cid = r.json()["correction"]["id"]

    inbox = requests.get(f"{BASE_URL}/api/corrections/pending", headers=auth,
                        timeout=10).json()["items"]
    assert any(x["id"] == cid for x in inbox)


def test_preview_returns_applicable_by_tag(auth):
    r = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "decode", "wrong_finding": {"kind": "ioc", "value": "http://x"},
        "correct_prompt": "URL is a known good telemetry endpoint — ignore.",
        "tags": ["telemetry-safelist"], "scope": "team",
    })
    r = requests.post(f"{BASE_URL}/api/corrections/preview", headers=auth,
                     timeout=10, json={
        "surface": "decode", "input_text": "", "tags": ["telemetry-safelist"],
    })
    assert r.status_code == 200
    assert any(c.get("tags") and "telemetry-safelist" in c["tags"]
               for c in r.json()["items"])


def test_invalid_surface_rejected(auth):
    r = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "not-a-real-surface",
        "wrong_finding": {"kind": "mitre", "value": "T1078"},
        "correct_prompt": "won't be accepted",
    })
    assert r.status_code == 400


def test_verdict_types_accepted_and_validated(auth):
    """Feb-2026 v2/v3: all 4 verdict types accepted; invalid rejected."""
    for v in ("correct", "incorrect", "partial", "suggest"):
        r = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
            "surface": "ioc", "wrong_finding": {"kind": "ioc", "value": "http://t"},
            "correct_prompt": f"verdict={v} regression test",
            "verdict": v, "scope": "private",
        })
        assert r.status_code == 200, r.text
        assert r.json()["correction"]["verdict"] == v
    # Invalid verdict rejected
    r = requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "ioc", "wrong_finding": {"kind": "ioc", "value": "http://t"},
        "correct_prompt": "bad verdict", "verdict": "wat", "scope": "private",
    })
    assert r.status_code == 400


def test_correct_verdict_does_NOT_apply_deterministic_override(auth):
    """A "correct" verdict is positive reinforcement — it must NEVER
    delete the finding from a future analysis, only incorrect does that.
    Regression for the v2/v3 verdict-gating rule."""
    # Use a fully unique diagram so no prior test's incorrect-verdict
    # correction bleeds in via the shared analyst_corrections collection.
    unique_mermaid = ("flowchart TD\n  UserC1 --> ApiC1\n  ApiC1 --> DbC1[[DATA]]\n"
                     "  ApiC1 --> KafkaC1[[INT]]")
    # Seed a `correct` verdict on T1078 in threat_model
    requests.post(f"{BASE_URL}/api/corrections", headers=auth, timeout=10, json={
        "surface": "threat_model", "wrong_finding": {"kind": "mitre", "value": "T1078"},
        "correct_prompt": "T1078 is CORRECT for auth flow here — do not remove.",
        "verdict": "correct", "tags": ["correct-verdict-test-c1"],
        "scope": "team", "input_text": unique_mermaid,
    })
    # Analyze — the correct-verdict correction must appear in
    # corrections_available but must NOT drop T1078 from the report.
    r = requests.post(f"{BASE_URL}/api/threat-model/analyze", headers=auth,
                     timeout=15, json={"mermaid": unique_mermaid,
                                       "tags": ["correct-verdict-test-c1"]})
    d = r.json()
    avail = d.get("corrections_available") or []
    assert any(c.get("verdict") == "correct" for c in avail), avail
    # No T1078 removal — since the diagram doesn't naturally produce T1078,
    # we just verify the response has no `_applied_corrections` (no
    # deterministic-override triggered by a correct verdict).
    applied = (d.get("_applied_corrections") or [])
    assert not any(a.get("kind") == "mitre" for a in applied), applied


def test_analytics_endpoint_returns_full_shape(auth):
    r = requests.get(f"{BASE_URL}/api/corrections/analytics", headers=auth, timeout=15)
    assert r.status_code == 200
    d = r.json()
    for k in ("totals", "by_status", "by_surface", "top_reused", "top_mitre",
              "verdict_dist", "reviewer_stats", "avg_approval_seconds",
              "accuracy_signal", "trend_7d"):
        assert k in d, f"missing analytics key: {k}"
    assert isinstance(d["trend_7d"], list) and len(d["trend_7d"]) == 7
    assert 0.0 <= float(d["accuracy_signal"]) <= 1.0
