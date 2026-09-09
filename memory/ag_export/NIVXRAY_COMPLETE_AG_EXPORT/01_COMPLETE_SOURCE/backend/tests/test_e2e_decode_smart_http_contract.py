"""End-to-end · decode/smart HTTP contract locked against BOTH decode
classes (complete-decodes vs graceful-stop-on-corrupt).

Runtime note
============
Each POST /api/decode/smart in this file exercises the FULL pipeline
(IU → CRE → RTE → Intent → Verdict → Graph → Report) including any
OSINT/LLM enrichment layers, so per-call wall-time is ~30-60 seconds.
Response fixtures are module-scoped so the endpoint is hit AT MOST
four times per full run of this file (once per unique input × recipe).
Full-suite wall-time is ~3-4 minutes — mark with `-m e2e` to opt-in
on CI stages that can afford it.

Why this test file exists
=========================
Previous v1.5.x cycles kept adding unit tests that PASSED while the
deployed workspace still surfaced bugs. The gap was structural: no
test ever exercised the full HTTP path from `POST /api/decode/smart`
through the routers/ops.py output-promotion block to the JSON keys
the frontend reads.

This test closes that gap. It:

    1. Hits the actual FastAPI application via ``TestClient`` (no
       supervisor, no external network — but the SAME code path,
       middleware, and response mapping).
    2. Uses the SAME two canonical samples in ``trust_corpus``.
    3. Locks the FOUR diagnostic questions posed by the SME as
       independent regression assertions:

           Q1  artifacts[] contained decoded PowerShell
           Q2  API `output` field carried decoded PowerShell
           Q3  UI payload contained the RTE brain-block header
           Q4  Stop reason + root diagnostic matched expectations

Sample A · byte-exact reflective loader   → all 4 answers YES
Sample B · corpus corrupt (mod-4 = 3)     → Q1/Q2/Q3 YES for L1 partial
                                             recovery; Q4 documents
                                             DX1001 root cause.

Neither sample is allowed to cross-contaminate. A future change that
breaks either class fails CI at the file that promises it works.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# Module-level timeout — the module-scoped `client` fixture pays a
# one-time ~120s LLM-warmup cost on the FIRST test that requests it
# (litellm import chain fires on server startup). Subsequent tests
# reuse the cached fixture so they need only ~30-60s each. We set the
# per-test budget to 360s so the first test doesn't timeout on the
# amortized startup + one decode call while every other test still
# has plenty of headroom. Feb-2026 · v1.5.5 · SME release-gate.
pytestmark = pytest.mark.timeout(360)


# ── Bootstrapping ──────────────────────────────────────────────

@pytest.fixture(scope="module")
def client() -> TestClient:
    """The same FastAPI app the workspace hits — TestClient exercised
    within a context manager so the ``@app.on_event('startup')`` hooks
    (which bind ``deps.db`` and seed the admin) actually fire. Without
    the context manager TestClient skips lifespan events and login
    fails with 500 ``deps.db accessed before init_database()``."""
    from server import app  # noqa: WPS433 — deliberately late-imported
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers(client: TestClient) -> dict:
    """Log in with the seeded admin so we hit the SAME auth path the
    UI hits. Password comes from `memory/test_credentials.md` (source
    of truth) so a future rotation only needs to update ONE file.

    v1.5.5 · Feb-2026 — we UPSERT the admin bcrypt hash directly
    against the test-time DB *before* login instead of calling
    `seed_admin()` (which is an async coroutine and also idempotent,
    i.e. it will NOT rewrite the password if the admin already
    exists with a stale hash from a previous rotation/test). This
    guarantees the login POST matches the password we're about to
    submit — regardless of any state left behind by earlier tests
    that rotated the admin password.

    We use a *synchronous* pymongo connection (NOT the async motor
    handle bound to the server's event loop) so this fixture can be
    called from pytest's synchronous fixture stack without hitting
    the classic ``RuntimeError: got Future … attached to a different
    loop`` failure motor raises when its coroutine is scheduled on a
    fresh loop."""
    from pymongo import MongoClient
    from deps import hash_password

    email = os.environ.get("ADMIN_EMAIL", "admin@nivxray.com")
    password = os.environ.get("ADMIN_PASSWORD") or _read_seeded_password()

    # Force-align the DB admin row with the password we're about to
    # POST — idempotent, synchronous, no async-loop crossover.
    mongo_url = os.environ["MONGO_URL"]
    db_name = os.environ["DB_NAME"]
    sync_client = MongoClient(mongo_url)
    try:
        sync_client[db_name].users.update_one(
            {"email": email},
            {"$set": {
                "email": email,
                "password": hash_password(password),
                "role": "admin",
                "must_change_password": False,
            }},
            upsert=True,
        )
    finally:
        sync_client.close()

    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, (
        f"admin login failed ({r.status_code}): {r.text[:200]}"
    )
    tok = r.json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


def _read_seeded_password() -> str:
    """Read the current admin password from memory/test_credentials.md
    without hard-coding it in this test."""
    cred = Path("/app/memory/test_credentials.md")
    if not cred.exists():
        return ""
    for line in cred.read_text().splitlines():
        low = line.lower().strip()
        if low.startswith("- **password**:") or low.startswith("- password:"):
            _, _, val = line.partition(":")
            val = val.strip()
            if "`" in val:
                return val.split("`")[1]
            return val.split()[0] if val else val
    return ""


# ── Sample loaders ─────────────────────────────────────────────

_CORPUS_DIR = Path(__file__).with_name("trust_corpus")


def _read_sample(name: str) -> str:
    p = _CORPUS_DIR / name
    return p.read_text(encoding="utf-8").rstrip("\n")


@pytest.fixture(scope="module")
def sample_complete() -> str:
    """Sample A — byte-exact reflective PS shellcode loader.
    Trust corpus entry PS_ENCODEDCOMMAND_GZIP_REFLECTIVE_LOADER_002.
    Full 3-layer decode (L0 → L1 → L2 reflective loader)."""
    import yaml
    spec = yaml.safe_load(
        (_CORPUS_DIR / "PS_ENCODEDCOMMAND_GZIP_REFLECTIVE_LOADER_002.yaml")
        .read_text(encoding="utf-8"))
    return spec["input"].strip()


@pytest.fixture(scope="module")
def sample_corrupt() -> str:
    """Sample B — canonical corrupt-inner-base64 (mod 4 = 3).
    Trust corpus entry PS_ENCODEDCOMMAND_GZIP_STAGE2_001.txt.
    Stops at L1 with DX1001 root cause — deterministic honest stop."""
    return _read_sample("PS_ENCODEDCOMMAND_GZIP_STAGE2_001.txt")


# ── Response caches ─── module-scoped fixtures hit the endpoint
# ── exactly ONCE per sample; every test asserts against the cached
# ── JSON. Keeps CI wall-time bounded even when the pipeline includes
# ── OSINT/LLM enrichment paths.

@pytest.fixture(scope="module")
def resp_complete(client, auth_headers, sample_complete) -> dict:
    r = client.post("/api/decode/smart",
                    json={"input": sample_complete},
                    headers=auth_headers)
    assert r.status_code == 200, r.text[:200]
    return r.json()


@pytest.fixture(scope="module")
def resp_complete_repeat(client, auth_headers, sample_complete) -> dict:
    """Second identical POST — used only by the determinism test."""
    r = client.post("/api/decode/smart",
                    json={"input": sample_complete},
                    headers=auth_headers)
    assert r.status_code == 200, r.text[:200]
    return r.json()


@pytest.fixture(scope="module")
def resp_corrupt(client, auth_headers, sample_corrupt) -> dict:
    r = client.post("/api/decode/smart",
                    json={"input": sample_corrupt},
                    headers=auth_headers)
    assert r.status_code == 200, r.text[:200]
    return r.json()


@pytest.fixture(scope="module")
def resp_recipe_replay(client, auth_headers, sample_complete) -> dict:
    r = client.post("/api/recipe/run",
                    json={"input": sample_complete,
                          "steps": [{"op": "ps-encodedcommand-recovery", "args": {}}]},
                    headers=auth_headers)
    assert r.status_code == 200, r.text[:200]
    return r.json()


# ══════════════════════════════════════════════════════════════════
# Sample A · complete input · MUST decode to L2 · MUST verdict Malicious
# ══════════════════════════════════════════════════════════════════

def test_complete_sample_Q1_artifacts_contain_decoded_powershell(resp_complete):
    """Q1 · The RTE artifacts[] array MUST contain the recovered PS at L1
    and the reflective-shellcode plaintext at L2 for a byte-exact input."""
    data = resp_complete
    rte = (data.get("investigation") or {}).get("rte") or {}
    arts = rte.get("artifacts") or []
    assert len(arts) >= 3, (
        f"Q1 FAIL · expected ≥ 3 layers on the complete sample, got {len(arts)}. "
        f"stop_reason={rte.get('stop_reason')}"
    )
    l1 = arts[1].get("content") or ""
    l2 = arts[2].get("content") or ""
    assert "$s=New-Object IO.MemoryStream" in l1
    assert "GetDelegateForFunctionPointer" in l2, (
        "Q1 FAIL · L2 did not contain the reflective delegate-invoke "
        "primitive; the gzip layer either did not run or produced the "
        "wrong artefact."
    )


def test_complete_sample_Q2_api_output_field_carries_decoded_powershell(resp_complete):
    """Q2 · The top-level ``output`` field the frontend reads MUST carry
    the RTE decoder trace + recovered L2 payload (v1.5.1 promotion)."""
    data = resp_complete
    out = data.get("output") or ""
    assert "INVESTIGATION BRAIN · RTE DECODER TRACE" in out, (
        "Q2 FAIL · `output` does not carry the v1.5.1 promotion header. "
        "Either the promotion block in routers/ops.py did not fire or "
        "the endpoint has fallen back to the legacy orchestrator text."
    )
    assert "RECOVERED PAYLOAD" in out
    assert "ps_encoded_command" in out
    assert "ps_indirect_compression_stream" in out
    # Legacy is preserved for any UI still keyed off the old shape.
    assert "output_legacy" in data


def test_complete_sample_Q3_ui_payload_contains_final_l2_content(resp_complete):
    """Q3 · The UI payload MUST include the L2 recovered content — the
    workspace's Output panel reads this. Missing it is a frontend-mapping
    bug even if the artefact exists in `investigation.rte.artifacts`."""
    out = resp_complete.get("output") or ""
    # A textbook reflective loader emits these tokens. If they don't
    # reach the UI payload, the promotion block dropped the L2 layer.
    assert "func_get_proc_address" in out or "VirtualAlloc" in out, (
        "Q3 FAIL · UI payload does not carry the L2 recovered content."
    )


def test_complete_sample_Q4_stop_reason_is_deterministic_convergence(resp_complete):
    """Q4 · For a byte-exact input the RTE MUST converge cleanly at L2
    with DX2002 as ROOT (INFO) — no error-level diagnostic upstream."""
    rte = (resp_complete.get("investigation") or {}).get("rte") or {}
    assert rte.get("stop_reason") == "no_transformation"
    diags = rte.get("diagnostics") or []
    root = next((d for d in diags if not d.get("caused_by")), None)
    assert root is not None
    assert root.get("code") == "DX2002"
    assert (root.get("severity") or "").lower() == "info"


def test_complete_sample_verdict_is_malicious(resp_complete):
    """The Investigation Brain MUST classify the reflective loader as
    MALICIOUS. Anything else is the v1.5.2 defect returning."""
    v = (resp_complete.get("investigation") or {}).get("verdict") or {}
    assert v.get("band") == "malicious", (
        f"Brain returned band={v.get('band')!r} · confidence={v.get('confidence')} · "
        f"reason={v.get('reason')!r}"
    )


def test_complete_sample_recipe_replay_of_ps_encodedcommand_recovery_no_errors(resp_recipe_replay):
    """v1.5.2 fix · the recipe UI's `Run Recipe` action must NOT emit
    a red `Unknown operation: ps-encodedcommand-recovery` badge."""
    body = resp_recipe_replay
    assert body.get("errors") == [], f"recipe errors: {body.get('errors')}"
    step = (body.get("steps_output") or [{}])[0]
    assert (step.get("output_length") or 0) > 500, (
        f"recipe replay produced too-short output ({step.get('output_length')} bytes)"
    )


# ══════════════════════════════════════════════════════════════════
# Sample B · corrupt inner base64 · MUST stop gracefully with DX1001
# ══════════════════════════════════════════════════════════════════

def test_corrupt_sample_stops_at_L1_with_dx1001_root_cause(resp_corrupt):
    """The corpus sample has an inner base64 length of 2635 chars
    (mod 4 = 3). The engine MUST detect this and stop at L1 — never
    fabricate an L2 payload."""
    rte = (resp_corrupt.get("investigation") or {}).get("rte") or {}
    arts = rte.get("artifacts") or []
    diags = rte.get("diagnostics") or []
    assert len(arts) == 2, f"expected exactly 2 layers, got {len(arts)}"
    codes = {d.get("code") for d in diags}
    assert "DX1001" in codes, "corrupt inner base64 must produce DX1001"
    assert "DX2002" in codes, "convergence marker DX2002 must still be emitted"
    # Causal linkage — DX1001 root, DX2002 caused_by DX1001.
    dx1001 = next(d for d in diags if d.get("code") == "DX1001")
    dx2002 = next(d for d in diags if d.get("code") == "DX2002")
    assert not dx1001.get("caused_by"), "DX1001 must be a root diagnostic"
    assert dx2002.get("caused_by") == "DX1001", (
        f"DX2002 must be caused_by=DX1001, got {dx2002.get('caused_by')!r}"
    )


def test_corrupt_sample_output_never_fabricates_L2(resp_corrupt):
    """Analyst-safety net · the promoted `output` MUST surface the
    diagnostic and the L1 partial recovery — but MUST NOT invent an
    L2 payload from the malformed inner base64."""
    out = resp_corrupt.get("output") or ""
    assert "DX1001" in out, "DX1001 must appear in analyst-facing output"
    assert "$s=New-Object IO.MemoryStream" in out, (
        "L1 partial recovery must be surfaced to the analyst even on stop."
    )


def test_both_samples_are_byte_exact_same_length(sample_complete, sample_corrupt):
    """Sanity check · both canonical samples happen to be 7,624 chars.
    If a future PR changes their length, the corpus contract has
    silently drifted — that is exactly the kind of regression the trust
    harness was designed to catch."""
    assert len(sample_complete) == 7624
    assert len(sample_corrupt)  == 7624
    # But their bytes DIFFER — that's the entire point of running both.
    assert sample_complete != sample_corrupt


# ══════════════════════════════════════════════════════════════════
# Determinism · every stage must be reproducible byte-for-byte
# ══════════════════════════════════════════════════════════════════

def test_repeated_decode_is_deterministic(resp_complete, resp_complete_repeat):
    """Two identical POSTs must produce identical `investigation.determinism_hash`
    and byte-identical `output` fields."""
    d1 = ((resp_complete.get("investigation") or {}).get("rte") or {}).get("determinism_hash")
    d2 = ((resp_complete_repeat.get("investigation") or {}).get("rte") or {}).get("determinism_hash")
    assert d1 and d1 == d2, f"RTE determinism_hash drifted: {d1!r} vs {d2!r}"
    assert resp_complete.get("output") == resp_complete_repeat.get("output"), (
        "output field drifted between runs"
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
