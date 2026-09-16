"""
P0-A.2 · Adversarial LIVE probes against the deployed preview backend.

These tests exercise the running platform (not the in-process TestClient) so we
can (a) probe /openapi.json for secret leakage, (b) hit the real admin auth
guard, (c) look for the plaintext prefixes 'enr_', 'eak_', 'est_' escaping into
any non-creation response, and (d) confirm the error-oracle discipline holds
across the real HTTP surface.
"""
from __future__ import annotations
import os
import re
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

TENANT = "default"


# ---------- fixtures ----------
@pytest.fixture(scope="module")
def admin_token() -> str:
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=15)
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text[:200]}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok, r.json()
    return tok


@pytest.fixture(scope="module")
def admin_hdr(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def _mint_token(admin_hdr):
    # The tokens endpoint derives tenant from the authenticated admin; body
    # accepts only optional fields (extra=forbid). Try with an empty body,
    # then fall back to a couple of harmless variants if the schema expects
    # a label or ttl override.
    for body in ({}, {"label": "adv-probe"}):
        r = requests.post(f"{BASE_URL}/api/edr/enrollment/tokens",
                          headers=admin_hdr, json=body, timeout=15)
        if r.status_code in (200, 201):
            return r.json()
    raise AssertionError(f"mint: {r.status_code} {r.text[:300]}")


def _enroll(token_plain, processor_id=None, hostname="LAB-ADV-01"):
    body = {
        "tenant_id": TENANT,
        "enrollment_token": token_plain,
        "hostname": hostname,
        "platform": "linux",
        "processor_id": processor_id or f"CPU-{uuid.uuid4().hex[:12]}",
    }
    return requests.post(f"{BASE_URL}/api/edr/agent/enroll", json=body, timeout=15)


def _session(credential, tenant_id=TENANT):
    return requests.post(f"{BASE_URL}/api/edr/agent/session",
                         json={"tenant_id": tenant_id,
                               "agent_credential": credential}, timeout=15)


# ---------- 1. Admin auth guard ----------
def test_admin_routes_reject_unauthenticated():
    for path in ("/api/edr/enrollment/tokens",
                 "/api/edr/enrollment/endpoints",
                 "/api/edr/enrollment/rejections"):
        r = requests.get(f"{BASE_URL}{path}", timeout=10)
        assert r.status_code in (401, 403), f"{path} exposed to anon: {r.status_code}"


def test_agent_routes_do_NOT_require_platform_user():
    # 401 unauth check would be wrong here: these are agent routes, presented
    # secret IS the auth, so they must return 422/401 for missing body/secret
    # but never 'requires platform login'.
    r = requests.post(f"{BASE_URL}/api/edr/agent/enroll", json={}, timeout=10)
    assert r.status_code in (401, 422), r.status_code
    # If admin-guard bug present, body would say 'not authenticated'
    assert "Not authenticated" not in r.text


# ---------- 2. Error oracle discipline ----------
def test_token_failure_messages_are_identical(admin_hdr):
    tok = _mint_token(admin_hdr)
    plain = tok["enrollment_token"]

    # unknown
    r_unknown = _enroll("enr_" + "0" * 40)
    # malformed
    r_malformed = _enroll("this-is-not-an-enr-token")
    # wrong tenant
    body = {
        "tenant_id": "some-other-tenant",
        "enrollment_token": plain,
        "hostname": "LAB", "platform": "linux",
        "processor_id": f"CPU-{uuid.uuid4().hex[:8]}",
    }
    r_wrong_tenant = requests.post(f"{BASE_URL}/api/edr/agent/enroll", json=body, timeout=10)

    # consume once, then reuse
    ok = _enroll(plain)
    assert ok.status_code in (200, 201), ok.text[:300]
    r_reused = _enroll(plain)

    codes = {r_unknown.status_code, r_malformed.status_code, r_wrong_tenant.status_code, r_reused.status_code}
    assert codes == {401}, f"non-401 leaked: {codes}"

    msgs = [r.json().get("detail") for r in (r_unknown, r_malformed, r_wrong_tenant, r_reused)]
    # normalise detail to string
    norm = []
    for m in msgs:
        if isinstance(m, dict):
            norm.append(m.get("reason") or m.get("code") or str(sorted(m.items())))
        else:
            norm.append(str(m))
    assert len(set(norm)) == 1, f"error-oracle leak: {norm}"


# ---------- 3. Revocation kills in-flight session (live) ----------
def test_revocation_kills_in_flight_session_live(admin_hdr):
    tok = _mint_token(admin_hdr)
    er = _enroll(tok["enrollment_token"], hostname="LAB-REVKILL")
    assert er.status_code in (200, 201), er.text[:300]
    body = er.json()
    endpoint_id = body["endpoint_id"]
    cred = body["agent_credential"]

    sr = _session(cred)
    assert sr.status_code == 200, sr.text[:300]
    session = sr.json()["session_token"]

    hdr = {"Authorization": f"Bearer {session}"}
    r1 = requests.post(f"{BASE_URL}/api/edr/agent/telemetry", headers=hdr,
                       json={"payload": "adv-probe-1"}, timeout=10)
    assert r1.status_code == 200, r1.text[:200]

    # revoke
    rv = requests.post(f"{BASE_URL}/api/edr/enrollment/endpoints/{endpoint_id}/revoke",
                       headers=admin_hdr, json={"reason": "adversarial-test"}, timeout=10)
    assert rv.status_code in (200, 204), rv.text[:200]

    # SAME session token, still inside TTL, MUST fail
    r2 = requests.post(f"{BASE_URL}/api/edr/agent/telemetry", headers=hdr,
                       json={"payload": "adv-probe-2"}, timeout=10)
    assert r2.status_code in (401, 403), f"in-flight session survived revoke: {r2.status_code}"

    # cred cannot open a new session
    r3 = _session(cred)
    assert r3.status_code in (401, 403), r3.status_code


# ---------- 4. OpenAPI + admin GETs must not leak plaintext ----------
# Real secrets are secrets.token_urlsafe(32) → ~43 base64url chars containing
# a mix of upper/lower case + digits. Test-corpus identifiers like
# `est_xdr_round28x2_mde_s1` (lowercase + digits + underscores, ≤ 30 chars)
# are NOT real secrets. Require length ≥ 40 AND at least one uppercase letter.
_SECRET_TAIL = re.compile(r"(enr|eak|est)_([A-Za-z0-9_\-]{40,})")


def _is_real_secret(m: "re.Match[str]") -> bool:
    tail = m.group(2)
    return bool(re.search(r"[A-Z]", tail))


def _scan_for_secrets(text: str):
    return [m.group(0) for m in _SECRET_TAIL.finditer(text) if _is_real_secret(m)]


SECRET_RE = _SECRET_TAIL  # kept for backwards-compat name in tests below


def test_openapi_has_no_plaintext_secret():
    r = requests.get(f"{BASE_URL}/openapi.json", timeout=15)
    assert r.status_code == 200
    hits = _scan_for_secrets(r.text)
    assert not hits, f"OpenAPI leaks a real secret-shaped value: {hits[:3]}"


def test_admin_list_endpoints_has_no_plaintext_or_hash(admin_hdr):
    for path in ("/api/edr/enrollment/tokens",
                 "/api/edr/enrollment/endpoints",
                 "/api/edr/enrollment/rejections"):
        r = requests.get(f"{BASE_URL}{path}", headers=admin_hdr, timeout=15)
        assert r.status_code == 200, f"{path}: {r.status_code}"
        text = r.text
        hits = _scan_for_secrets(text)
        assert not hits, f"{path} leaks plaintext secret: {hits[:3]}"
        if path.endswith("/tokens"):
            assert "token_hash" not in text, "token_hash exposed in admin list"


# ---------- 5. 401 detail body must show only a redacted form ----------
def test_bearer_401_body_shows_redacted_fingerprint_not_secret():
    fake = "est_" + "z" * 40
    r = requests.post(f"{BASE_URL}/api/edr/agent/telemetry",
                      headers={"Authorization": f"Bearer {fake}"},
                      json={"payload": "probe"},
                      timeout=10)
    assert r.status_code in (401, 403), r.status_code
    body = r.text
    # secret prefix + tail must not appear verbatim
    assert fake not in body, "raw secret echoed in 401 body"


# ---------- 6. Envelope rejects tenant_id / endpoint_id ----------
def test_telemetry_envelope_rejects_tenant_and_endpoint_fields(admin_hdr):
    tok = _mint_token(admin_hdr)
    er = _enroll(tok["enrollment_token"], hostname="LAB-ENV")
    body = er.json()
    sr = _session(body["agent_credential"])
    session = sr.json()["session_token"]
    hdr = {"Authorization": f"Bearer {session}"}
    for bad in [{"tenant_id": "attacker"}, {"endpoint_id": "ep_attacker"}]:
        payload = {"payload": "envelope-probe", **bad}
        r = requests.post(f"{BASE_URL}/api/edr/agent/telemetry", headers=hdr,
                          json=payload, timeout=10)
        assert r.status_code == 422, f"envelope accepted {bad}: {r.status_code} {r.text[:200]}"


# ---------- 7. Backend log must not contain plaintext secrets ----------
def test_backend_log_has_no_plaintext_secret_material():
    """Grep supervisor logs. Only fail on secret-shaped tails, not the prefix alone."""
    import glob, os as _os
    hits = []
    for lp in glob.glob("/var/log/supervisor/backend.*.log"):
        try:
            with open(lp, "r", errors="ignore") as fh:
                for i, line in enumerate(fh):
                    for m in _SECRET_TAIL.finditer(line):
                        if _is_real_secret(m):
                            hits.append((lp, i, m.group(0)))
                            break
                    if len(hits) > 10:
                        break
        except FileNotFoundError:
            continue
    assert not hits, f"plaintext secret leaked into backend log: {hits[:5]}"
