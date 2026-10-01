"""LIVE (preview-URL) tests for NivXRay XDR Intelligence Controls.

Modules covered
  · /api/intelligence/policy/global            (GET/PUT + defaults)
  · /api/intelligence/policy/incident/{id}     (GET/PUT/DELETE + effective)
  · /api/intelligence/policy/{scope}/{id}/history   (append-only audit)
  · /api/intelligence/health                   (honest health readouts)
  · /api/narration/incident/{id}/executive-summary  (policy enforcement)
  · RBAC 403 once a tenant has provisioned xdr_users

All tests live in ONE class so pytest-xdist `--dist loadscope` keeps them
on a single worker (shared preview backend, sequential shared state).
"""
from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

import pytest
import requests
from dotenv import dotenv_values

frontend_env = dotenv_values("/app/frontend/.env")
base_url = (os.environ.get("REACT_APP_BACKEND_URL")
            or frontend_env.get("REACT_APP_BACKEND_URL"))
if not base_url:
    raise RuntimeError("REACT_APP_BACKEND_URL missing")
BASE_URL = base_url.rstrip("/")
API = f"{BASE_URL}/api"

INCIDENT_ID = "36d8cd4d-a6b8-42b5-8106-1daf05a7d0ed"
# unique per run so the zero-user bootstrap allowance applies for the
# first provisioning call, then enforcement engages for that tenant.
RBAC_TENANT = f"TEST_intel_rbac_{uuid.uuid4().hex[:8]}"


def _creds() -> dict[str, str]:
    p = Path("/app/memory/test_credentials.md")
    if not p.exists():
        pytest.skip("missing /app/memory/test_credentials.md")
    c = p.read_text(encoding="utf-8")
    e = re.search(r'(?im)^\s*(?:[-*]\s*)?(?:\*\*)?email(?:\*\*)?\s*:\s*`?([^`\s]+)', c)
    pw = re.search(r'(?im)^\s*(?:[-*]\s*)?(?:\*\*)?password(?:\*\*)?\s*:\s*`?([^`\s]+)', c)
    if not e or not pw:
        pytest.skip("no creds parsed")
    return {"email": e.group(1), "password": pw.group(1)}


@pytest.fixture(scope="class")
def client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="class")
def auth(client):
    """JWT session for narration endpoints (get_current_user)."""
    c = _creds()
    r = client.post(f"{API}/auth/login",
                    json={"email": c["email"], "password": c["password"]},
                    timeout=60)
    if r.status_code != 200:
        pytest.fail(f"login failed {r.status_code}: {r.text[:300]}")
    body = r.json()
    tok = (body.get("access_token") or body.get("token")
           or (body.get("data") or {}).get("access_token"))
    if not tok:
        pytest.fail(f"no token in login response: {r.text[:300]}")
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json",
                      "Authorization": f"Bearer {tok}"})
    return s


def _put_global(client, ai, llm, reason="TEST_reason"):
    return client.put(f"{API}/intelligence/policy/global",
                      json={"online_ai": ai, "online_llm": llm,
                            "reason": reason}, timeout=60)


class TestIntelligencePolicyLive:

    # ---- teardown: restore permissive default state ----------------
    @pytest.fixture(scope="class", autouse=True)
    def _cleanup(self, client):
        yield
        client.delete(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}"
            "?reason=TEST_teardown", timeout=60)
        _put_global(client, "on", "on", reason="TEST_teardown_restore")

    # ---- 1. defaults on a virgin tenant ----------------------------
    def test_global_defaults_for_fresh_tenant(self, client):
        ten = f"TEST_fresh_{uuid.uuid4().hex[:8]}"
        r = client.get(f"{API}/intelligence/policy/global",
                       headers={"X-Tenant-Id": ten}, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["online_ai"] == "on"
        assert d["online_llm"] == "on"
        assert d["offline_ai"] == "on"
        assert d["offline_llm"] == "on"
        assert d["nivxray_narration_engine"] == "on"
        assert d["scope"] == "global"

    # ---- 2. PUT persists -------------------------------------------
    def test_put_global_persists(self, client):
        """online_ai=on/online_llm=off must round-trip verbatim."""
        r = _put_global(client, "on", "off")
        assert r.status_code == 200, r.text
        assert r.json()["online_ai"] == "on"
        assert r.json()["online_llm"] == "off"

        g = client.get(f"{API}/intelligence/policy/global", timeout=60).json()
        assert g["online_ai"] == "on"
        assert g["online_llm"] == "off"

    # ---- 2b. MEDIUM FIX: master-permission clamp in storage --------
    def test_master_permission_clamps_online_llm_off_in_storage(self, client):
        r = _put_global(client, "off", "on")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["online_ai"] == "off"
        assert body["online_llm"] == "off", (
            "PUT response must clamp online_llm to off when online_ai=off")

        g = client.get(f"{API}/intelligence/policy/global", timeout=60).json()
        assert g["online_ai"] == "off"
        assert g["online_llm"] == "off", (
            "stored policy must not keep a stale online_llm=on")

    # ---- 3. hierarchy: global online_ai=off forces llm off ---------
    def test_effective_implicit_llm_off_when_ai_off(self, client):
        _put_global(client, "off", "on")
        client.delete(f"{API}/intelligence/policy/incident/{INCIDENT_ID}"
                      "?reason=TEST_reset", timeout=60)
        r = client.get(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}/effective",
            timeout=60)
        assert r.status_code == 200, r.text
        eff = r.json()["effective"]
        assert eff["online_ai"] == "off"
        assert eff["online_llm"] == "off"
        # Storage now clamps online_llm=off at write time, so the resolver
        # inherits an already-off value from global ("global") instead of
        # deriving it ("implicit").  Both are valid post-fix.
        assert eff["online_llm_source"] in ("implicit", "global"), eff
        assert eff["offline_ai"] == "on"
        assert eff["offline_llm"] == "on"
        assert eff["nivxray_narration_engine"] == "on"
        assert eff["narration_engine_health"] == "ready"

    # ---- 4. incident cannot widen the global ceiling ---------------
    def test_incident_cannot_widen_global(self, client):
        _put_global(client, "off", "off")
        r = client.put(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}",
            json={"online_ai": "on", "online_llm": "on",
                  "reason": "TEST_try_widen"}, timeout=60)
        assert r.status_code == 200, r.text
        eff = client.get(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}/effective",
            timeout=60).json()["effective"]
        assert eff["online_ai"] == "off", "incident widened the global ceiling"
        assert eff["online_llm"] == "off"

    # ---- 5. incident may narrow -----------------------------------
    def test_incident_narrows_llm(self, client):
        _put_global(client, "on", "on")
        r = client.put(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}",
            json={"online_ai": None, "online_llm": "off",
                  "reason": "TEST_narrow"}, timeout=60)
        assert r.status_code == 200, r.text
        eff = client.get(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}/effective",
            timeout=60).json()["effective"]
        assert eff["online_ai"] == "on"
        assert eff["online_llm"] == "off"
        assert eff["online_llm_source"] == "incident_override"

    # ---- 6. narration blocked when effective online_llm=off --------
    def test_narration_deterministic_when_llm_off(self, client, auth):
        _put_global(client, "on", "on")
        client.put(f"{API}/intelligence/policy/incident/{INCIDENT_ID}",
                   json={"online_ai": None, "online_llm": "off",
                         "reason": "TEST_block"}, timeout=60)
        r = auth.get(
            f"{API}/narration/incident/{INCIDENT_ID}/executive-summary",
            timeout=180)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("generation_mode") == "deterministic", d.get("generation_mode")
        caveats = " ".join(d.get("caveats") or [])
        assert "blocked by intelligence policy (online_llm=off)" in caveats, caveats

    # ---- 7. narration uses cloud LLM when allowed ------------------
    def test_narration_llm_cloud_when_llm_on(self, client, auth):
        _put_global(client, "on", "on")
        client.delete(f"{API}/intelligence/policy/incident/{INCIDENT_ID}"
                      "?reason=TEST_allow", timeout=60)
        r = auth.get(
            f"{API}/narration/incident/{INCIDENT_ID}/executive-summary",
            timeout=240)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d.get("generation_mode") == "llm_cloud", d.get("generation_mode")
        assert (d.get("prose") or d.get("text") or d.get("summary")), d

    # ---- 8. global audit is append-only ----------------------------
    def test_global_history_append_only_and_row_shape(self, client):
        """HIGH FIX: global audit rows are written with scope_id='global'."""
        before = client.get(
            f"{API}/intelligence/policy/global/global/history", timeout=60)
        assert before.status_code == 200, before.text
        n0 = len(before.json()["history"])

        _put_global(client, "on", "off", reason="TEST_audit_1")
        _put_global(client, "on", "on", reason="TEST_audit_2")

        after = client.get(
            f"{API}/intelligence/policy/global/global/history", timeout=60)
        hist = after.json()["history"]
        assert len(hist) >= n0 + 2, f"{n0} -> {len(hist)} (not append-only)"
        e = hist[0]
        for k in ("tenant_id", "scope", "scope_id", "previous", "new",
                  "changed_by", "changed_by_role", "reason", "source",
                  "recorded_at", "audit_id"):
            assert k in e, f"missing audit field {k}: {e}"
        assert e["scope"] == "global"
        assert e["scope_id"] == "global"
        assert e["tenant_id"] == "default"
        assert e["source"] == "global"
        assert isinstance(e["previous"], dict) and isinstance(e["new"], dict)
        assert e["audit_id"].startswith("pol-aud-")
        assert "_id" not in e
        assert "TEST_audit_2" in [x.get("reason") for x in hist[:5]]

    def test_global_history_at_spec_scope_id_global(self, client):
        """BUG: spec + frontend call .../policy/global/global/history but the
        service writes audit rows with scope_id=tenant_id, so this always
        returns an empty list (UI 'Show History' is permanently empty)."""
        before = client.get(
            f"{API}/intelligence/policy/global/global/history",
            timeout=60)
        assert before.status_code == 200, before.text
        n0 = len(before.json()["history"])

        _put_global(client, "on", "off", reason="TEST_audit_1")
        _put_global(client, "on", "on", reason="TEST_audit_2")

        after = client.get(
            f"{API}/intelligence/policy/global/global/history", timeout=60)
        assert after.status_code == 200
        hist = after.json()["history"]
        assert len(hist) >= n0 + 2, (
            "global history at spec scope_id='global' is empty "
            f"({n0} -> {len(hist)}); audit rows are written with "
            "scope_id=tenant_id instead")

    # ---- 9. incident audit -----------------------------------------
    def test_incident_history(self, client):
        client.put(f"{API}/intelligence/policy/incident/{INCIDENT_ID}",
                   json={"online_ai": None, "online_llm": "off",
                         "reason": "TEST_inc_audit"}, timeout=60)
        r = client.get(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}/history",
            timeout=60)
        assert r.status_code == 200, r.text
        hist = r.json()["history"]
        assert len(hist) >= 1
        assert hist[0]["scope"] == "incident"
        assert hist[0]["scope_id"] == INCIDENT_ID
        assert "TEST_inc_audit" in [h.get("reason") for h in hist[:3]]

    def test_history_bad_scope_rejected(self, client):
        r = client.get(f"{API}/intelligence/policy/bogus/x/history", timeout=60)
        assert r.status_code == 400, r.text

    # ---- 10. clear override ----------------------------------------
    def test_clear_override_writes_clear_audit(self, client):
        client.put(f"{API}/intelligence/policy/incident/{INCIDENT_ID}",
                   json={"online_ai": None, "online_llm": "off",
                         "reason": "TEST_before_clear"}, timeout=60)
        r = client.delete(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}"
            "?reason=cleared", timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["online_ai"] is None
        assert d["online_llm"] is None

        got = client.get(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}",
            timeout=60).json()
        assert got["online_ai"] is None and got["online_llm"] is None

        hist = client.get(
            f"{API}/intelligence/policy/incident/{INCIDENT_ID}/history",
            timeout=60).json()["history"]
        assert hist[0]["action"] == "clear", hist[0]
        assert hist[0]["reason"] == "cleared"

    # ---- 11. health -------------------------------------------------
    def test_health(self, client):
        r = client.get(f"{API}/intelligence/health", timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["offline_ai"]["health"] in ("ready", "not_provisioned")
        assert d["offline_llm"]["health"] in ("ready", "not_provisioned")
        assert d["nivxray_narration_engine"]["health"] == "ready"

    # ---- 12. RBAC 403 in an enforced tenant -------------------------
    def test_rbac_denies_unprivileged_principal(self, client):
        h_boot = {"X-Tenant-Id": RBAC_TENANT,
                  "X-Principal-Id": "TEST_bootstrap@nivxray.com"}
        # provision a user with NO roles -> enforcement engages for tenant
        cr = client.post(f"{API}/xdr/rbac/users",
                         json={"email": "TEST_noroles@nivxray.com",
                               "display_name": "TEST No Roles",
                               "initial_roles": []},
                         headers=h_boot, timeout=60)
        assert cr.status_code in (200, 201, 409), cr.text

        r = client.put(
            f"{API}/intelligence/policy/global",
            json={"online_ai": "off", "online_llm": "off",
                  "reason": "TEST_rbac"},
            headers={"X-Tenant-Id": RBAC_TENANT,
                     "X-Principal-Id": "TEST_noroles@nivxray.com"},
            timeout=60)
        assert r.status_code == 403, f"{r.status_code}: {r.text[:300]}"
        detail = r.json().get("detail") or r.json()
        assert detail.get("code") == "ACCESS_DENIED", detail
        assert detail.get("permission") == "intelligence_policy.update", detail

    def test_rbac_allows_tenant_admin(self, client):
        ten = f"TEST_intel_allow_{uuid.uuid4().hex[:8]}"
        # Bootstrap tenant: first call is allowed, provision tenant_admin.
        cr = client.post(f"{API}/xdr/rbac/users",
                         json={"email": "TEST_tadmin@nivxray.com",
                               "display_name": "TEST Tenant Admin",
                               "initial_roles": ["tenant_admin"]},
                         headers={"X-Tenant-Id": ten,
                                  "X-Principal-Id": "TEST_boot@nivxray.com"},
                         timeout=60)
        assert cr.status_code in (200, 201, 409), cr.text
        r = client.put(
            f"{API}/intelligence/policy/global",
            json={"online_ai": "on", "online_llm": "on",
                  "reason": "TEST_rbac_allow"},
            headers={"X-Tenant-Id": ten,
                     "X-Principal-Id": "TEST_tadmin@nivxray.com"},
            timeout=60)
        assert r.status_code == 200, f"{r.status_code}: {r.text[:300]}"
