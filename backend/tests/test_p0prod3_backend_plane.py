"""P0-PROD-3 · production EDR backend plane — deployability proof.

This gate is about whether the CURRENT proven EDR plane can be SERVED by a
production process, so the tests are deliberately about wiring and
configuration rather than about EDR behaviour (which the accepted
P0-A/P0-B/P0-C/P0-PROD-2 suites already cover).

Four things are proven here:

  1. every EDR route the console and the sensor need is registered on the
     application, unconditionally — no environment, product-scope or
     deployment guard can strip the EDR plane out of a build;
  2. the application starts under `NIVX_DEPLOYMENT_ENV=production` with a
     non-production test secret set, and the EDR plane is present in that
     process;
  3. production refuses to serve when the EDR plane's own mandatory
     configuration is missing, blank or a placeholder — including the two
     TTL settings that used to fail at first enrolment instead of at boot;
  4. a FRESH, EMPTY production database is represented truthfully as empty
     (never as verified-clean), needs no preview migration, and cannot be
     enrolled into without a registered tenant.

Nothing here contacts production, and no production secret is used.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import uuid
from pathlib import Path

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from edr_plane.enrollment import store
from edr_plane.enrollment.store import EnrollmentError
from security import secret_policy

SERVER = Path("/app/backend/server.py")

#: The production capability set the owner enumerated, expressed as the
#: ACTUAL route paths in the source (inventoried from the OpenAPI schema,
#: not invented).
REQUIRED_EDR_ROUTES: tuple[str, ...] = (
    # 1 enrolment
    "/api/edr/enrollment/tokens",
    "/api/edr/enrollment/tokens/{token_id}/revoke",
    "/api/edr/enrollment/endpoints",
    "/api/edr/enrollment/endpoints/{endpoint_id}/rotate",
    "/api/edr/enrollment/endpoints/{endpoint_id}/revoke",
    "/api/edr/enrollment/rejections",
    # 2–3 endpoint/agent identity and session
    "/api/edr/agent/enroll",
    "/api/edr/agent/session",
    "/api/edr/agent/whoami",
    # 4–5 heartbeat and telemetry
    "/api/edr/agent/heartbeat",
    "/api/edr/agent/telemetry",
    # 6 inventory
    "/api/edr/endpoints",
    "/api/edr/onboarding/computers",
    # 7–8 policy and policy fetch/ACK
    "/api/edr/policies",
    "/api/edr/policies/{policy_id}",
    "/api/edr/policies/{policy_id}/assign",
    "/api/edr/policies/{policy_id}/versions",
    "/api/edr/policies/deployment",
    "/api/edr/groups",
    "/api/edr/agent/policy",
    "/api/edr/agent/policy-ack",
    # 9 exclusions
    "/api/edr/exclusions",
    "/api/edr/exclusions/sets",
    "/api/edr/exclusions/taxonomy",
    "/api/edr/exclusions/{exclusion_id}/approval",
    "/api/edr/exclusions/{exclusion_id}/revoke",
    "/api/edr/exclusions/enforcement-proof",
    "/api/edr/agent/exclusion-enforcement",
    # 10–11 durable findings and evaluation state
    "/api/edr/findings",
    "/api/edr/findings/{finding_id}",
    "/api/edr/findings/evaluation-state",
    "/api/edr/findings/taxonomy",
    # 12 detections/events the console needs
    "/api/edr/detections",
    "/api/edr/endpoint-detections",
    "/api/edr/events",
    "/api/edr/events/facets",
    "/api/edr/telemetry/freshness",
    # 13 trajectory
    "/api/edr/device-trajectory",
    "/api/edr/file-trajectory",
    "/api/edr/process-tree",
    "/api/edr/endpoints/{endpoint_id}/trajectory",
    "/api/edr/campaign-story",
    # 14 audit
    "/api/edr/audit",
    "/api/edr/audit/facets",
    # 15 non-destructive control plane
    "/api/edr/endpoint-commands",
    "/api/edr/saved-views",
    "/api/edr/connector/releases",
    "/api/edr/connector/deployments",
    "/api/edr/context",
    "/api/edr/wave0/capabilities",
)

#: Registered on the application, but must stay BLOCKED until P0-PROD-4.
RESPONSE_ROUTES_PENDING_P0PROD4 = (
    "/api/edr/response/actions",
    "/api/edr/response/actions/{command_id}",
    "/api/edr/response/isolation-policy",
    "/api/edr/agent/commands",
    "/api/edr/agent/command-result",
    "/api/edr/agent/command-verification",
)

#: A production-shaped environment that uses NO production secret.
PROD_TEST_ENV = {
    "NIVX_DEPLOYMENT_ENV": "production",
    "JWT_SECRET": "p0prod3-test-jwt-not-a-production-secret-0000000000",
    "EDR_AUTH_PEPPER": "p0prod3-test-pepper-not-a-production-secret-000000",
    "XDR_AUDIT_MASTER_SECRET": "p0prod3-test-audit-not-production-000000000000",
    "XDR_SECRETS_MASTER": "p0prod3-test-secrets-not-production-00000000000",
    "NIVXRAY_SIGNING_SECRET": "p0prod3-test-signing-not-production-000000000",
    "XDR_ROOT_KEY": "p0prod3-test-root-not-production-00000000000000",
    "EDR_ENROLLMENT_TOKEN_TTL_SECONDS": "900",
    "EDR_AGENT_SESSION_TTL_SECONDS": "300",
}


def _base_env(**overrides: str) -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in secret_policy.FORBIDDEN_IN_PRODUCTION}
    env.update(PROD_TEST_ENV)
    for k, v in overrides.items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    return env


def _run(script: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", textwrap.dedent(script)],
                          cwd="/app/backend", env=env, capture_output=True,
                          text=True, timeout=240)


# ── 1 · route inventory and unconditional wiring ──────────────────

def test_every_required_edr_route_exists_in_the_application():
    from server import app
    served = {r.path for r in app.routes if hasattr(r, "path")}
    missing = [p for p in REQUIRED_EDR_ROUTES if p not in served]
    assert not missing, f"not registered on the application: {missing}"


def test_response_plane_is_registered_so_it_can_fail_closed_visibly():
    from server import app
    served = {r.path for r in app.routes if hasattr(r, "path")}
    missing = [p for p in RESPONSE_ROUTES_PENDING_P0PROD4 if p not in served]
    assert not missing, f"response plane not registered: {missing}"


def test_edr_router_registration_is_not_conditional():
    """A guard around `include_router` is how an EDR plane silently
    disappears from one deployment and not another. There is none."""
    for line in SERVER.read_text().splitlines():
        if "include_router" in line and "edr" in line.lower():
            assert not line.startswith((" ", "\t")), (
                f"EDR router registration is nested inside a guard: {line!r}")
    src = SERVER.read_text()
    for forbidden in ("PRODUCT_SCOPE", "NIVX_PRODUCT", "if is_production()",
                      "DISABLE_EDR", "EDR_ENABLED"):
        assert forbidden not in src, (
            f"{forbidden} could strip the EDR plane from a build")


# ── 2 · production start proof (non-production secrets) ───────────

def test_application_starts_in_production_mode_with_the_edr_plane():
    script = """
        from deps import validate_config
        validate_config()
        from server import app
        import json
        paths = sorted({r.path for r in app.routes if hasattr(r, 'path')})
        print("ROUTES " + json.dumps([p for p in paths if '/edr' in p]))
    """
    p = _run(script, _base_env())
    assert p.returncode == 0, p.stderr[-2000:]
    line = [l for l in p.stdout.splitlines() if l.startswith("ROUTES ")][0]
    edr = json.loads(line[len("ROUTES "):])
    missing = [r for r in REQUIRED_EDR_ROUTES if r not in edr]
    assert not missing, f"absent from the production-mode process: {missing}"


@pytest.fixture
def prod_env(monkeypatch):
    """A production-declared environment built from nothing.

    NOTE: a subprocess cannot prove ABSENCE here, because `deps` calls
    `load_dotenv(backend/.env)` on import and this pod's `.env` supplies
    the EDR settings. So absence is proven against the policy function
    `validate_config()` itself calls, with the environment patched in
    process and no dotenv reload.
    """
    for name in (secret_policy.MANDATORY_PRODUCTION_SECRETS
                 + secret_policy.MANDATORY_PRODUCTION_CONFIG
                 + secret_policy.FORBIDDEN_IN_PRODUCTION):
        monkeypatch.delenv(name, raising=False)
    for k, v in PROD_TEST_ENV.items():
        monkeypatch.setenv(k, v)
    return monkeypatch


def test_production_start_is_refused_without_the_edr_pepper(prod_env):
    for bad in (None, "   ", "changeme"):
        if bad is None:
            prod_env.delenv("EDR_AUTH_PEPPER", raising=False)
        else:
            prod_env.setenv("EDR_AUTH_PEPPER", bad)
        with pytest.raises(secret_policy.SecretPolicyError) as e:
            secret_policy.assert_production_ready()
        assert "EDR_AUTH_PEPPER" in str(e.value)
        assert "production configuration refused" in str(e.value)
        assert bad is None or bad not in str(e.value), "a value was printed"


@pytest.mark.parametrize("name", ["EDR_ENROLLMENT_TOKEN_TTL_SECONDS",
                                  "EDR_AGENT_SESSION_TTL_SECONDS"])
def test_production_start_is_refused_without_the_edr_ttl_settings(
        name, prod_env):
    for bad in (None, "", "0", "-1", "not-a-number"):
        if bad is None:
            prod_env.delenv(name, raising=False)
        else:
            prod_env.setenv(name, bad)
        with pytest.raises(secret_policy.SecretPolicyError) as e:
            secret_policy.assert_production_ready()
        assert name in str(e.value)


def test_production_refuses_a_forbidden_deployment_credential(prod_env):
    prod_env.setenv("VERCEL_TOKEN", "not-a-real-token")
    with pytest.raises(secret_policy.SecretPolicyError) as e:
        secret_policy.assert_production_ready()
    assert "VERCEL_TOKEN" in str(e.value)


def test_the_production_contract_passes_with_a_complete_environment(prod_env):
    out = secret_policy.assert_production_ready()
    assert out["enforced"] is True
    assert out["deployment_env"] == "production"


def test_the_mandatory_production_contract_is_explicit():
    assert "EDR_AUTH_PEPPER" in secret_policy.MANDATORY_PRODUCTION_SECRETS
    assert set(secret_policy.MANDATORY_PRODUCTION_CONFIG) == {
        "EDR_ENROLLMENT_TOKEN_TTL_SECONDS", "EDR_AGENT_SESSION_TTL_SECONDS"}


# ── 3 · preview key material is worthless in production ───────────

def test_a_fresh_production_pepper_cannot_verify_preview_digests():
    from importlib import reload
    from edr_plane.enrollment import security as sec
    secret = "enr_" + "a" * 43
    os.environ["EDR_AUTH_PEPPER"] = "preview-pepper-value-for-this-test"
    reload(sec)
    preview_digest = sec.digest(secret)
    os.environ["EDR_AUTH_PEPPER"] = "an-independent-production-pepper-value"
    reload(sec)
    assert sec.digest(secret) != preview_digest, (
        "a preview-issued credential must not be verifiable in production")


# ── 4 · fresh, empty production database ──────────────────────────

@pytest.mark.asyncio
async def test_a_fresh_empty_database_is_truthfully_empty():
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    fresh = f"nivx_p0prod3_fresh_{uuid.uuid4().hex[:8]}"
    db = client[fresh]
    try:
        # Index creation on a brand-new database must succeed: this is a
        # clean initialisation, not a migration.
        await store.ensure_indexes(db)
        tenant = "ten_fresh_production"
        assert await store.list_endpoints(db, tenant_id=tenant) == []
        assert await store.get_endpoint(db, tenant_id=tenant,
                                        endpoint_id="ep_none") is None
        assert await store.list_tokens(db, tenant_id=tenant) == []
        # No collection was pre-seeded with synthetic content.
        for coll in (store.ENDPOINTS, store.CREDENTIALS, store.SESSIONS,
                     store.TOKENS):
            assert await db[coll].count_documents({}) == 0
    finally:
        await client.drop_database(fresh)
        client.close()


@pytest.mark.asyncio
async def test_a_fresh_database_cannot_be_enrolled_into_by_guessing():
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    fresh = f"nivx_p0prod3_fresh_{uuid.uuid4().hex[:8]}"
    db = client[fresh]
    try:
        await store.ensure_indexes(db)
        with pytest.raises(EnrollmentError):
            await store.enroll(db, tenant_id="ten_fresh_production",
                               presented_token="enr_" + "b" * 43,
                               endpoint_id="ep_x", hostname="H")
        assert await db[store.ENDPOINTS].count_documents({}) == 0
    finally:
        await client.drop_database(fresh)
        client.close()


def test_enrolment_cannot_create_tenancy():
    """A fresh production database has no tenants, and the enrolment
    plane is not allowed to invent one."""
    from services import tenant_registry
    src = Path("/app/backend/services/tenant_registry.py").read_text()
    assert "def authoritative" in src
    assert hasattr(tenant_registry, "TenantRegistryError")
    router = Path("/app/backend/routers/edr_enrollment.py").read_text()
    assert "tenant_registry.authoritative" in router
    assert "tenancy" in router


# ── 5 · destructive response stays fail-closed (P0-PROD-4) ────────

def test_response_authority_has_no_default_url_and_fails_closed():
    src = Path("/app/backend/edr_plane/authority.py").read_text()
    assert 'os.environ.get("XDR_RESPONSE_SERVICE_URL") or ""' in src
    assert "localhost" not in src, (
        "the response authority must not carry a preview default")
    assert "RESPONSE_AUTHORITY_NOT_CONFIGURED" in src


def test_response_authority_is_unconfigured_absence_not_permission():
    from edr_plane import authority
    saved = os.environ.pop("XDR_RESPONSE_SERVICE_URL", None)
    try:
        assert authority._service_url() is None
    finally:
        if saved is not None:
            os.environ["XDR_RESPONSE_SERVICE_URL"] = saved


# ── 6 · production configurability (deployment-mechanism reality) ──

def test_every_mandatory_production_key_is_exposed_for_configuration():
    """The deployment's Secrets tab can only EDIT keys that already exist
    in `backend/.env`; brand-new key names cannot be added there. So a key
    that is absent from `.env` is a key the owner CANNOT configure in
    production — and production then refuses to boot. Each mandatory name
    must therefore be present, with a value that is either a preview value
    or an explicit placeholder (placeholders are refused in production, so
    exposure never becomes a weak default).
    """
    text = Path("/app/backend/.env").read_text()
    names = {line.split("=", 1)[0].strip() for line in text.splitlines()
             if "=" in line and not line.strip().startswith("#")}
    required = set(secret_policy.MANDATORY_PRODUCTION_SECRETS) | \
        set(secret_policy.MANDATORY_PRODUCTION_CONFIG) | \
        {"NIVX_DEPLOYMENT_ENV"}
    missing = sorted(required - names)
    assert not missing, (
        f"not configurable in the production deployment: {missing}")
    for name in secret_policy.FORBIDDEN_IN_PRODUCTION:
        assert name not in names


def test_placeholder_values_are_refused_in_production(prod_env):
    prod_env.setenv("XDR_ROOT_KEY",
                    "PLACEHOLDER-SET-REAL-VALUE-IN-PRODUCTION-SECRETS-TAB")
    with pytest.raises(secret_policy.SecretPolicyError) as e:
        secret_policy.assert_production_ready()
    assert "XDR_ROOT_KEY" in str(e.value)
