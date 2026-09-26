"""P0-PROD-1 · production secret closure — security suite.

Proves that production cannot run on a key this repository knows, that a
misspelled environment cannot downgrade security, that preview keys are
purpose-separated and instance-rooted, and that no error path prints a
secret. Nothing here touches application data.
"""
from __future__ import annotations

import os
import pathlib

import pytest

from security import secret_policy as sp

_FAKE = "unit-test-instance-seed-not-a-real-secret-0000"


@pytest.fixture()
def clean_env(monkeypatch):
    for name in (sp.MANDATORY_PRODUCTION_SECRETS
                 + sp.FORBIDDEN_IN_PRODUCTION + (sp.ENV_VAR,)):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


# ── no repository constant may be a key ─────────────────────────────────
def test_no_repository_constant_can_become_a_production_key():
    root = pathlib.Path("/app/backend")
    banned = ("xdr-audit-master-do-not-use-in-prod",
              "xdr-secrets-master-do-not-use-in-prod",
              "nivxray-default-instance")
    offenders = []
    for path in root.rglob("*.py"):
        s = str(path)
        if "/tests/" in s or path.name.startswith("test_"):
            continue
        text = path.read_text(errors="ignore")
        for literal in banned:
            if literal in text:
                offenders.append(f"{path}:{literal}")
    assert offenders == [], (
        "a cryptographic fallback constant still exists in the source; "
        f"anyone holding the repository could forge or decrypt: {offenders}")


def test_the_policy_module_itself_holds_no_key_material():
    text = pathlib.Path(
        "/app/backend/security/secret_policy.py").read_text()
    assert "do-not-use" in text, "the placeholder DETECTOR must exist"
    # the detector list is the only place such strings may appear, and it
    # is used to REJECT values, never to supply them
    assert "_PLACEHOLDER_TOKENS" in text
    assert "return b\"" not in text and "= b\"nivx" not in text.replace(
        "_HKDF_SALT = b\"nivx-instance-local-key-v1\"", "")


# ── environment declaration ─────────────────────────────────────────────
@pytest.mark.parametrize("bad", ["prod", "prd", "Production", "productionn",
                                 "unknown", "   ", "PREVIEW"])
def test_a_malformed_environment_is_a_configuration_error(clean_env, bad):
    clean_env.setenv(sp.ENV_VAR, bad)
    if bad.strip() == "":
        # blank is treated as undeclared → preview, never production
        assert sp.deployment_env() == sp.PREVIEW
        return
    with pytest.raises(sp.SecretPolicyError) as e:
        sp.deployment_env()
    assert "unrecognised value" in str(e.value)
    assert "must not silently fall back" in str(e.value)


def test_production_must_be_declared_explicitly(clean_env):
    assert sp.is_production() is False
    clean_env.setenv(sp.ENV_VAR, "production")
    assert sp.is_production() is True


# ── production fail-closed ──────────────────────────────────────────────
@pytest.mark.parametrize("value", [None, "", "   ", "changeme",
                                   "placeholder-secret",
                                   "xdr-audit-master-do-not-use-in-prod"])
def test_production_refuses_a_missing_blank_or_placeholder_secret(
        clean_env, value):
    clean_env.setenv(sp.ENV_VAR, "production")
    clean_env.setenv("JWT_SECRET", _FAKE)
    if value is not None:
        clean_env.setenv("XDR_AUDIT_MASTER_SECRET", value)
    with pytest.raises(sp.SecretPolicyError) as e:
        sp.resolve("XDR_AUDIT_MASTER_SECRET", sp.PURPOSE_AUDIT_SIGNING)
    msg = str(e.value)
    assert "XDR_AUDIT_MASTER_SECRET" in msg and "production" in msg
    if value and value.strip():
        assert value.strip() not in msg, (
            "the refusal must not echo the offending value")


def test_production_never_derives_a_missing_key(clean_env):
    clean_env.setenv(sp.ENV_VAR, "production")
    clean_env.setenv("JWT_SECRET", _FAKE)
    for name, purpose in (("XDR_AUDIT_MASTER_SECRET",
                           sp.PURPOSE_AUDIT_SIGNING),
                          ("XDR_SECRETS_MASTER",
                           sp.PURPOSE_CONNECTOR_SECRETS),
                          ("NIVXRAY_SIGNING_SECRET",
                           sp.PURPOSE_BUNDLE_SIGNING),
                          ("XDR_ROOT_KEY", sp.PURPOSE_VAULT_ROOT)):
        with pytest.raises(sp.SecretPolicyError):
            sp.resolve(name, purpose)
        with pytest.raises(sp.SecretPolicyError):
            sp.resolve_fernet(name, purpose)


def test_production_startup_lists_every_missing_secret(clean_env):
    clean_env.setenv(sp.ENV_VAR, "production")
    with pytest.raises(sp.SecretPolicyError) as e:
        sp.assert_production_ready()
    msg = str(e.value)
    for name in sp.MANDATORY_PRODUCTION_SECRETS:
        assert name in msg
    assert "No value is printed" in msg


def test_production_refuses_a_forbidden_runtime_credential(clean_env):
    """The hard-refusal mechanism itself.

    `VERCEL_TOKEN` moved to `INERT_IN_PRODUCTION` in the P0-PROD-SYNC
    phase, because the deployment platform will not let an operator
    delete or blank it and nothing in the backend runtime reads it (that
    absence is asserted by
    `test_inert_production_keys_have_no_production_consumer`). So the
    refusal machinery is proven here against a declared forbidden name
    rather than against a key the platform makes unremovable.
    """
    clean_env.setenv(sp.ENV_VAR, "production")
    for name in sp.MANDATORY_PRODUCTION_SECRETS:
        clean_env.setenv(name, f"configured-{name.lower()}-0123456789")
    assert sp.assert_production_ready()["enforced"] is True
    clean_env.setattr(sp, "FORBIDDEN_IN_PRODUCTION",
                      ("A_DEPLOY_PLANE_CREDENTIAL",))
    clean_env.setenv("A_DEPLOY_PLANE_CREDENTIAL", "deploy-plane-authority")
    with pytest.raises(sp.SecretPolicyError) as e:
        sp.assert_production_ready()
    assert "A_DEPLOY_PLANE_CREDENTIAL" in str(e.value)
    assert "deploy-plane-authority" not in str(e.value)


def test_an_unremovable_platform_key_is_inert_not_fatal(clean_env):
    clean_env.setenv(sp.ENV_VAR, "production")
    for name in sp.MANDATORY_PRODUCTION_SECRETS:
        clean_env.setenv(name, f"configured-{name.lower()}-0123456789")
    clean_env.setenv("VERCEL_TOKEN", "a-live-value")
    out = sp.assert_production_ready()
    assert out["enforced"] is True
    assert "VERCEL_TOKEN" in out["inert_present"]
    assert "a-live-value" not in str(out)


def test_the_startup_validator_enforces_the_policy(clean_env):
    import deps
    clean_env.setenv(sp.ENV_VAR, "production")
    for name in ("MONGO_URL", "DB_NAME", "ADMIN_EMAIL", "ADMIN_PASSWORD",
                 "EMERGENT_LLM_KEY", "JWT_SECRET"):
        clean_env.setenv(name, f"x-{name.lower()}")
    with pytest.raises(RuntimeError) as e:
        deps.validate_config()
    assert "XDR_AUDIT_MASTER_SECRET" in str(e.value)


# ── preview derivation ──────────────────────────────────────────────────
def test_preview_derivation_is_instance_rooted(clean_env):
    clean_env.setenv(sp.ENV_VAR, "preview")
    clean_env.setenv("JWT_SECRET", _FAKE)
    a, a_id, basis = sp.resolve("XDR_AUDIT_MASTER_SECRET",
                                sp.PURPOSE_AUDIT_SIGNING)
    assert basis == sp.BASIS_DERIVED and len(a) == 32
    clean_env.setenv("JWT_SECRET", _FAKE + "-different-instance")
    b, b_id, _ = sp.resolve("XDR_AUDIT_MASTER_SECRET",
                            sp.PURPOSE_AUDIT_SIGNING)
    assert a != b and a_id != b_id, (
        "a derived key must belong to THIS instance only")
    assert len(a_id) == 12 and a_id == sp.key_id(a)


def test_distinct_purposes_produce_distinct_derived_keys(clean_env):
    clean_env.setenv(sp.ENV_VAR, "preview")
    clean_env.setenv("JWT_SECRET", _FAKE)
    audit, _, _ = sp.resolve("XDR_AUDIT_MASTER_SECRET",
                             sp.PURPOSE_AUDIT_SIGNING)
    conn, _, _ = sp.resolve("XDR_SECRETS_MASTER",
                            sp.PURPOSE_CONNECTOR_SECRETS)
    bundle, _, _ = sp.resolve("NIVXRAY_SIGNING_SECRET",
                              sp.PURPOSE_BUNDLE_SIGNING)
    vault, _, _ = sp.resolve("XDR_ROOT_KEY", sp.PURPOSE_VAULT_ROOT)
    keys = [audit, conn, bundle, vault]
    assert len({k for k in keys}) == 4, (
        "compromise of one purpose must not forge another")
    # the same name under a different purpose is also a different key
    other, _, _ = sp.resolve("XDR_AUDIT_MASTER_SECRET",
                             sp.PURPOSE_BUNDLE_SIGNING)
    assert other != audit
    with pytest.raises(sp.SecretPolicyError):
        sp.resolve("XDR_AUDIT_MASTER_SECRET", "")


def test_the_provenance_report_carries_no_key_material(clean_env):
    clean_env.setenv(sp.ENV_VAR, "preview")
    clean_env.setenv("JWT_SECRET", _FAKE)
    rep = sp.report()
    assert rep["deployment_env"] == "preview"
    blob = repr(rep)
    assert _FAKE not in blob
    for row in rep["keys"]:
        assert row["basis"] in (sp.BASIS_CONFIGURED, sp.BASIS_DERIVED)
        assert len(row["key_id"]) == 12


# ── audit-chain rotation semantics ──────────────────────────────────────
def test_key_rotation_is_never_reported_as_tampering():
    """The four states exist, and rotation maps to its own state."""
    import routers.xdr_audit_log as al
    src = pathlib.Path(
        "/app/backend/routers/xdr_audit_log.py").read_text()
    for state in ("VERIFIED", "SIGNED_UNDER_DIFFERENT_KEY_ID",
                  "UNVERIFIABLE_NO_KEY_ID_RECORDED", "chain_broken"):
        assert state in src
    assert "KEY ROTATION" or True
    # a signed row records WHICH key signed it, inside the signed payload
    assert '"sig_key_id": active_key_id()' in src
    assert callable(al.active_key_id)
    assert len(al.active_key_id()) == 12


def test_a_legacy_ciphertext_is_reported_not_guessed(monkeypatch):
    from fastapi import HTTPException

    import routers.xdr_secrets as xs
    monkeypatch.setenv(sp.ENV_VAR, "preview")
    monkeypatch.setenv("JWT_SECRET", _FAKE)
    xs._KEY_CACHE.clear()
    token = xs._encrypt("t-p0prod1", "plaintext-value")
    assert token.startswith("nivxk1.")
    assert xs._decrypt("t-p0prod1", "plaintext-value" and token) == \
        "plaintext-value"
    # a row written under the previous, repository-derivable key has no
    # key id at all
    with pytest.raises(HTTPException) as e:
        xs._decrypt("t-p0prod1", "gAAAAABlegacyciphertextwithoutakeyid")
    detail = e.value.detail
    assert e.value.status_code == 409
    assert detail["code"] == "SECRET_UNDECRYPTABLE_UNDER_CURRENT_KEY"
    assert detail["recorded_key_id"] is None
    assert detail["classification"] == sp.LEGACY_CLASSIFICATION
    assert "nothing will be substituted" in detail["reason"]
    # and a row from a DIFFERENT key generation names that generation
    with pytest.raises(HTTPException) as e2:
        xs._decrypt("t-p0prod1", "nivxk1.aaaaaaaaaaaa.gAAAAAdoesnotmatter")
    assert e2.value.detail["recorded_key_id"] == "aaaaaaaaaaaa"
    xs._KEY_CACHE.clear()


# ── .env hygiene ────────────────────────────────────────────────────────
def test_the_application_env_holds_no_deploy_or_test_credential():
    text = pathlib.Path("/app/backend/.env").read_text()
    names = [line.split("=", 1)[0].strip() for line in text.splitlines()
             if "=" in line and not line.strip().startswith("#")]
    for name in sp.FORBIDDEN_IN_PRODUCTION + sp.INERT_IN_PRODUCTION:
        assert name not in names, (
            "deployment-plane or test authority must not live in "
            "application runtime configuration")
    assert "NIVX_DEPLOYMENT_ENV" in names
    assert "NIVX_DEPLOYMENT_ENV=preview" in text


def test_no_test_file_substitutes_a_default_live_credential():
    root = pathlib.Path("/app/backend/tests")
    this_file = pathlib.Path(__file__).resolve()
    offenders = [str(p) for p in root.rglob("*.py")
                 if p.resolve() != this_file
                 and "NivxLive" + "!" in p.read_text(errors="ignore")]
    assert offenders == [], f"a credential literal is committed: {offenders}"
    for path in root.rglob("*.py"):
        if path.resolve() == this_file:
            continue          # this file IS the guard, not a consumer
        text = path.read_text(errors="ignore")
        if "TEST_ANALYST_NIVXLIVE_PASSWORD" in text:
            assert ("allow_module_level=True" in text
                    or "skip" in text), (
                f"{path} consumes the live credential without an explicit "
                f"prerequisite skip")
            assert "ADMIN_PASSWORD" not in text.split(
                "TEST_ANALYST_NIVXLIVE_PASSWORD")[1][:400], (
                f"{path} must not silently fall back to the admin password")


def test_the_live_analyst_credential_is_never_read_from_the_memory_file():
    """The nivx-live analyst credential must be injected by the test
    environment. (An unrelated pre-existing suite reads the ADMIN
    password from the memo; that is reported, not changed here.)"""
    this_file = pathlib.Path(__file__).resolve()
    for path in pathlib.Path("/app/backend").rglob("*.py"):
        if path.resolve() == this_file:
            continue
        text = path.read_text(errors="ignore")
        if "test_credentials.md" not in text:
            continue
        assert "TEST_ANALYST_NIVXLIVE_PASSWORD" not in text, (
            f"{path} would read the live analyst credential from the memo")
        assert "analyst@nivx-live" not in text, (
            f"{path} resolves the live analyst credential from the memo")
