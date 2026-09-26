"""P0-PROD-1 · the ONE place that decides where a cryptographic key comes
from, and refuses to invent one.

Why this module exists: the audit chain, the connector-secret envelope and
the evidence-bundle signature each used to fall back to a constant that
lives in this repository. Anyone holding the source could forge a signed
audit chain or decrypt a stored connector credential. That is not a
configuration oversight to be fixed in an .env file — it has to become
impossible to ship.

Rules, enforced here and nowhere else:

* **No repository constant is ever a key.** There is no fallback literal
  in this file or in any consumer.
* **Production fails closed.** With ``NIVX_DEPLOYMENT_ENV=production``
  every mandatory secret must be configured, non-blank and not a
  placeholder, and forbidden development/deploy credentials must be
  absent. Missing or invalid → the process refuses to serve.
* **Preview/CI derive an instance-local key**, HKDF'd from this
  instance's own ``JWT_SECRET`` with a **distinct purpose label per
  cryptographic use**, so no two purposes ever share key material and
  nothing usable exists in version control.
* **An unknown or misspelled environment value is a configuration
  error**, never a silent downgrade to preview.
* **Nothing here logs, returns or raises a secret value.** Only variable
  names, purposes, and the non-secret ``key_id`` fingerprint.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENV_VAR = "NIVX_DEPLOYMENT_ENV"
PREVIEW, TEST, PRODUCTION = "preview", "test", "production"
VALID_ENVIRONMENTS = (PREVIEW, TEST, PRODUCTION)

#: Secrets that MUST be operator-configured in production. Each one, if
#: absent, is a real loss of integrity or confidentiality — not a
#: degraded feature.
MANDATORY_PRODUCTION_SECRETS: Tuple[str, ...] = (
    "JWT_SECRET",                 # operator session authenticity
    "EDR_AUTH_PEPPER",            # endpoint credential digests
    "XDR_AUDIT_MASTER_SECRET",    # tamper-evident audit chain
    "XDR_SECRETS_MASTER",         # connector / webhook secret envelope
    "NIVXRAY_SIGNING_SECRET",     # evidence bundle signatures
    "XDR_ROOT_KEY",               # credential vault root key
)

#: Non-secret settings the EDR endpoint plane READS DIRECTLY at use time
#: (`os.environ[...]`). Absent in production, the plane would not fail at
#: boot — it would 500 at the first enrolment or session exchange, which
#: is a production incident disguised as a configuration omission. Each
#: must parse as a positive integer.
MANDATORY_PRODUCTION_CONFIG: Tuple[str, ...] = (
    "EDR_ENROLLMENT_TOKEN_TTL_SECONDS",
    "EDR_AGENT_SESSION_TTL_SECONDS",
)

#: Development and deployment-plane credentials that must not exist in a
#: production application runtime. A deploy token in the app's own
#: environment is a privilege the app has no business holding.
FORBIDDEN_IN_PRODUCTION: Tuple[str, ...] = (
    "VERCEL_TOKEN",
    "TEST_ANALYST_NIVXLIVE_PASSWORD",
)

#: Purpose labels — domain separation. Two purposes NEVER share derived
#: key material, so compromise of one cannot forge another.
PURPOSE_AUDIT_SIGNING = "audit-signing"
PURPOSE_CONNECTOR_SECRETS = "connector-secret-encryption"
PURPOSE_BUNDLE_SIGNING = "evidence-bundle-signing"
PURPOSE_VAULT_ROOT = "credential-vault-root"

BASIS_CONFIGURED = "CONFIGURED"
BASIS_DERIVED = "DERIVED_INSTANCE_LOCAL"

#: Values that look configured but are not a secret. Matched
#: case-insensitively as substrings, because "changeme-please" is no
#: better than "changeme".
_PLACEHOLDER_TOKENS = (
    "changeme", "change-me", "change_me", "placeholder", "example",
    "do-not-use", "donotuse", "dummy", "sample", "todo", "fixme",
    "yourkeyhere", "insert-secret", "xxxxx",
)

_HKDF_SALT = b"nivx-instance-local-key-v1"

LEGACY_CLASSIFICATION = ("PREVIEW_LEGACY_SECRET — "
                         "REPLACEMENT_REQUIRED_BEFORE_PRODUCTION_USE")


class SecretPolicyError(RuntimeError):
    """Configuration refusal. Carries names and purposes — never values."""


def deployment_env() -> str:
    """The declared environment. An unrecognised value is an ERROR.

    Production must be declared explicitly; a typo must never leave the
    process quietly running with preview-grade key material.
    """
    raw = os.environ.get(ENV_VAR)
    if raw is None or raw.strip() == "":
        return PREVIEW
    value = raw.strip()
    if value not in VALID_ENVIRONMENTS:
        raise SecretPolicyError(
            f"{ENV_VAR} is set to an unrecognised value. Accepted values "
            f"are {list(VALID_ENVIRONMENTS)}. A misspelled environment "
            f"must not silently fall back to '{PREVIEW}', because that "
            f"would let a production process run on preview-grade, "
            f"instance-derived key material.")
    return value


def is_production() -> bool:
    return deployment_env() == PRODUCTION


def _looks_like_placeholder(value: str) -> bool:
    low = value.strip().lower()
    return any(tok in low for tok in _PLACEHOLDER_TOKENS)


def _configured(name: str) -> str | None:
    """The configured value, or None when it is absent, blank or a
    placeholder. Never returned to a caller that does not need it."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return None
    if _looks_like_placeholder(raw):
        return None
    return raw


def key_id(material: bytes) -> str:
    """A publishable fingerprint of a key: first 12 hex of its SHA-256.

    Safe to store on signed records and return over the API — it
    identifies WHICH key was used without disclosing it.
    """
    return hashlib.sha256(material).hexdigest()[:12]


def _derive(name: str, purpose: str) -> bytes:
    seed = _configured("JWT_SECRET")
    if not seed:
        raise SecretPolicyError(
            f"{name} is not configured and no instance seed (JWT_SECRET) "
            f"exists to derive a {deployment_env()} key from. Refusing to "
            f"use an unkeyed or repository-known value for '{purpose}'.")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT,
                info=f"{purpose}\x1f{name}".encode()).derive(seed.encode())


def resolve(name: str, purpose: str) -> Tuple[bytes, str, str]:
    """Return ``(key_material, key_id, basis)`` for one purpose.

    In production the secret MUST be configured. Outside production an
    instance-local key is derived, domain-separated by purpose, and the
    basis says so — so no evidence document can imply an operator key
    where there is none.
    """
    if not purpose:
        raise SecretPolicyError("a cryptographic purpose is required; "
                                "unlabelled key use is not permitted")
    configured = _configured(name)
    if configured:
        material = configured.encode()
        return material, key_id(material), BASIS_CONFIGURED
    if is_production():
        raise SecretPolicyError(
            f"{name} is not configured (or is blank/placeholder) and the "
            f"deployment environment is '{PRODUCTION}'. There is no "
            f"fallback key for '{purpose}': a derived or repository-known "
            f"key would make signatures forgeable and stored secrets "
            f"readable by anyone holding the source.")
    material = _derive(name, purpose)
    return material, key_id(material), BASIS_DERIVED


def resolve_fernet(name: str, purpose: str) -> Tuple[bytes, str, str]:
    """As :func:`resolve`, but normalised to a Fernet key (urlsafe-base64
    of 32 bytes). A configured value that is already a Fernet key is used
    verbatim; anything else is stretched, never truncated."""
    material, kid, basis = resolve(name, purpose)
    if len(material) == 44:
        try:
            if len(base64.urlsafe_b64decode(material)) == 32:
                return material, kid, basis
        except Exception:                                     # noqa: BLE001
            pass
    stretched = HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT,
                     info=f"fernet\x1f{purpose}\x1f{name}".encode()
                     ).derive(material)
    key = base64.urlsafe_b64encode(stretched)
    return key, key_id(key), basis


def assert_production_ready() -> Dict[str, object]:
    """Fail closed before serving. Names only — never values."""
    env = deployment_env()
    if env != PRODUCTION:
        return {"deployment_env": env, "enforced": False,
                "note": (f"mandatory-secret enforcement applies only when "
                         f"{ENV_VAR}={PRODUCTION}; this process derives "
                         f"instance-local keys and says so on every "
                         f"record it signs")}
    missing: List[str] = [n for n in MANDATORY_PRODUCTION_SECRETS
                          if not _configured(n)]
    forbidden: List[str] = [n for n in FORBIDDEN_IN_PRODUCTION
                            if (os.environ.get(n) or "").strip()]
    badconfig: List[str] = []
    for name in MANDATORY_PRODUCTION_CONFIG:
        raw = (os.environ.get(name) or "").strip()
        try:
            if int(raw) <= 0:
                raise ValueError
        except ValueError:
            badconfig.append(name)
    if missing or forbidden or badconfig:
        parts = []
        if missing:
            parts.append(f"missing or invalid mandatory secret(s): "
                         f"{missing}")
        if badconfig:
            parts.append(f"missing or non-positive mandatory setting(s): "
                         f"{badconfig}")
        if forbidden:
            parts.append(f"forbidden development/deployment credential(s) "
                         f"present in the production runtime: {forbidden}")
        raise SecretPolicyError(
            "production configuration refused — " + "; ".join(parts) +
            ". No value is printed. Set production secrets in the "
            "deployment's own secret store, not in application code.")
    return {"deployment_env": env, "enforced": True,
            "mandatory_secrets_configured": list(
                MANDATORY_PRODUCTION_SECRETS),
            "mandatory_config_configured": list(MANDATORY_PRODUCTION_CONFIG),
            "forbidden_absent": list(FORBIDDEN_IN_PRODUCTION)}


def report() -> Dict[str, object]:
    """Non-secret provenance of every cryptographic key in use. Safe to
    log and safe to paste into an evidence document."""
    out: Dict[str, object] = {"deployment_env": deployment_env(),
                              "keys": []}
    for name, purpose in (("XDR_AUDIT_MASTER_SECRET",
                           PURPOSE_AUDIT_SIGNING),
                          ("XDR_SECRETS_MASTER",
                           PURPOSE_CONNECTOR_SECRETS),
                          ("NIVXRAY_SIGNING_SECRET",
                           PURPOSE_BUNDLE_SIGNING),
                          ("XDR_ROOT_KEY", PURPOSE_VAULT_ROOT)):
        try:
            _, kid, basis = resolve(name, purpose)
            out["keys"].append({"name": name, "purpose": purpose,
                                "key_id": kid, "basis": basis})
        except SecretPolicyError as e:
            out["keys"].append({"name": name, "purpose": purpose,
                                "key_id": None, "basis": "UNAVAILABLE",
                                "reason": str(e)})
    return out
