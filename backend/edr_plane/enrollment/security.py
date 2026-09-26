"""Secret generation and verification for machine identities.

Design decision, from the integration playbook and deliberately different
from user-password handling: these are **256-bit CSPRNG machine secrets**,
not human passwords. So we use a **keyed HMAC-SHA-256 digest with a
server-side pepper**, not bcrypt or Argon2id.

Why that is the right call here and not a shortcut:
  * A 256-bit random secret is not guessable. The threat bcrypt/Argon2id
    defend against — offline brute force of a low-entropy human choice —
    does not exist for these values.
  * bcrypt silently truncates at 72 bytes and is deliberately slow. The
    session token is verified on EVERY telemetry request; a slow KDF on
    that path is a self-inflicted denial of service.
  * A keyed digest is deterministic, so it can be INDEXED. That is what
    makes revocation an immediate server-side lookup rather than a scan.

The pepper lives in the environment, never in Mongo. A database-only
compromise therefore does not let an attacker verify candidate secrets
offline.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

#: Non-secret prefixes. They exist so secret-scanning tooling can spot a
#: leaked value in a log or a commit, and so a malformed presentation can
#: be rejected before any database work.
PREFIX_ENROLLMENT = "enr"
PREFIX_CREDENTIAL = "eak"
PREFIX_SESSION = "est"

_ENTROPY_BYTES = 32   # 256 bits


def _pepper() -> bytes:
    p = os.environ.get("EDR_AUTH_PEPPER")
    if not p:
        # Fail fast and loudly. A missing pepper must never silently
        # degrade to an unkeyed digest — that would make every stored
        # value offline-verifiable without anybody noticing.
        raise RuntimeError(
            "EDR_AUTH_PEPPER is not configured. Endpoint authentication "
            "refuses to run with an unkeyed digest.")
    return p.encode()


def new_secret(prefix: str) -> str:
    """A prefixed, URL-safe, 256-bit secret."""
    return f"{prefix}_{secrets.token_urlsafe(_ENTROPY_BYTES)}"


def digest(value: str) -> str:
    """Keyed digest. This is the ONLY form ever written to Mongo."""
    return hmac.new(_pepper(), value.encode(), hashlib.sha256).hexdigest()


def fingerprint(value: str) -> str:
    """A short, non-reversible identifier safe to put in an audit record.

    Needed for the rejected-telemetry security signal: an investigator has
    to be able to correlate repeated attempts by the same bad credential
    without the platform ever storing or logging the credential itself.
    """
    return digest(value)[:16]


def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def has_prefix(value: str, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(f"{prefix}_")


def redact(value: str | None) -> str:
    """What may appear in a log line or an API response. Never the secret.

    Deliberately does NOT show a trailing fragment: 'enr_…AbCd' looks
    harmless but narrows a brute force and invites someone to log the
    'safe' part of a value that has no safe part.
    """
    if not value:
        return "⊘ NONE PRESENTED"
    head = value.split("_", 1)[0] if "_" in value else "?"
    return f"{head}_[REDACTED:{fingerprint(value)}]"
