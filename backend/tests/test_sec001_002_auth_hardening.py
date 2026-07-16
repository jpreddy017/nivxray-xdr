"""Regression: SEC-001 + SEC-002 auth hardening (Feb-2026 audit).

SEC-001 — Published admin credential:
    The pre-audit release checklist and .env pinned the admin password to
    `NivXRay#2026!`. This test proves that literal is now REJECTED, so any
    attacker who copied the value from the public repo cannot log in.

SEC-002 — Weak JWT signing secret:
    The pre-audit .env used `nivxary_super_secret_key_change_in_prod_2026`.
    This test proves the current signing secret differs from that literal
    (defence against passive brute-force / secret guessing), and that
    tokens forged with the old secret are rejected.

The tests intentionally do NOT check what the new secret IS — that stays
in .env — only that the OLD one no longer works.
"""
import os
import jwt as pyjwt
import requests

BASE_URL = ""
with open("/app/frontend/.env") as f:
    for line in f:
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
assert BASE_URL

OLD_ADMIN_PW = "NivXRay#2026!"
OLD_JWT_SECRET = "nivxary_super_secret_key_change_in_prod_2026"


def test_old_admin_password_is_rejected():
    """SEC-001: the pre-audit credential must no longer authenticate."""
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": "admin@nivxray.com", "password": OLD_ADMIN_PW},
        timeout=15,
    )
    assert r.status_code == 401, (
        f"OLD ADMIN PASSWORD STILL WORKS — SEC-001 REGRESSION. "
        f"status={r.status_code} body={r.text[:200]}"
    )


def test_current_env_password_is_not_the_old_leaked_one():
    """Guard against a lazy revert — even if the seed hash matched the old
    password again (e.g. someone re-pasted the value into `.env`), fail
    the build."""
    env_path = "/app/backend/.env"
    with open(env_path) as f:
        content = f.read()
    assert OLD_ADMIN_PW not in content, (
        f"{env_path} still contains the leaked pre-audit admin password. "
        f"Rotate it and update /app/memory/test_credentials.md."
    )
    assert OLD_JWT_SECRET not in content, (
        f"{env_path} still contains the leaked pre-audit JWT_SECRET. "
        f"Rotate to a fresh secrets.token_urlsafe(64) value."
    )


def test_release_checklist_scrubbed_of_credentials():
    """The public release checklist must not embed live admin credentials."""
    for path in ("/app/GITHUB_RELEASE_CHECKLIST.md", "/app/README.md"):
        if not os.path.exists(path):
            continue
        text = open(path).read()
        assert OLD_ADMIN_PW not in text, (
            f"{path} still contains the leaked pre-audit password literal. "
            f"Replace with a doc-only placeholder."
        )


def test_token_forged_with_old_jwt_secret_is_rejected():
    """SEC-002: an attacker who guessed / kept a copy of the old
    signing secret must NOT be able to mint a valid session."""
    forged = pyjwt.encode(
        {"sub": "admin@nivxray.com"},
        OLD_JWT_SECRET,
        algorithm="HS256",
    )
    r = requests.get(
        f"{BASE_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {forged}"},
        timeout=15,
    )
    assert r.status_code == 401, (
        f"TOKEN FORGED WITH LEGACY JWT_SECRET WAS ACCEPTED — SEC-002 REGRESSION. "
        f"status={r.status_code}"
    )


def test_change_password_endpoint_exists_and_gates_wrong_current_password():
    """SEC-001 hardening — the change-password endpoint must require the
    current password (401) and only accept a new one that differs from
    the current."""
    admin_email = "admin@nivxray.com"
    admin_pw = os.environ.get("ADMIN_PASSWORD", "uulVDp5cCSB3Hva99s7UUAwK")
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": admin_email, "password": admin_pw},
                      timeout=15)
    if r.status_code != 200:
        # Preview env may have rotated the admin password again — skip
        # rather than fail. The 4 tests above still cover the audit fixes.
        import pytest
        pytest.skip("live admin password differs from ADMIN_PASSWORD env var")
    tok = r.json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}

    # Wrong current password → 401
    r_bad = requests.post(f"{BASE_URL}/api/auth/change-password", headers=h,
                         json={"current_password": "wrong-guess",
                               "new_password": "SomeNewPass!2026Extra"},
                         timeout=15)
    assert r_bad.status_code == 401, r_bad.text

    # Same new as current → 400
    r_same = requests.post(f"{BASE_URL}/api/auth/change-password", headers=h,
                          json={"current_password": admin_pw,
                                "new_password": admin_pw},
                          timeout=15)
    assert r_same.status_code == 400, r_same.text
