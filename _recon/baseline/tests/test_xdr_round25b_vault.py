"""
Round 25b · Credential Vault invariants.

Locked by owner (2026-02-14):
  1. mint → access → revoke lifecycle audit trail is complete.
  2. Revoked secret cannot be accessed.
  3. Rotation mints a NEW secret_ref and tombstones the old one
     with predecessor_ref set.
  4. Two separate integrations under the same tenant share a DEK
     version but their ciphertexts are independent (a leak of one
     ciphertext must not affect the other).
  5. The vault never returns plaintext through any read path other
     than `access(...)`.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import pytest

from detection_content.xdr_credential_vault import (
    CredentialVault, VaultAccessError, FileRootKeyProvider,
    VAULT_COLLECTION, AUDIT_COLLECTION,
)


class _MemColl:
    """Minimal async Mongo shim — matches the calls the vault makes."""
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def insert_one(self, doc: dict) -> None:
        self.rows.append(dict(doc))

    def find(self, q: dict | None = None, proj: dict | None = None):
        rows = [dict(r) for r in self.rows]
        if q:
            rows = [r for r in rows if all(r.get(k) == v for k, v in q.items())]
        async def _agen():
            for r in rows:
                yield r
        return _Sortable(_agen(), rows)

    async def find_one(self, q: dict, proj: dict | None = None):
        for r in self.rows:
            if all(r.get(k) == v for k, v in q.items()):
                return dict(r)
        return None

    async def update_one(self, q: dict, update: dict):
        for r in self.rows:
            if all(r.get(k) == v for k, v in q.items()):
                sets = update.get("$set", {})
                for k, v in sets.items():
                    r[k] = v
                unsets = update.get("$unset", {})
                for k in unsets.keys():
                    r.pop(k, None)
                class _Res:
                    matched_count = 1
                    modified_count = 1 if sets or unsets else 0
                return _Res()
        class _Res:
            matched_count = 0
            modified_count = 0
        return _Res()


class _Sortable:
    def __init__(self, agen, rows):
        self._agen = agen
        self._rows = rows
    def sort(self, key, direction):
        rows = sorted(self._rows, key=lambda r: r.get(key) or "",
                          reverse=direction == -1)
        async def _agen():
            for r in rows:
                yield r
        return _Sortable(_agen(), rows)
    def limit(self, n):
        async def _agen():
            i = 0
            async for r in self._agen:
                if i >= n:
                    return
                i += 1
                yield r
        return _Sortable(_agen(), self._rows[:n])
    def __aiter__(self):
        return self._agen


class _MemDB(dict):
    def __getitem__(self, key):
        if key not in self:
            super().__setitem__(key, _MemColl())
        return super().__getitem__(key)


@pytest.fixture()
def vault(tmp_path):
    os.environ["XDR_STATE_DIR"] = str(tmp_path)
    db = _MemDB()
    return CredentialVault(db, root_provider=FileRootKeyProvider(str(tmp_path))), db


def test_mint_access_revoke_lifecycle(vault):
    v, db = vault
    async def _run():
        ref = await v.mint_secret(
            tenant_id="t1", integration_id="i1",
            purpose="cortex_api_key", plaintext="SECRET_1",
            principal="test")
        assert ref.startswith("vlt-")
        # Access returns exact plaintext.
        got = await v.access(secret_ref=ref, purpose="cortex_probe",
                                 principal="test")
        assert got == "SECRET_1"
        # Revoke, then access must fail.
        ok = await v.revoke(secret_ref=ref, principal="test")
        assert ok is True
        with pytest.raises(VaultAccessError):
            await v.access(secret_ref=ref, purpose="cortex_probe",
                              principal="test")
        # Audit trail records everything, including the denied access.
        trail = await v.audit_trail(integration_id="i1")
        ops = [(row["op"], row["outcome"]) for row in reversed(trail)]
        assert ops == [
            ("MINT",   "OK"),
            ("ACCESS", "OK"),
            ("REVOKE", "OK"),
            ("ACCESS", "REVOKED_DENY"),
        ]
        # Ciphertext / wrapped_dek never present in redacted forms
        # (we don't have a redact API but we check the raw row shape).
        raw = db[VAULT_COLLECTION].rows[0]
        assert "SECRET_1" not in str(raw)
    asyncio.get_event_loop().run_until_complete(_run())


def test_rotate_installs_predecessor(vault):
    v, db = vault
    async def _run():
        ref1 = await v.mint_secret(tenant_id="t1", integration_id="i2",
                                          purpose="cortex_api_key",
                                          plaintext="K1", principal="test")
        ref2 = await v.rotate_secret(secret_ref=ref1,
                                            new_plaintext="K2",
                                            principal="test")
        assert ref2 != ref1
        # New ref carries predecessor_ref pointing at old.
        row2 = await db[VAULT_COLLECTION].find_one({"secret_ref": ref2})
        assert row2["predecessor_ref"] == ref1
        # Old ref is inactive.
        row1 = await db[VAULT_COLLECTION].find_one({"secret_ref": ref1})
        assert row1["active"] is False
        # Access old ref denied.
        with pytest.raises(VaultAccessError):
            await v.access(secret_ref=ref1, purpose="probe",
                              principal="test")
        # Access new ref returns new plaintext.
        assert await v.access(secret_ref=ref2, purpose="probe",
                                    principal="test") == "K2"
    asyncio.get_event_loop().run_until_complete(_run())


def test_independent_ciphertexts_same_tenant(vault):
    v, db = vault
    async def _run():
        r1 = await v.mint_secret(tenant_id="t1", integration_id="a",
                                        purpose="k", plaintext="AAA",
                                        principal="test")
        r2 = await v.mint_secret(tenant_id="t1", integration_id="b",
                                        purpose="k", plaintext="BBB",
                                        principal="test")
        assert r1 != r2
        row_a = await db[VAULT_COLLECTION].find_one({"secret_ref": r1})
        row_b = await db[VAULT_COLLECTION].find_one({"secret_ref": r2})
        # Ciphertexts differ even though same DEK version wraps them.
        assert row_a["ciphertext"] != row_b["ciphertext"]
        assert row_a["dek_id"] == row_b["dek_id"]
    asyncio.get_event_loop().run_until_complete(_run())
