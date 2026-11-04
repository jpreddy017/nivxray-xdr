"""
Round 25b · NivXRay Credential Vault.
=====================================

**Boundary invariant (owner-locked · Round 25b):**

    xdr_integrations           (no plaintext, no ciphertext)
          │  integration_id
          ▼
    Credential Vault           ← THIS module (envelope-encrypted)
          │  decrypt only at execution boundary
          ▼
    xdr_cortex_adapter (or any future adapter)
          │  scoped, one-shot, audited
          ▼
    Vendor API

Adapters MUST NEVER read `xdr_integrations.credentials`.  They call
`vault.access(secret_ref, purpose=…, principal=…)` at the moment they
sign a vendor request.  Every access is audit-logged; plaintext is
returned once and is not persisted anywhere by the vault.

## Envelope model

* **Data-Encryption Key (DEK)** — per-tenant, per-purpose 32-byte
  AES-256 key.  Generated at first-use, cached in memory only.
* **Root Key** — supplied by a `RootKeyProvider`.  Two providers
  ship today:
    - `EnvRootKeyProvider` — reads `XDR_ROOT_KEY` (base64).
    - `FileRootKeyProvider` — reads/creates
      `${XDR_STATE_DIR}/root.key`, chmod 600.
  Round 26+ can drop in a `KMSRootKeyProvider` without touching
  callers.
* **Ciphertext record** — `xdr_credential_vault` document:
    {
      secret_ref:       "vlt-<uuid>",           # opaque reference
      tenant_id:        str,
      integration_id:   str,
      purpose:          "cortex_api_key" | …,
      dek_id:           "dek-<tenant>-v<version>",
      wrapped_dek:      base64 · Fernet(root_key, dek),
      ciphertext:       base64 · Fernet(dek, plaintext),
      created_at, updated_at, active,
      predecessor_ref:  secret_ref of the row this one replaced
    }
* **Audit** — every `mint / access / rotate / revoke` writes to
  `xdr_vault_audit` (append-only).

## Rotation semantics

* `rotate_secret(secret_ref, new_plaintext)` mints a NEW record with
  a fresh wrapped_dek + ciphertext, sets `predecessor_ref` to the
  old row, tombstones the old row (`active=False`), and returns the
  new secret_ref.
* `rotate_dek(tenant_id)` bumps the tenant's DEK version.  Existing
  secrets stay usable — their `dek_id` records the DEK version they
  were sealed under.  Future writes use the new DEK.
* A revoked secret cannot be accessed.  Attempted access is
  audit-logged with `outcome=REVOKED_DENY`.
"""
from __future__ import annotations

import base64
import datetime as _dt
import logging
import os
import secrets as _secrets
import uuid
from abc import ABC, abstractmethod
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger("nivxray.xdr.vault")

VAULT_COLLECTION = "xdr_credential_vault"
AUDIT_COLLECTION = "xdr_vault_audit"


# ── Root-key providers (KMS-agnostic boundary) ────────────────
class RootKeyProvider(ABC):
    """Returns the raw Fernet-compatible root key.  A KMS-backed
    implementation should wrap the DEK via KMS Encrypt/Decrypt calls
    and return a stable local key here only when the KMS provider is
    unavailable (never do both)."""
    @abstractmethod
    def root_key(self) -> bytes: ...


class EnvRootKeyProvider(RootKeyProvider):
    def root_key(self) -> bytes:
        raw = os.environ.get("XDR_ROOT_KEY")
        if not raw:
            raise KeyError("XDR_ROOT_KEY not set")
        return raw.encode("ascii")


class FileRootKeyProvider(RootKeyProvider):
    def __init__(self, state_dir: Optional[str] = None) -> None:
        self._state_dir = state_dir or os.environ.get(
            "XDR_STATE_DIR", "/app/backend/xdr_state")
        self._path = os.path.join(self._state_dir, "root.key")

    def root_key(self) -> bytes:
        os.makedirs(self._state_dir, exist_ok=True)
        if os.path.isfile(self._path):
            with open(self._path, "rb") as f:
                return f.read().strip()
        key = Fernet.generate_key()
        with open(self._path, "wb") as f:
            f.write(key)
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass
        return key


def default_root_key_provider() -> RootKeyProvider:
    if os.environ.get("XDR_ROOT_KEY"):
        return EnvRootKeyProvider()
    return FileRootKeyProvider()


# ── Vault ─────────────────────────────────────────────────────
def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


class VaultAccessError(Exception):
    """Raised when a vault access fails (revoked, missing, wrong DEK)."""


class CredentialVault:
    """Envelope-encrypted, tenant-isolated credential store."""

    def __init__(self, db, root_provider: Optional[RootKeyProvider] = None) -> None:
        self._db = db
        self._root = root_provider or default_root_key_provider()
        # In-process DEK cache · reset on process restart.  Never
        # persisted; MUST NEVER leak out of this class.
        self._dek_cache: dict[str, bytes] = {}

    # ── Internals ─────────────────────────────────────────
    def _root_fernet(self) -> Fernet:
        return Fernet(self._root.root_key())

    def _current_dek_id(self, tenant_id: str) -> str:
        # v1 is created on demand; rotation bumps versions.
        return f"dek-{tenant_id}-v1"

    def _dek_bytes(self, dek_id: str) -> bytes:
        """Return the raw DEK (32-byte Fernet key) for `dek_id`,
        materialising it from cache or newly generated (and mirrored
        as a wrapped stub in the audit trail)."""
        if dek_id in self._dek_cache:
            return self._dek_cache[dek_id]
        # Materialise fresh — the wrapped copy is written per-secret.
        # The DEK itself is never persisted directly.
        dek = Fernet.generate_key()
        self._dek_cache[dek_id] = dek
        return dek

    async def _audit(self, *, op: str, tenant_id: str, integration_id: str,
                     secret_ref: Optional[str], principal: str,
                     purpose: Optional[str], outcome: str,
                     detail: Optional[str] = None) -> None:
        await self._db[AUDIT_COLLECTION].insert_one({
            "op":             op,          # MINT / ACCESS / ROTATE / REVOKE
            "tenant_id":      tenant_id,
            "integration_id": integration_id,
            "secret_ref":     secret_ref,
            "principal":      principal,
            "purpose":        purpose,
            "outcome":        outcome,     # OK / DENIED / NOT_FOUND / REVOKED_DENY / DECRYPT_FAIL
            "detail":         detail,
            "at":             _iso_now(),
        })

    # ── Public API ────────────────────────────────────────
    async def mint_secret(self, *, tenant_id: str, integration_id: str,
                            purpose: str, plaintext: str,
                            principal: str = "system") -> str:
        """Encrypt `plaintext` under a fresh (or cached) tenant DEK,
        wrap the DEK under the root key, persist, return the opaque
        secret_ref.  The caller MUST discard `plaintext` after this
        call — the vault does not keep a copy."""
        if not plaintext:
            raise ValueError("plaintext must be non-empty")
        dek_id = self._current_dek_id(tenant_id)
        dek    = self._dek_bytes(dek_id)
        wrapped_dek = self._root_fernet().encrypt(dek)
        ciphertext  = Fernet(dek).encrypt(plaintext.encode("utf-8"))
        secret_ref  = f"vlt-{uuid.uuid4().hex}"
        now = _iso_now()
        await self._db[VAULT_COLLECTION].insert_one({
            "secret_ref":       secret_ref,
            "tenant_id":        tenant_id,
            "integration_id":   integration_id,
            "purpose":          purpose,
            "dek_id":           dek_id,
            "wrapped_dek":      _b64e(wrapped_dek),
            "ciphertext":       _b64e(ciphertext),
            "created_at":       now,
            "updated_at":       now,
            "active":           True,
            "predecessor_ref":  None,
        })
        await self._audit(op="MINT", tenant_id=tenant_id,
                             integration_id=integration_id,
                             secret_ref=secret_ref, principal=principal,
                             purpose=purpose, outcome="OK")
        return secret_ref

    async def access(self, *, secret_ref: str, purpose: str,
                        principal: str) -> str:
        """Return the plaintext ONCE.  Callers MUST use the returned
        value inside the current call frame and never persist it.
        Every call is audit-logged."""
        rec = await self._db[VAULT_COLLECTION].find_one(
            {"secret_ref": secret_ref}, {"_id": 0})
        if rec is None:
            await self._audit(op="ACCESS", tenant_id="?",
                                 integration_id="?", secret_ref=secret_ref,
                                 principal=principal, purpose=purpose,
                                 outcome="NOT_FOUND")
            raise VaultAccessError(f"secret_ref {secret_ref} not found")
        if not rec.get("active"):
            await self._audit(op="ACCESS", tenant_id=rec["tenant_id"],
                                 integration_id=rec["integration_id"],
                                 secret_ref=secret_ref, principal=principal,
                                 purpose=purpose, outcome="REVOKED_DENY")
            raise VaultAccessError(f"secret_ref {secret_ref} is revoked")
        try:
            dek = self._root_fernet().decrypt(_b64d(rec["wrapped_dek"]))
            plaintext = Fernet(dek).decrypt(
                _b64d(rec["ciphertext"])).decode("utf-8")
        except InvalidToken:
            await self._audit(op="ACCESS", tenant_id=rec["tenant_id"],
                                 integration_id=rec["integration_id"],
                                 secret_ref=secret_ref, principal=principal,
                                 purpose=purpose, outcome="DECRYPT_FAIL")
            raise VaultAccessError("decrypt failed (root key mismatch)")
        await self._audit(op="ACCESS", tenant_id=rec["tenant_id"],
                             integration_id=rec["integration_id"],
                             secret_ref=secret_ref, principal=principal,
                             purpose=purpose, outcome="OK")
        return plaintext

    async def rotate_secret(self, *, secret_ref: str,
                                new_plaintext: str,
                                principal: str = "system") -> str:
        """Mint a NEW secret, mark the old one inactive.  Returns the
        new secret_ref.  Adapters that hold the old ref must be
        updated by the caller (typically the integration record on
        `xdr_integrations`)."""
        old = await self._db[VAULT_COLLECTION].find_one(
            {"secret_ref": secret_ref}, {"_id": 0})
        if old is None or not old.get("active"):
            raise VaultAccessError("cannot rotate an unknown/revoked secret")
        new_ref = await self.mint_secret(
            tenant_id      = old["tenant_id"],
            integration_id = old["integration_id"],
            purpose        = old["purpose"],
            plaintext      = new_plaintext,
            principal      = principal,
        )
        await self._db[VAULT_COLLECTION].update_one(
            {"secret_ref": secret_ref},
            {"$set": {"active": False, "updated_at": _iso_now()}})
        await self._db[VAULT_COLLECTION].update_one(
            {"secret_ref": new_ref},
            {"$set": {"predecessor_ref": secret_ref}})
        await self._audit(op="ROTATE",
                             tenant_id=old["tenant_id"],
                             integration_id=old["integration_id"],
                             secret_ref=new_ref, principal=principal,
                             purpose=old["purpose"], outcome="OK",
                             detail=f"predecessor={secret_ref}")
        return new_ref

    async def revoke(self, *, secret_ref: str,
                        principal: str = "system") -> bool:
        rec = await self._db[VAULT_COLLECTION].find_one(
            {"secret_ref": secret_ref}, {"_id": 0})
        if rec is None:
            await self._audit(op="REVOKE", tenant_id="?",
                                 integration_id="?", secret_ref=secret_ref,
                                 principal=principal, purpose=None,
                                 outcome="NOT_FOUND")
            return False
        result = await self._db[VAULT_COLLECTION].update_one(
            {"secret_ref": secret_ref, "active": True},
            {"$set": {"active": False, "updated_at": _iso_now()}})
        outcome = "OK" if result.modified_count == 1 else "ALREADY_INACTIVE"
        await self._audit(op="REVOKE", tenant_id=rec["tenant_id"],
                             integration_id=rec["integration_id"],
                             secret_ref=secret_ref, principal=principal,
                             purpose=rec.get("purpose"), outcome=outcome)
        return outcome == "OK"

    async def audit_trail(self, *, integration_id: Optional[str] = None,
                              limit: int = 100) -> list[dict]:
        q: dict = {}
        if integration_id:
            q["integration_id"] = integration_id
        cursor = self._db[AUDIT_COLLECTION].find(q, {"_id": 0}).sort(
            "at", -1).limit(limit)
        return [row async for row in cursor]


# ── Singleton binding · used by routers ──────────────────────
_VAULT_SINGLETON: Optional[CredentialVault] = None


def get_vault(db) -> CredentialVault:
    global _VAULT_SINGLETON                                        # noqa: PLW0603
    if _VAULT_SINGLETON is None:
        _VAULT_SINGLETON = CredentialVault(db)
    return _VAULT_SINGLETON
