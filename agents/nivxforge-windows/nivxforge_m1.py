#!/usr/bin/env python3
"""NivXForge M1 clean installer — isolated from the enterprise engine.

M1 installs ONE sensor onto ONE freshly imaged, exclusively administered
Windows 11 test VM. It is deliberately NOT an upgrade path: it creates, it
verifies, and it refuses. It never settles an enterprise transaction, never
replaces a predecessor and never adopts a resource it cannot prove it owns.

Scope contract: NIVXFORGE_M1_SCOPE_V3.md + AMENDMENT_A2_R4.
This module MUST NOT import nivxforge_transaction or nivxforge_scm_worker,
directly or transitively, and must not reference the enterprise service
entrypoints. `backend/tests/edr/test_m1_clean_install.py` asserts both
statically and from a fresh interpreter.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlparse

M1_VERSION = "1.0.0-m1"
SERVICE_NAME = "NivXForgeSensor"
LEGACY_TASK_NAME = "NivXForgeSensor"
OWNERSHIP_FILENAME = "m1-ownership.json"
CONFIG_FILENAME = "m1-config.json"
CONFIG_META_FILENAME = "m1-config.meta.json"
WORKER_FLAG = "--transaction-scm-worker"

# ── R1 ownership states ────────────────────────────────────────────
CREATE_INTENDED = "CREATE_INTENDED"
CREATE_CONFIRMED = "CREATE_CONFIRMED"
CREATE_OUTCOME_UNKNOWN = "CREATE_OUTCOME_UNKNOWN"
ACTIVATION_VERIFIED = "ACTIVATION_VERIFIED"
#: Only a CONFIRMED resource may ever be stopped, deleted or uninstalled.
OWNED_STATES = (CREATE_CONFIRMED, ACTIVATION_VERIFIED)
#: Any of these outstanding blocks a fresh install: the host is not clean and
#: the outcome of the earlier attempt is not known.
BLOCKING_STATES = (CREATE_INTENDED, CREATE_OUTCOME_UNKNOWN)

# ── R4/A2 service rights ───────────────────────────────────────────
SERVICE_CHANGE_CONFIG = 0x0002
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_PAUSE_CONTINUE = 0x0040
SERVICE_USER_DEFINED_CONTROL = 0x0100
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008
SERVICE_INTERROGATE = 0x0080
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
STANDARD_RIGHTS_READ = READ_CONTROL
STANDARD_RIGHTS_WRITE = READ_CONTROL
STANDARD_RIGHTS_EXECUTE = READ_CONTROL
SERVICE_ALL_ACCESS = 0xF01FF
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000

#: The service GENERIC_MAPPING. ACE masks are resolved through this BEFORE
#: any comparison: AccessCheck does not map generic bits carried in an ACE.
GENERIC_MAPPING = {
    GENERIC_READ: (STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG
                   | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE
                   | SERVICE_ENUMERATE_DEPENDENTS),
    GENERIC_WRITE: STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG,
    GENERIC_EXECUTE: (STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP
                      | SERVICE_PAUSE_CONTINUE
                      | SERVICE_USER_DEFINED_CONTROL),
    GENERIC_ALL: SERVICE_ALL_ACCESS,
}
DANGEROUS_RIGHTS = {
    "SERVICE_CHANGE_CONFIG": SERVICE_CHANGE_CONFIG,
    "SERVICE_START": SERVICE_START,
    "SERVICE_STOP": SERVICE_STOP,
    "SERVICE_PAUSE_CONTINUE": SERVICE_PAUSE_CONTINUE,
    "SERVICE_USER_DEFINED_CONTROL": SERVICE_USER_DEFINED_CONTROL,
    "DELETE": DELETE,
    "WRITE_DAC": WRITE_DAC,
    "WRITE_OWNER": WRITE_OWNER,
}
SID_LOCAL_SYSTEM = "S-1-5-18"
SID_ADMINISTRATORS = "S-1-5-32-544"
#: The ONLY trustees that may hold a dangerous right, compared by SID.
APPROVED_TRUSTEES = (SID_LOCAL_SYSTEM, SID_ADMINISTRATORS)
#: Logon-session and well-known group SIDs an ACL walk for one account would
#: not reflect; the token-aware context must carry them explicitly.
REQUIRED_CONTEXT_SIDS = ("S-1-5-11", "S-1-5-4", "S-1-1-0", "S-1-5-32-545")
ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1
#: An inherit-only ACE does not apply to the object that carries it. It is
#: still load-bearing for CHILDREN, which is why every directory M1 creates
#: carries a PROTECTED descriptor applied at creation and is re-verified in
#: `owned` role afterwards, instead of being trusted to inherit safely.
INHERIT_ONLY_ACE = 0x08
SE_DACL_PRESENT = 0x0004
SE_DACL_PROTECTED = 0x1000

# ── P1-4 · filesystem rights, mapping and trustee policy ───────────
FILE_READ_DATA = 0x0001
FILE_WRITE_DATA = 0x0002                      # for a directory: add file
FILE_APPEND_DATA = 0x0004                     # for a directory: add subdir
FILE_READ_EA = 0x0008
FILE_WRITE_EA = 0x0010
FILE_EXECUTE = 0x0020                         # for a directory: traverse
FILE_DELETE_CHILD = 0x0040
FILE_READ_ATTRIBUTES = 0x0080
FILE_WRITE_ATTRIBUTES = 0x0100
SYNCHRONIZE = 0x00100000
FILE_GENERIC_READ = (READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES
                     | FILE_READ_EA | SYNCHRONIZE)
FILE_GENERIC_WRITE = (READ_CONTROL | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES
                      | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE)
FILE_GENERIC_EXECUTE = (READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE
                        | SYNCHRONIZE)
FILE_ALL_ACCESS = 0x1F01FF
FILE_GENERIC_MAPPING = {
    GENERIC_READ: FILE_GENERIC_READ,
    GENERIC_WRITE: FILE_GENERIC_WRITE,
    GENERIC_EXECUTE: FILE_GENERIC_EXECUTE,
    GENERIC_ALL: FILE_ALL_ACCESS,
}
#: Rights by which a non-administrator could REPLACE, REDIRECT or RE-PERMISSION
#: an existing child of this directory. Applied to every ancestor of a
#: protected path.
DANGEROUS_ANCESTOR_RIGHTS = {
    "FILE_WRITE_DATA": FILE_WRITE_DATA,
    "FILE_DELETE_CHILD": FILE_DELETE_CHILD,
    "DELETE": DELETE,
    "WRITE_DAC": WRITE_DAC,
    "WRITE_OWNER": WRITE_OWNER,
}
#: Everything above PLUS creation inside the object itself. Applied to the
#: directories and files M1 owns.
#:
#: FILE_APPEND_DATA is deliberately NOT dangerous on an ANCESTOR: the default
#: Windows `C:\` DACL grants Authenticated Users "create folders / append
#: data" on that folder only, which permits creating a NEW subdirectory but
#: not replacing an existing one. Treating it as dangerous there would refuse
#: every default Windows 11 host while protecting nothing, because M1's own
#: directory creation is CREATE_NEW and refuses an existing directory. On an
#: OWNED object it IS dangerous, because content could be planted inside it.
DANGEROUS_OWNED_RIGHTS = {**DANGEROUS_ANCESTOR_RIGHTS,
                          "FILE_APPEND_DATA": FILE_APPEND_DATA,
                          "FILE_WRITE_EA": FILE_WRITE_EA,
                          "FILE_WRITE_ATTRIBUTES": FILE_WRITE_ATTRIBUTES}
#: TrustedInstaller owns much of a default Windows installation; it is a
#: protected OS principal, not a user-controllable trustee.
SID_TRUSTED_INSTALLER = ("S-1-5-80-956008885-3418522649-1831038044"
                         "-1853292631-2271478464")
APPROVED_PATH_OWNERS = (SID_LOCAL_SYSTEM, SID_ADMINISTRATORS,
                        SID_TRUSTED_INSTALLER)
#: Applied AT CREATION, with an EXPLICIT owner and group. Without `O:BA` the
#: object is owned by its creator — the administrator's user account on a
#: default host — and an owner holds WRITE_DAC implicitly, which the owned-role
#: verdict refuses. `P` blocks the inherited "Modify for Authenticated Users on
#: subfolders and files" that `C:\` grants by default.
_PROTECTED_DIR_SDDL = "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
_PROTECTED_FILE_SDDL = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)"
#: ancestor — a path M1 does not own and must only prove cannot be hijacked.
#: file     — a file whose CONTENT must not be attacker-controllable.
#: owned    — a directory M1 created, which must additionally be PROTECTED
#:            against inheritance, because `C:\` grants Authenticated Users
#:            Modify on "subfolders and files only" by default.
ROLE_ANCESTOR = "ancestor"
ROLE_FILE = "file"
ROLE_OWNED = "owned"

# ── G3-B3 · the two authorization contexts M1 actually runs in ─────
#: installer — an ELEVATED INTERACTIVE administrator session. A filtered
#:             non-administrator probe token can be derived from the caller's
#:             own token, so both A2 mechanisms are available.
#: service   — LocalSystem under the SCM. S-1-5-18 carries neither INTERACTIVE
#:             nor Users, and membership must never be manufactured, so the
#:             probe principal is built with Authz FROM A SID instead.
AUTH_INSTALLER = "installer-elevated-interactive"
AUTH_SERVICE = "service-localsystem"

# ── G3-B2 · tri-state path classification ──────────────────────────
PATH_ABSENT = "ABSENT"
PATH_DIRECTORY = "DIRECTORY"
PATH_FILE = "FILE"
PATH_REPARSE = "REPARSE"
PATH_UNKNOWN = "UNKNOWN"
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
ERROR_SUCCESS = 0
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_NAME = 123
ERROR_BAD_NETPATH = 53
ERROR_NOT_READY = 21
#: Only these two mean "this name does not exist". Everything else — access
#: denied, device not ready, a malformed name — is UNKNOWN and refuses.
ABSENT_ERRORS = (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND)
_RIGHTS_FOR_ROLE = {ROLE_ANCESTOR: DANGEROUS_ANCESTOR_RIGHTS,
                    ROLE_FILE: DANGEROUS_OWNED_RIGHTS,
                    ROLE_OWNED: DANGEROUS_OWNED_RIGHTS}

# ── P0-2 · service start types ─────────────────────────────────────
SERVICE_DISABLED = 4
SERVICE_DEMAND_START = 3
SERVICE_AUTO_START = 2
#: SCM state codes used for the running/stopped verdicts.
SERVICE_RUNNING = 4
SERVICE_STOPPED = 1

_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL",
                   *(f"COM{d}" for d in range(1, 10)),
                   *(f"LPT{d}" for d in range(1, 10))}
_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$")


class M1Error(RuntimeError):
    """A refusal. Carries a stable code so tests assert behaviour, not text."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest()


def canonical_record(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


# ── B1 · M1-local payload validation ───────────────────────────────
def _reject_component(part: str) -> str | None:
    if part in ("", ".", ".."):
        return "traversal or empty component"
    if ":" in part:
        return "alternate data stream or drive qualifier"
    if part != part.rstrip(". "):
        return "trailing dot or space"
    if part.split(".")[0].upper() in _RESERVED_NAMES:
        return "reserved device name"
    return None


def payload_members(manifest: dict) -> list[str]:
    return sorted(manifest)


def m1_payload_check(bundle_root, dest_root, manifest: dict, host) -> dict:
    """Validate a frozen payload against its manifest. No engine imports.

    Checks canonical member names, the EXACT expected file set (no missing
    and no unexpected member), per-file size and SHA-256, and refuses any
    reparse point in the destination ancestry.
    """
    bundle_root = Path(bundle_root)
    dest_root = Path(dest_root)
    for part in dest_root.parts[1:]:
        problem = _reject_component(part)
        if problem:
            raise M1Error("PAYLOAD_PATH_UNSAFE",
                          f"destination component {part!r}: {problem}")
    #: Re-checked HERE, after the destination was created, as the
    #: time-of-use counterpart to the time-of-check walk in
    #: `clean_host_report`: a link introduced in between is caught before any
    #: payload byte is written. UNKNOWN refuses.
    for ancestor in host.path_ancestry(dest_root):
        linked = host.is_reparse_point(ancestor)
        if linked is None:
            raise M1Error("PAYLOAD_PATH_UNSAFE",
                          f"cannot classify destination ancestor {ancestor}")
        if linked:
            raise M1Error("PAYLOAD_PATH_UNSAFE",
                          f"reparse point in destination ancestry: {ancestor}")
    for member in manifest:
        if PureWindowsPath(member).is_absolute() or member.startswith("/"):
            raise M1Error("PAYLOAD_PATH_UNSAFE", f"absolute member {member!r}")
        for part in PurePosixPath(member.replace("\\", "/")).parts:
            problem = _reject_component(part)
            if problem:
                raise M1Error("PAYLOAD_PATH_UNSAFE",
                              f"member {member!r} component {part!r}: {problem}")
    present = sorted(
        str(p.relative_to(bundle_root)).replace("\\", "/")
        for p in bundle_root.rglob("*") if p.is_file())
    expected = payload_members(manifest)
    missing = [m for m in expected if m not in present]
    unexpected = [m for m in present if m not in manifest]
    if missing:
        raise M1Error("PAYLOAD_INCOMPLETE", f"missing members: {missing}")
    if unexpected:
        raise M1Error("PAYLOAD_UNEXPECTED_FILE",
                      f"unexpected members: {unexpected}")
    for member, want in manifest.items():
        source = bundle_root / member
        size = source.stat().st_size
        if size != want["size"]:
            raise M1Error("PAYLOAD_SIZE_MISMATCH",
                          f"{member}: {size} != {want['size']}")
        got = file_digest(source)
        if got != want["sha256"]:
            raise M1Error("PAYLOAD_DIGEST_MISMATCH",
                          f"{member}: {got} != {want['sha256']}")
    return {"members": len(expected), "root": str(dest_root)}


# ── B6/R6 · protected non-production configuration ─────────────────
class M1Config:
    __slots__ = ("origin", "tenant_id", "state_dir", "install_dir",
                 "service_exe", "service_args", "certificate_policy",
                 "config_path", "config_digest", "metadata", "interval")

    def __init__(self, raw: dict, path: Path, digest: str, metadata: dict):
        self.config_path = path
        self.config_digest = digest
        self.metadata = metadata
        self.origin = raw["origin"]
        self.tenant_id = raw["tenant_id"]
        self.state_dir = Path(raw["state_dir"])
        self.install_dir = Path(raw["install_dir"])
        self.service_exe = raw["service_exe"]
        self.service_args = list(raw["service_args"])
        self.certificate_policy = raw["certificate_policy"]
        self.interval = int(raw.get("interval", 30))

    def as_record(self) -> dict:
        return {"origin": self.origin, "tenant_id": self.tenant_id,
                "state_dir": str(self.state_dir),
                "install_dir": str(self.install_dir),
                "config_digest": self.config_digest}


_REQUIRED_CONFIG_KEYS = ("origin", "tenant_id", "state_dir", "install_dir",
                         "service_exe", "service_args", "certificate_policy")


def load_config(path, host) -> M1Config:
    """Load, protect-verify and validate the pre-provisioned M1 configuration.

    Trust comes from the DACL and the ancestry, verified by readback. The
    digest only detects accidental drift and is never presented as
    protection against a privileged attacker.
    """
    path = Path(path)
    if not host.is_file(path):
        raise M1Error("CONFIG_ABSENT", f"no M1 configuration at {path}")
    #: The configuration file must EXIST, so its whole chain must exist and
    #: be verified; nothing here is a fresh destination.
    ancestry = ancestry_report(path, host, leaf_must_be_absent=False,
                               leaf_is_file=True)
    if ancestry["problems"]:
        raise M1Error("CONFIG_ANCESTRY_UNSAFE",
                      f"configuration ancestry: {ancestry['problems']}")
    file_acl = host.file_security(path)
    if file_acl is None:
        raise M1Error("CONFIG_ACL_UNKNOWN", f"cannot read security of {path}")
    if file_acl.get("nonadmin_writable"):
        raise M1Error("CONFIG_ACL_UNSAFE",
                      f"{path} is writable by a non-administrator")
    body = host.read_bytes(path)
    digest = _digest_bytes(body)
    try:
        raw = json.loads(body)
    except ValueError as ex:
        raise M1Error("CONFIG_MALFORMED", f"{path}: {ex}") from None
    missing = [k for k in _REQUIRED_CONFIG_KEYS if not raw.get(k)]
    if missing:
        raise M1Error("CONFIG_INCOMPLETE", f"missing keys: {missing}")
    parsed = urlparse(raw["origin"])
    if parsed.scheme != "https":
        raise M1Error("CONFIG_ORIGIN_NOT_HTTPS",
                      f"origin {raw['origin']!r} is not https")
    if not parsed.netloc:
        raise M1Error("CONFIG_ORIGIN_INVALID", f"origin {raw['origin']!r}")
    if raw["certificate_policy"] != "windows-default":
        raise M1Error("CONFIG_CERT_POLICY",
                      "only 'windows-default' certificate verification is "
                      "approved for M1; verification is never disabled")
    meta_path = path.with_name(CONFIG_META_FILENAME)
    metadata: dict = {}
    if host.is_file(meta_path):
        meta_acl = host.file_security(meta_path)
        if meta_acl is None or meta_acl.get("nonadmin_writable"):
            raise M1Error("CONFIG_ACL_UNSAFE",
                          f"{meta_path} is unreadable or unprotected")
        metadata = json.loads(host.read_bytes(meta_path))
        if metadata.get("config_digest") not in (None, digest):
            raise M1Error("CONFIG_DIGEST_DRIFT",
                          "configuration does not match its recorded digest")
    return M1Config(raw, path, digest, metadata)


# ── R1/B3 · ownership record ───────────────────────────────────────
class Ownership:
    """Durable, digest-enveloped record of resources THIS attempt created.

    It lives in the administrator pre-provisioned configuration root, so a
    record exists before the first installer-created directory and no root
    ever has to be adopted on trust.
    """

    def __init__(self, path, host):
        self.path = Path(path)
        self.host = host

    def exists(self) -> bool:
        return self.host.is_file(self.path)

    def create(self, install_id: str, config: M1Config) -> dict:
        record = {"schema": 1, "install_id": install_id,
                  "created_at": self.host.now_utc(),
                  "config": config.as_record(), "resources": {},
                  "history": []}
        self.host.write_new_file(self.path, self._envelope(record))
        return record

    def read(self) -> dict:
        body = self.host.read_bytes(self.path)
        try:
            record = json.loads(body)
        except ValueError:
            raise M1Error("OWNERSHIP_TORN",
                          f"{self.path} is unparseable; refusing") from None
        envelope = record.pop("envelope", None)
        if envelope != _digest_bytes(canonical_record(record)):
            raise M1Error("OWNERSHIP_TORN",
                          f"{self.path} failed its integrity envelope")
        return record

    def _envelope(self, record: dict) -> bytes:
        body = dict(record)
        body.pop("envelope", None)
        body["envelope"] = _digest_bytes(canonical_record(body))
        return json.dumps(body, indent=2, sort_keys=True).encode()

    def save(self, record: dict) -> None:
        #: Replacement of ALREADY OWNED metadata, deliberately a different
        #: operation from the no-overwrite creation above.
        self.host.replace_file(self.path, self._envelope(record))

    def mark(self, record: dict, resource: str, state: str,
             evidence: dict | None = None) -> dict:
        entry = {"resource": resource, "state": state,
                 "at": self.host.now_utc(), "evidence": evidence or {}}
        record["resources"][resource] = entry
        record["history"].append(entry)
        self.save(record)
        return record

    def blocking(self, record: dict) -> list[str]:
        return sorted(name for name, entry in record["resources"].items()
                      if entry["state"] in BLOCKING_STATES)

    def owns(self, record: dict, resource: str) -> bool:
        entry = record["resources"].get(resource)
        return bool(entry and entry["state"] in OWNED_STATES)


# ── M1-03 · fail-closed clean-host verification ────────────────────
PROBE_ABSENT, PROBE_PRESENT, PROBE_UNKNOWN = "ABSENT", "PRESENT", "UNKNOWN"


def clean_host_report(config: M1Config, host) -> dict:
    """Tri-state probes. PRESENT or UNKNOWN both refuse; UNKNOWN is never
    read as ABSENT, and a non-Windows host answers UNKNOWN for every
    Windows-only probe."""
    probes: dict[str, dict] = {}
    ancestry_problems: list[str] = []

    def record(name, state, detail=""):
        probes[name] = {"state": state, "detail": detail}

    state, detail = host.service_lookup(SERVICE_NAME)
    record("service", state, detail)
    record("scheduled_task", *host.scheduled_task_lookup(LEGACY_TASK_NAME))
    workers = host.worker_processes()
    if workers is None:
        record("live_worker", PROBE_UNKNOWN, "process enumeration unavailable")
    else:
        record("live_worker", PROBE_PRESENT if workers else PROBE_ABSENT,
               ",".join(str(p) for p in workers))
    for name, path in (("install_dir", config.install_dir),
                       ("state_dir", config.state_dir)):
        #: A fresh destination is EXPECTED to be absent: verified absence is
        #: the normal, clean case and is no longer mistaken for an unreadable
        #: path (G3-B2). Its existing ancestors are still fully verified.
        report = ancestry_report(path, host, leaf_must_be_absent=True)
        if report["problems"]:
            record(name, PROBE_PRESENT, ";".join(report["problems"]))
        else:
            record(name, PROBE_ABSENT, f"{path} verified absent")
        ancestry_problems.extend(report["problems"])
    for name, path in (("prior_identity", config.state_dir / "identity.json"),
                       ("enterprise_records",
                        config.install_dir / "operations")):
        present = host.path_exists(path)
        record(name, PROBE_UNKNOWN if present is None
               else (PROBE_PRESENT if present else PROBE_ABSENT), str(path))
    record("path_ancestry",
           PROBE_PRESENT if ancestry_problems else PROBE_ABSENT,
           ";".join(ancestry_problems))
    refusals = [name for name, probe in probes.items()
                if probe["state"] != PROBE_ABSENT]
    return {"probes": probes, "refusals": sorted(refusals),
            "clean": not refusals}


# ── R4 + A2 · service security verdict ─────────────────────────────
def map_generic(mask: int, mapping: dict | None = None) -> int:
    """Resolve generic bits through an object-type GENERIC_MAPPING.

    AccessCheck does not map generic bits carried INSIDE an ACE, so every
    mask is resolved here before any comparison and before the descriptor is
    handed to the OS.
    """
    mapping = GENERIC_MAPPING if mapping is None else mapping
    resolved = mask & 0x0FFFFFFF
    for generic, specific in mapping.items():
        if mask & generic:
            resolved |= specific
    return resolved


def _rights_in(mask: int, table: dict | None = None) -> list[str]:
    table = DANGEROUS_RIGHTS if table is None else table
    return sorted(name for name, bit in table.items() if mask & bit)


def ace_inspection(descriptor: dict) -> list[str]:
    """A2 check 1 — exhaustive inspection of every access-allow ACE.

    A dangerous right may be allowed ONLY to LocalSystem or Administrators,
    compared by SID. Nesting cannot hide a grant: the ACE is rejected on its
    trustee. Anything not fully understood refuses.
    """
    problems: list[str] = []
    if descriptor.get("dacl_present") is False or descriptor.get("dacl") is None:
        return ["NULL DACL grants all access to everyone"]
    if descriptor.get("malformed"):
        return ["malformed or truncated ACL"]
    owner = descriptor.get("owner")
    if owner not in APPROVED_TRUSTEES:
        problems.append(f"owner {owner!r} is not SYSTEM or Administrators")
    if not descriptor.get("protected", False):
        problems.append("DACL is not protected against inheritance")
    granted: dict[str, int] = {}
    for ace in descriptor["dacl"]:
        ace_type = ace.get("type")
        trustee = ace.get("sid")
        if ace_type not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
            problems.append(f"unsupported ACE type {ace_type!r}")
            continue
        if not isinstance(trustee, str) or not _SID_RE.match(trustee):
            problems.append(f"unparseable trustee {trustee!r}")
            continue
        mask = ace.get("mask")
        if not isinstance(mask, int) or mask < 0:
            problems.append(f"unresolvable mask {mask!r} for {trustee}")
            continue
        if ace_type == ACCESS_DENIED_ACE_TYPE:
            #: Recorded, never used to justify a dangerous allow: canonical
            #: ordering is not guaranteed on a descriptor read back from the
            #: SCM, so the descriptor is refused and rewritten instead.
            continue
        resolved = map_generic(mask)
        if trustee in APPROVED_TRUSTEES:
            granted[trustee] = granted.get(trustee, 0) | resolved
            continue
        dangerous = _rights_in(resolved)
        if dangerous:
            problems.append(f"{trustee} is allowed {','.join(dangerous)}")
    for required in APPROVED_TRUSTEES:
        if granted.get(required, 0) & SERVICE_ALL_ACCESS != SERVICE_ALL_ACCESS:
            problems.append(f"{required} lacks SERVICE_ALL_ACCESS")
    return problems


def token_access_verdict(descriptor: dict, host) -> list[str]:
    """A1/A2 check 2 — token-aware effective access for a non-administrator.

    Each dangerous right is probed INDIVIDUALLY; a bulk SERVICE_ALL_ACCESS
    query can report denied while single rights are granted.
    """
    problems: list[str] = []
    if descriptor.get("owner") is None or descriptor.get("group") is None:
        return ["descriptor lacks owner or group; AccessCheck would fail "
                "with ERROR_INVALID_SECURITY_DESCR (1338)"]
    context = host.access_context()
    if context is None:
        return ["no token or Authz context could be built"]
    missing = [sid for sid in REQUIRED_CONTEXT_SIDS
               if sid not in context.get("sids", ())]
    if missing:
        return [f"access context is incomplete, missing {missing}"]
    for name, bit in DANGEROUS_RIGHTS.items():
        granted = host.access_check(descriptor, context, bit,
                                    GENERIC_MAPPING)
        if granted is None:
            problems.append(f"access evaluation for {name} was indeterminate")
        elif granted:
            problems.append(f"non-administrator context is granted {name}")
    return problems


def service_security_verdict(descriptor: dict, host) -> dict:
    """Both checks must pass; either failing or unevaluable refuses."""
    problems = ace_inspection(descriptor) + token_access_verdict(descriptor, host)
    return {"safe": not problems, "problems": problems}


def m1_service_descriptor() -> dict:
    """The descriptor M1 applies: SYSTEM and Administrators only."""
    return {"owner": SID_ADMINISTRATORS, "group": SID_ADMINISTRATORS,
            "protected": True, "dacl_present": True,
            "dacl": [{"type": ACCESS_ALLOWED_ACE_TYPE, "sid": SID_LOCAL_SYSTEM,
                      "mask": SERVICE_ALL_ACCESS},
                     {"type": ACCESS_ALLOWED_ACE_TYPE,
                      "sid": SID_ADMINISTRATORS, "mask": SERVICE_ALL_ACCESS},
                     {"type": ACCESS_ALLOWED_ACE_TYPE, "sid": "S-1-5-32-545",
                      "mask": (SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS
                               | SERVICE_INTERROGATE
                               | SERVICE_ENUMERATE_DEPENDENTS
                               | READ_CONTROL)}]}


# ── P1-4 · filesystem security verdict ─────────────────────────────
def filesystem_ace_inspection(descriptor: dict, role: str) -> list[str]:
    """Exhaustive allow-ACE inspection for a path, by the same rules as the
    service descriptor: FILE generic mapping, SID comparison, owner control,
    and refusal of anything not fully understood.

    `role` selects the dangerous-right table. ACE ORDERING is deliberately not
    relied upon: a deny ACE is never credited as cancelling a dangerous allow,
    because canonical order is not guaranteed on a descriptor read back from
    the filesystem. The allow ACE alone is disqualifying.
    """
    if descriptor.get("malformed"):
        return ["malformed or truncated ACL"]
    if not descriptor.get("dacl_present", True) or descriptor.get("dacl") is None:
        return ["NULL DACL grants all access to everyone"]
    problems: list[str] = []
    owner = descriptor.get("owner")
    if owner not in APPROVED_PATH_OWNERS:
        problems.append(f"owner {owner!r} is not SYSTEM, Administrators or "
                        "TrustedInstaller, and an owner holds WRITE_DAC "
                        "implicitly")
    if role == ROLE_OWNED and not descriptor.get("protected", False):
        problems.append("DACL is not protected against inheritance")
    table = _RIGHTS_FOR_ROLE.get(role)
    if table is None:
        return [f"unknown evaluation role {role!r}"]
    for ace in descriptor["dacl"]:
        ace_type = ace.get("type")
        trustee = ace.get("sid")
        flags = ace.get("flags", 0)
        if ace_type not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
            problems.append(f"unsupported ACE type {ace_type!r}")
            continue
        if not isinstance(trustee, str) or not _SID_RE.match(trustee):
            problems.append(f"unparseable trustee {trustee!r}")
            continue
        mask = ace.get("mask")
        if not isinstance(mask, int) or mask < 0:
            problems.append(f"unresolvable mask {mask!r} for {trustee}")
            continue
        if not isinstance(flags, int) or flags < 0:
            problems.append(f"unparseable ACE flags {flags!r} for {trustee}")
            continue
        if ace_type == ACCESS_DENIED_ACE_TYPE:
            continue
        if flags & INHERIT_ONLY_ACE:
            #: Does not apply to THIS object. It would apply to children, and
            #: that is exactly why an owned directory must also be PROTECTED.
            continue
        if trustee in APPROVED_TRUSTEES:
            continue
        dangerous = _rights_in(map_generic(mask, FILE_GENERIC_MAPPING), table)
        if dangerous:
            problems.append(f"{trustee} is allowed {','.join(dangerous)}")
    return problems


def filesystem_token_verdict(descriptor: dict, role: str, host) -> list[str]:
    """Token-aware effective access for the same path, probed one right at a
    time against a genuinely non-administrator context."""
    if descriptor.get("owner") is None or descriptor.get("group") is None:
        return ["descriptor lacks owner or group; AccessCheck would fail "
                "with ERROR_INVALID_SECURITY_DESCR (1338)"]
    context = host.access_context()
    if context is None:
        return ["no token or Authz context could be built"]
    missing = [sid for sid in REQUIRED_CONTEXT_SIDS
               if sid not in context.get("sids", ())]
    if missing:
        return [f"access context is incomplete, missing {missing}"]
    table = _RIGHTS_FOR_ROLE.get(role)
    if table is None:
        return [f"unknown evaluation role {role!r}"]
    problems: list[str] = []
    for name, bit in table.items():
        granted = host.access_check(descriptor, context, bit,
                                    FILE_GENERIC_MAPPING)
        if granted is None:
            problems.append(f"access evaluation for {name} was indeterminate")
        elif granted:
            problems.append(f"non-administrator context is granted {name}")
    return problems


def path_security_verdict(descriptor, role: str, host) -> dict | None:
    """None means UNKNOWN. Every caller treats UNKNOWN as unsafe.

    `nonadmin_writable` is true for ANY problem, including an unevaluable
    one, so the existing fail-closed call sites need no new vocabulary.
    """
    if descriptor is None:
        return None
    problems = (filesystem_ace_inspection(descriptor, role)
                + filesystem_token_verdict(descriptor, role, host))
    return {"nonadmin_writable": bool(problems), "problems": problems,
            "role": role, "owner": descriptor.get("owner")}


def normalise_descriptor(control: int, owner, group, dacl, sid_text) -> dict:
    """Pure normalisation of a Windows descriptor into the verdict dict.

    Separated from the Win32 read so the decoding rules — what counts as
    malformed, how an unknown ACE layout is recorded, how a NULL DACL is
    distinguished from an empty one — are verifiable off Windows.
    """
    parsed = {"owner": sid_text(owner), "group": sid_text(group),
              "protected": bool(control & SE_DACL_PROTECTED),
              "dacl_present": bool(control & SE_DACL_PRESENT)}
    if dacl is None or not parsed["dacl_present"]:
        parsed["dacl"] = None
        return parsed
    aces: list[dict] = []
    try:
        for index in range(dacl.GetAceCount()):
            entry = dacl.GetAce(index)
            ace_type, flags = int(entry[0][0]), int(entry[0][1])
            if ace_type not in (ACCESS_ALLOWED_ACE_TYPE,
                                ACCESS_DENIED_ACE_TYPE):
                #: Object and callback ACEs carry a different layout. The TYPE
                #: is recorded so the inspection refuses; the remaining fields
                #: are never guessed.
                aces.append({"type": ace_type, "flags": flags,
                             "mask": None, "sid": None})
                continue
            sid = sid_text(entry[2])
            if sid is None:
                return {**parsed, "malformed": True, "dacl": aces}
            aces.append({"type": ace_type, "flags": flags,
                         "mask": int(entry[1]), "sid": sid})
    except Exception:                                        # noqa: BLE001
        return {**parsed, "malformed": True, "dacl": aces}
    parsed["dacl"] = aces
    return parsed


# ── G3-01 · the AccessCheck contract, read correctly ───────────────
def descriptor_to_sddl(descriptor: dict, mapping: dict) -> str | None:
    """Render a parsed descriptor as SDDL, with every generic bit RESOLVED.

    SDDL, because the only dependable way to obtain a VALID SELF-RELATIVE
    security descriptor for `AccessCheck` is
    `ConvertStringSecurityDescriptorToSecurityDescriptorW`: a hand-assembled
    absolute descriptor is not valid input to the API and is a documented
    source of ERROR_INVALID_SECURITY_DESCR.

    Deny ACEs are emitted first so the ACL is in canonical order. Inherit-only
    ACEs are omitted because they do not apply to the object being evaluated.
    None means the descriptor cannot be rendered, which the caller reads as
    UNKNOWN.
    """
    if descriptor.get("malformed") or descriptor.get("dacl") is None:
        return None
    owner, group = descriptor.get("owner"), descriptor.get("group")
    for sid in (owner, group):
        if not isinstance(sid, str) or not _SID_RE.match(sid):
            return None
    entries: list[str] = []
    ordered = sorted(descriptor["dacl"],
                     key=lambda ace: ace.get("type") != ACCESS_DENIED_ACE_TYPE)
    for ace in ordered:
        ace_type = ace.get("type")
        if ace_type not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
            return None
        trustee, mask, flags = ace.get("sid"), ace.get("mask"), ace.get("flags", 0)
        if not isinstance(trustee, str) or not _SID_RE.match(trustee):
            return None
        if not isinstance(mask, int) or mask < 0:
            return None
        if not isinstance(flags, int) or flags < 0:
            return None
        if flags & INHERIT_ONLY_ACE:
            continue
        letter = "A" if ace_type == ACCESS_ALLOWED_ACE_TYPE else "D"
        entries.append(f"({letter};;0x{map_generic(mask, mapping):08x};;;"
                       f"{trustee})")
    protected = "P" if descriptor.get("protected") else ""
    return f"O:{owner}G:{group}D:{protected}" + "".join(entries)


def access_check_verdict(ok: bool, status, granted, wanted: int):
    """The three-way reading of the native AccessCheck contract.

    True  — the API SUCCEEDED and reported AccessStatus=TRUE with the
            requested rights in GrantedAccess.
    False — the API SUCCEEDED and reported AccessStatus=FALSE. This is the
            ONLY verified denial.
    None  — UNKNOWN. The API failed, or returned a result we do not
            understand. A failure is NEVER a denial: the documented cause of
            ERROR_ACCESS_DENIED from AccessCheck itself is a ClientToken
            without TOKEN_QUERY, which says nothing whatsoever about the
            descriptor being evaluated. Reading it as "denied" would report a
            restrictive descriptor on the strength of a broken call.
    """
    if ok is not True:
        return None
    if not isinstance(status, int) or not isinstance(granted, int):
        return None
    if not isinstance(wanted, int):
        return None
    if wanted <= 0 or wanted & 0xF0000000:
        #: A desired mask that is empty, or that still carries generic bits
        #: the API refuses to map, is not a question we can ask.
        return None
    if not status:
        #: Denied. The API sets GrantedAccess to zero in this case; a
        #: non-zero mask alongside a FALSE status is a result we do not
        #: understand, so it is UNKNOWN rather than a denial.
        return False if granted == 0 else None
    return True if granted & wanted == wanted else None


def authz_access_verdict(ok: bool, reply_error, granted, wanted: int):
    """The three-way reading of ONE AuthzAccessCheck RESULT.

    AuthzAccessCheck reports two separate things and the earlier wrapper
    collapsed them: the BOOL return says whether the evaluation RAN, and
    AUTHZ_ACCESS_REPLY.Error[i] is the status of THAT evaluation. Microsoft
    documents ERROR_ACCESS_DENIED in Error[i] as the ordinary result for a
    request the descriptor does not grant — a VERIFIED DENIAL, not a failure.
    Reading every non-zero Error as UNKNOWN made a correctly restrictive
    descriptor permanently unevaluable, so a legitimate LocalSystem service
    could never validate its configuration (G3-B3).

    True  — the call SUCCEEDED, Error is ERROR_SUCCESS and GrantedAccessMask
            carries every requested right.
    False — the call SUCCEEDED, Error is ERROR_ACCESS_DENIED and none of the
            requested rights are in GrantedAccessMask. The ONLY verified
            denial.
    None  — UNKNOWN: the call failed, the reply code is one we do not
            understand, or the code and the granted mask contradict each
            other. A failure is never converted into a denial.
    """
    if ok is not True:
        return None
    if not isinstance(reply_error, int) or isinstance(reply_error, bool):
        return None
    if not isinstance(granted, int) or isinstance(granted, bool):
        return None
    if not isinstance(wanted, int) or isinstance(wanted, bool):
        return None
    if reply_error < 0 or granted < 0:
        return None
    if wanted <= 0 or wanted & 0xF0000000:
        #: Empty, or still carrying generic bits the API refuses to map.
        return None
    overlap = granted & wanted
    if reply_error == ERROR_SUCCESS:
        #: ERROR_SUCCESS means the whole request was granted. A mask that does
        #: not carry it contradicts the code; that is not a denial we can
        #: trust, so it is UNKNOWN.
        return True if overlap == wanted else None
    if reply_error == ERROR_ACCESS_DENIED:
        #: Denied. Any requested bit still present in the mask contradicts the
        #: code and is UNKNOWN rather than a denial.
        return False if overlap == 0 else None
    #: Any other per-result code — ERROR_INVALID_SECURITY_DESCR,
    #: ERROR_PRIVILEGE_NOT_HELD, anything unforeseen — was not an evaluation
    #: we understand.
    return None


# ── G3-B2 · path classification and ancestry judgement ─────────────
def classify_attributes(attributes: int, error: int) -> str:
    """Pure reading of a GetFileAttributesW result.

    The API returns a DWORD. With ctypes' default `int` restype the sentinel
    0xFFFFFFFF arrives as -1, the equality test misses, and `-1 & 0x400` is
    truthy — so EVERY absent or inaccessible path was classified as a reparse
    point. The sentinel is compared as an unsigned value here and the error
    code decides what the sentinel MEANS.
    """
    if (attributes & 0xFFFFFFFF) == INVALID_FILE_ATTRIBUTES:
        return PATH_ABSENT if error in ABSENT_ERRORS else PATH_UNKNOWN
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        #: Reported as a reparse point even when it is also a directory: the
        #: link, not its target, is what matters here.
        return PATH_REPARSE
    return PATH_DIRECTORY if attributes & FILE_ATTRIBUTE_DIRECTORY else PATH_FILE


def ancestry_report(target, host, *, leaf_must_be_absent: bool,
                    leaf_is_file: bool = False) -> dict:
    """Classify every element of a path chain and judge the EXISTING ones.

    A fresh destination is EXPECTED to be absent. Verified absence is normal
    and is not a security problem; it is only a problem when the leaf must be
    absent and is not, or when something that DOES exist is unreadable,
    ambiguous, a reparse point or non-administrator writable.

    `problems` is empty only when every existing ancestor was positively
    verified.
    """
    leaf = str(Path(target))
    states: dict[str, str] = {}
    problems: list[str] = []
    for element in host.path_ancestry(target):
        key = str(element)
        state = host.path_state(element)
        states[key] = state
        if state == PATH_UNKNOWN:
            problems.append(f"unreadable:{key}")
            continue
        if state == PATH_REPARSE:
            #: A link anywhere in the chain allows the destination to be
            #: redirected after it was approved.
            problems.append(f"reparse:{key}")
            continue
        if key == leaf:
            if leaf_must_be_absent:
                if state != PATH_ABSENT:
                    problems.append(f"destination_present:{key}:{state}")
                continue
            if leaf_is_file:
                #: Its own DACL is verified separately by `file_security`.
                if state != PATH_FILE:
                    problems.append(f"not_a_file:{key}:{state}")
                continue
        if state == PATH_ABSENT:
            #: An absent INTERMEDIATE cannot be created by M1 —
            #: CreateDirectoryW does not build parents — and cannot be
            #: security-verified, so it is an impossible precondition, named
            #: here rather than surfacing later as WinError 3.
            problems.append(f"parent_absent:{key}")
            continue
        if state == PATH_FILE:
            problems.append(f"not_a_directory:{key}")
            continue
        security = host.directory_security(element, role=ROLE_ANCESTOR)
        if security is None:
            problems.append(f"unreadable:{key}")
        elif security.get("nonadmin_writable"):
            problems.append(f"nonadmin_writable:{key}")
    leaf_state = states.get(leaf, PATH_UNKNOWN)
    if leaf_must_be_absent and leaf_state == PATH_UNKNOWN:
        problems.append(f"destination_unknown:{leaf}")
    return {"states": states, "problems": problems, "leaf_state": leaf_state}


# ── G3-B1 · pure self-identification rule ──────────────────────────
def is_self_process(candidate: dict, own: dict, parent: dict | None) -> bool:
    """Is this matching process THIS installer (or its own bootloader)?

    Exclusion requires pid, creation timestamp AND image path to agree, so a
    reused pid cannot hide a competitor behind our number. The onefile
    bootloader runs the SAME executable as its child, so the verified parent
    is excluded too — but only when it really is our parent, really runs our
    image, and really started before us.
    """
    if not isinstance(candidate, dict) or not isinstance(own, dict):
        return False
    for field in ("pid", "created", "image"):
        if candidate.get(field) is None or own.get(field) is None:
            return False
    if (candidate["pid"] == own["pid"]
            and candidate["created"] == own["created"]
            and image_path_matches(candidate["image"], own["image"])):
        return True
    if not isinstance(parent, dict):
        return False
    for field in ("pid", "created", "image"):
        if parent.get(field) is None:
            return False
    return (candidate["pid"] == parent["pid"] == own.get("parent_pid")
            and candidate["created"] == parent["created"]
            and image_path_matches(candidate["image"], parent["image"])
            and image_path_matches(parent["image"], own["image"])
            and parent["created"] <= own["created"])


# ── P1-5 · pure process-exit and image comparison rules ────────────

def exit_verdict(before, now):
    """True / False / None, PID-reuse aware. None is UNKNOWN.

    `before` is the identity captured BEFORE the stop. A different creation
    timestamp means the number was reused and our process is gone; an equal
    one means it is still alive. An unknown either side is never an exit.
    """
    if before is None:
        return None
    if before == "ABSENT":
        return True
    if now is None:
        return None
    if now == "ABSENT":
        return True
    if not isinstance(before, dict) or not isinstance(now, dict):
        return None
    if before.get("created") is None or now.get("created") is None:
        return None
    return now["created"] != before["created"]


def image_path_matches(actual, expected) -> bool:
    """Windows paths are case-insensitive and may differ in separators.

    PureWindowsPath, not os.path: the comparison must follow WINDOWS rules
    even when this logic is exercised on another platform, and `os.path.normcase`
    is the identity function off Windows. `..` is deliberately NOT resolved —
    QueryFullProcessImageNameW returns a canonical path, so a traversal in
    either operand is treated as a mismatch.
    """
    if not actual or not expected:
        return False
    return (str(PureWindowsPath(str(actual))).rstrip("\\").lower()
            == str(PureWindowsPath(str(expected))).rstrip("\\").lower())


# ── install ────────────────────────────────────────────────────────
def _bin_path(config: M1Config) -> str:
    exe = config.service_exe
    quoted = f'"{exe}"' if " " in exe else exe
    return " ".join([quoted, *config.service_args])


# ── P1-3 · trusted payload provenance for the service image ────────
def resolve_service_binary(config: M1Config, manifest: dict) -> str:
    """The service image MUST be a member of the verified payload.

    Comparison is case-insensitive because the filesystem is: two manifest
    members differing only in case are AMBIGUOUS, not a match.
    """
    exe = PureWindowsPath(config.service_exe)
    install_dir = PureWindowsPath(str(config.install_dir))
    try:
        member = exe.relative_to(install_dir)
    except ValueError:
        raise M1Error("SERVICE_EXE_OUTSIDE_PAYLOAD",
                      f"the approved service image {config.service_exe!r} is "
                      f"not inside the install directory {install_dir}; M1 "
                      "never registers a binary it did not place and "
                      "verify") from None
    key = str(member).replace("\\", "/").lower()
    matches = [name for name in manifest
               if name.replace("\\", "/").lower() == key]
    if not matches:
        raise M1Error("SERVICE_EXE_NOT_IN_MANIFEST",
                      f"{key!r} has no manifest entry; the payload does not "
                      "attest the binary the service would run")
    if len(matches) > 1:
        raise M1Error("SERVICE_EXE_AMBIGUOUS",
                      f"{matches} differ only by case and the filesystem "
                      "cannot distinguish them")
    return matches[0]


def verify_installed_binary(config: M1Config, manifest: dict, host) -> dict:
    """Prove the ON-DISK service image is the attested one, after the copy.

    This is what stops an existing unverified binary from being executed: the
    registration and the activation both depend on this digest, and the same
    digest is compared again against the RUNNING image.
    """
    member = resolve_service_binary(config, manifest)
    want = manifest[member]
    target = Path(config.install_dir) / member
    if not host.is_file(target):
        raise M1Error("SERVICE_EXE_MISSING",
                      f"{target} is absent after payload delivery")
    acl = host.file_security(target, role=ROLE_FILE)
    if acl is None or acl.get("nonadmin_writable"):
        raise M1Error("SERVICE_EXE_UNPROTECTED",
                      f"the security of {target} is unsafe or unreadable: "
                      f"{None if acl is None else acl.get('problems')}")
    try:
        got = file_digest(target)
    except OSError as ex:
        raise M1Error("SERVICE_EXE_UNVERIFIABLE",
                      f"{target} cannot be read for hashing: {ex}") from None
    if got != want["sha256"]:
        raise M1Error("SERVICE_EXE_DIGEST_MISMATCH",
                      f"{target}: {got} != {want['sha256']}")
    return {"member": member, "sha256": got, "path": str(target)}


def m1_install(config_path, host, *, enroll=None, bundle_root=None,
               manifest=None, install_id=None) -> dict:
    """Clean-only installation. Every step is gated, recorded and refusable."""
    config = load_config(config_path, host)
    root = Path(config_path).parent
    ownership = Ownership(root / OWNERSHIP_FILENAME, host)
    if not host.is_dir(root):
        raise M1Error("BOOTSTRAP_ROOT_ABSENT",
                      f"the pre-provisioned M1 root {root} does not exist; "
                      "the installer never creates it")
    install_id = install_id or os.urandom(8).hex()
    if ownership.exists():
        record = ownership.read()
        blocking = ownership.blocking(record)
        if blocking:
            raise M1Error("PRIOR_ATTEMPT_UNRESOLVED",
                          "a previous attempt left resources in an "
                          f"unconfirmed state: {blocking}. Nothing will be "
                          "adopted or deleted automatically; operator "
                          "investigation is required.")
        raise M1Error("ALREADY_INSTALLED",
                      f"{ownership.path} records install "
                      f"{record['install_id']}; M1 is clean-install only")
    with host.exclusive_lock() as lock:
        if lock is None:
            raise M1Error("CONCURRENT_INSTALLER",
                          "another M1 installer owns this host")
        report = clean_host_report(config, host)
        if not report["clean"]:
            raise M1Error("HOST_NOT_CLEAN",
                          "refusing: " + "; ".join(
                              f"{name}={report['probes'][name]['state']}"
                              f"({report['probes'][name]['detail']})"
                              for name in report["refusals"]))
        record = ownership.create(install_id, config)
        for name, path in (("install_dir", config.install_dir),
                           ("state_dir", config.state_dir)):
            ownership.mark(record, name, CREATE_INTENDED, {"path": str(path)})
            try:
                host.create_directory_protected(path)
            except M1Error:
                ownership.mark(record, name, CREATE_OUTCOME_UNKNOWN,
                               {"path": str(path)})
                raise
            security = host.directory_security(path, role=ROLE_OWNED)
            if security is None or security.get("nonadmin_writable"):
                ownership.mark(record, name, CREATE_OUTCOME_UNKNOWN,
                               {"path": str(path)})
                raise M1Error("DIR_ACL_UNVERIFIED",
                              f"cannot verify the security of {path}: "
                              f"{None if security is None else security.get('problems')}")
            ownership.mark(record, name, CREATE_CONFIRMED,
                           {"path": str(path), "security": security})
        # ── P1-3 · trusted payload delivery, then binary provenance ──
        if bundle_root is None or manifest is None:
            raise M1Error("PAYLOAD_NOT_SUPPLIED",
                          "no attested payload was supplied; M1 never "
                          "registers a service against a binary it has not "
                          "delivered and hash-verified")
        m1_payload_check(bundle_root, config.install_dir, manifest, host)
        host.copy_payload(bundle_root, config.install_dir, manifest)
        binary = verify_installed_binary(config, manifest, host)
        ownership.mark(record, "payload", CREATE_CONFIRMED,
                       {"members": len(manifest), "service_image": binary})
        # ── enrollment (marker before the request; single attempt) ──
        ownership.mark(record, "enrollment", CREATE_INTENDED,
                       {"origin": config.origin})
        if enroll is None:
            raise M1Error("ENROLLMENT_NOT_SUPPLIED",
                          "no enrollment callable was provided")
        try:
            identity = enroll(config)
        except Exception as ex:                              # noqa: BLE001
            ownership.mark(record, "enrollment", CREATE_OUTCOME_UNKNOWN,
                           {"error": type(ex).__name__})
            raise
        ownership.mark(record, "enrollment", CREATE_CONFIRMED,
                       {"endpoint_id": identity.get("endpoint_id")})
        # ── service: create-only, and created DISABLED (P0-2) ──
        state, detail = host.service_lookup(SERVICE_NAME)
        if state != PROBE_ABSENT:
            raise M1Error("SERVICE_NOT_ABSENT",
                          f"service state {state} ({detail}); M1 never "
                          "stops, deletes or replaces a service")
        ownership.mark(record, "service", CREATE_INTENDED,
                       {"name": SERVICE_NAME})
        try:
            #: A service created DISABLED cannot be launched by the SCM, by a
            #: reboot or by an unprivileged `sc start`, so an interruption
            #: anywhere between here and the explicit authorization below
            #: leaves a registration that CANNOT run.
            host.service_create(SERVICE_NAME, _bin_path(config),
                                start_type=SERVICE_DISABLED)
        except M1Error:
            ownership.mark(record, "service", CREATE_OUTCOME_UNKNOWN,
                           {"name": SERVICE_NAME})
            raise
        qc = host.service_qc(SERVICE_NAME)
        if qc is None:
            ownership.mark(record, "service", CREATE_OUTCOME_UNKNOWN,
                           {"name": SERVICE_NAME})
            raise M1Error("SERVICE_UNVERIFIABLE",
                          "the created service cannot be read back")
        for field, expected, code in (
                ("bin_path", _bin_path(config), "SERVICE_IDENTITY_MISMATCH"),
                ("start_type_code", SERVICE_DISABLED, "SERVICE_NOT_DISABLED"),
                ("account", "LocalSystem", "SERVICE_ACCOUNT_MISMATCH")):
            if qc.get(field) != expected:
                ownership.mark(record, "service", CREATE_OUTCOME_UNKNOWN,
                               {field: qc.get(field)})
                raise M1Error(code,
                              f"the registered {field} is {qc.get(field)!r}, "
                              f"not the approved {expected!r}")
        ownership.mark(record, "service", CREATE_CONFIRMED,
                       {"name": SERVICE_NAME, "bin_path": qc.get("bin_path"),
                        "account": qc.get("account"),
                        "start_type": qc.get("start_type"),
                        "created_disabled": True,
                        "service_image": binary,
                        "install_id": install_id})
        # ── security applied and INDEPENDENTLY verified while DISABLED ──
        host.service_set_security(SERVICE_NAME, m1_service_descriptor())
        descriptor = host.service_security(SERVICE_NAME)
        if descriptor is None:
            raise M1Error("SERVICE_SD_UNREADABLE",
                          "the service security descriptor cannot be read "
                          "back; the service stays disabled")
        verdict = service_security_verdict(descriptor, host)
        if not verdict["safe"]:
            raise M1Error("SERVICE_SD_UNSAFE",
                          "refusing to authorize the service: "
                          f"{verdict['problems']}")
        # ── authorization: DEMAND first, so a crash before the image is
        #    verified still cannot produce an auto-starting service ──
        host.service_set_start_type(SERVICE_NAME, SERVICE_DEMAND_START)
        qc = host.service_qc(SERVICE_NAME)
        if qc is None or qc.get("start_type_code") != SERVICE_DEMAND_START:
            raise M1Error("SERVICE_AUTHORIZATION_UNVERIFIED",
                          "the start type could not be read back as demand")
        if qc.get("bin_path") != _bin_path(config):
            raise M1Error("SERVICE_IDENTITY_MISMATCH",
                          "the binPath changed while the service was being "
                          "authorized")
        after = host.service_security(SERVICE_NAME)
        if after is None or not service_security_verdict(after, host)["safe"]:
            raise M1Error("SERVICE_SD_UNSAFE",
                          "the security descriptor no longer verifies after "
                          "the start type was changed")
        host.service_start(SERVICE_NAME)
        image = host.verify_running_image(SERVICE_NAME, config.service_exe,
                                          expected_sha256=binary["sha256"])
        if image is None or image.get("verdict") != "MATCH":
            raise M1Error("SERVICE_IMAGE_UNVERIFIED",
                          f"running image verdict "
                          f"{None if image is None else image.get('verdict')}"
                          f"; detail {None if image is None else image.get('detail')}")
        #: Only a service whose descriptor, binary and RUNNING image have all
        #: been verified is ever made auto-start.
        host.service_set_start_type(SERVICE_NAME, SERVICE_AUTO_START)
        qc = host.service_qc(SERVICE_NAME)
        if qc is None or qc.get("start_type_code") != SERVICE_AUTO_START:
            raise M1Error("SERVICE_AUTOSTART_UNVERIFIED",
                          "the service is running but its start type could "
                          "not be read back as auto")
        ownership.mark(record, "service", ACTIVATION_VERIFIED,
                       {**record["resources"]["service"]["evidence"],
                        "image": image,
                        "start_type": qc.get("start_type"),
                        "config_digest": config.config_digest})
        return {"install_id": install_id, "service": SERVICE_NAME,
                "endpoint_id": identity.get("endpoint_id"),
                "state": ACTIVATION_VERIFIED, "image": image,
                "service_image": binary,
                "security": verdict, "host_report": report}


# ── uninstall ──────────────────────────────────────────────────────
def m1_uninstall(config_path, host) -> dict:
    """Ownership-bound, fail-closed. Identity and evidence are preserved."""
    config = load_config(config_path, host)
    ownership = Ownership(Path(config_path).parent / OWNERSHIP_FILENAME, host)
    if not ownership.exists():
        raise M1Error("NOT_OWNED",
                      "no M1 ownership record; refusing to touch anything")
    record = ownership.read()
    if not ownership.owns(record, "service"):
        raise M1Error("NOT_OWNED",
                      "the service is not recorded as confirmed-owned by "
                      "this M1 installation")
    evidence = record["resources"]["service"]["evidence"]
    qc = host.service_qc(SERVICE_NAME)
    if qc is None:
        raise M1Error("SERVICE_UNVERIFIABLE",
                      "the service cannot be read back; refusing to stop or "
                      "delete anything")
    if qc.get("bin_path") != evidence.get("bin_path"):
        raise M1Error("SERVICE_IDENTITY_MISMATCH",
                      "the installed service is not the one M1 created")
    #: P1-5 — the process is identified BEFORE the stop, so the exit proof
    #: cannot be satisfied by a DIFFERENT process that later reuses the PID.
    pid = qc.get("pid") or 0
    before = host.process_identity(pid) if pid else "ABSENT"
    if before is None:
        raise M1Error("PROCESS_IDENTITY_UNKNOWN",
                      f"the identity of service process {pid} cannot be "
                      "established; refusing to stop or delete anything")
    stopped = host.service_stop(SERVICE_NAME)
    if stopped != "STOPPED":
        raise M1Error("SERVICE_STOP_UNCERTAIN",
                      f"stop outcome {stopped}; refusing to delete. Operator "
                      "action required.")
    exited = True if before == "ABSENT" else host.process_exited(pid, before)
    if exited is not True:
        raise M1Error("PROCESS_EXIT_UNPROVEN",
                      "the service process has not been proven to have "
                      "exited; the payload will not be removed")
    removal = host.service_delete(SERVICE_NAME)
    after, detail = host.service_lookup(SERVICE_NAME)
    if after == PROBE_PRESENT and removal == "PENDING_DELETION":
        ownership.mark(record, "service", CREATE_CONFIRMED,
                       {**evidence, "removal": "PENDING_DELETION"})
        return {"service": "PENDING_DELETION", "detail": detail,
                "evidence_preserved": True}
    if after != PROBE_ABSENT:
        raise M1Error("SERVICE_REMOVAL_UNVERIFIED",
                      f"post-removal service state {after} ({detail})")
    record["resources"].pop("service", None)
    record["history"].append({"resource": "service", "state": "REMOVED",
                              "at": host.now_utc(), "evidence": evidence})
    ownership.save(record)
    #: D-M1-3: identity, journal, cursors, queued evidence and the audit
    #: record are PRESERVED. Nothing under the state directory is removed.
    return {"service": "REMOVED", "state_dir_preserved": str(config.state_dir),
            "evidence_preserved": True}


# ── enrollment reconciliation ──────────────────────────────────────
def m1_reconcile_enrollment(config_path, host, *, session_probe,
                            operator_confirmed: bool = False) -> dict:
    """R3 — an identity that exists while its attempt marker is still open.

    Neither re-enrollment nor silent adoption. Closing the marker requires
    BOTH an explicit operator confirmation and a successful authenticated
    session probe, which is a machine check that the credential is live.
    """
    config = load_config(config_path, host)
    marker = host.read_attempt_marker(config.state_dir)
    identity = host.read_identity(config.state_dir)
    if marker is None:
        return {"state": "NO_ATTEMPT_MARKER", "identity": bool(identity)}
    if marker.get("outcome") != "OPEN":
        return {"state": marker.get("outcome"), "identity": bool(identity)}
    if not identity:
        raise M1Error("ENROLLMENT_OUTCOME_UNKNOWN",
                      "an enrollment attempt is open and no identity was "
                      "published; automatic re-enrollment is blocked. "
                      "Backend reconciliation is required for attempt "
                      f"{marker.get('attempt_id')}")
    if not operator_confirmed:
        raise M1Error("ENROLLMENT_UNCONFIRMED_IDENTITY_PRESENT",
                      "an identity exists while its attempt marker is open; "
                      "it will not be adopted without explicit operator "
                      "confirmation and a successful session probe")
    probe = session_probe(config, identity)
    if not probe.get("ok"):
        raise M1Error("ENROLLMENT_RECONCILE_REFUSED",
                      f"session probe failed: {probe.get('detail')}")
    host.close_attempt_marker(config.state_dir,
                              "ENROLLMENT_CONFIRMED_BY_RECONCILE",
                              {"endpoint_id": identity.get("endpoint_id"),
                               "probe": probe.get("detail")})
    return {"state": "ENROLLMENT_CONFIRMED_BY_RECONCILE",
            "endpoint_id": identity.get("endpoint_id")}


# ── M1 service adapter · never calls the enterprise service entrypoint ─
def m1_service_run(argv: list[str]) -> None:
    """Host the EXISTING sensor collection loop under the SCM for M1.

    Order is load-bearing: the protected configuration is verified BEFORE
    the state directory is bound, before any log is opened in it, before any
    credential is read and before any socket exists.
    """
    if os.name != "nt":
        raise M1Error("NOT_WINDOWS",
                      "the M1 service adapter runs only on Windows")
    config_path = _argv_value(argv, "--m1-config")
    if not config_path:
        raise M1Error("CONFIG_ABSENT", "--m1-config is required")
    #: G3-B3 — the SERVICE authorization context is declared here, at the
    #: service entrypoint, and then PROVEN: a process that is not actually
    #: LocalSystem must not evaluate under the service context.
    host = WindowsHost(authorization=AUTH_SERVICE)
    identity = host.running_identity()
    if identity is None:
        raise M1Error("SERVICE_IDENTITY_UNKNOWN",
                      "the service cannot establish which account it runs as")
    if not identity["is_local_system"]:
        raise M1Error("SERVICE_NOT_LOCAL_SYSTEM",
                      f"the service runs as {identity['user_sid']}, not "
                      "LocalSystem; the approved configuration registers it "
                      "as LocalSystem and M1 will not evaluate its "
                      "configuration under any other identity")
    config = load_config(config_path, host)             # before anything else
    state_dir = _argv_value(argv, "--state-dir") or str(config.state_dir)
    if Path(state_dir) != config.state_dir:
        raise M1Error("CONFIG_STATE_DIR_MISMATCH",
                      "the service was given a state directory the approved "
                      "configuration does not name")
    import nivxforge_sensor as sensor                    # existing loop
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    sensor.use_state_dir(config.state_dir)

    class M1SensorService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = "NivXForge Sensor (M1)"

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            while True:
                sensor.run(config.origin, config.interval, once=True)
                if win32event.WaitForSingleObject(
                        self.stop_event,
                        max(5, config.interval) * 1000) == win32event.WAIT_OBJECT_0:
                    break

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(M1SensorService)
    servicemanager.StartServiceCtrlDispatcher()


def _argv_value(argv: list[str], flag: str) -> str | None:
    for index, value in enumerate(argv):
        if value == flag and index + 1 < len(argv):
            return argv[index + 1]
        if value.startswith(flag + "="):
            return value.split("=", 1)[1]
    return None


# ── the OS surface ─────────────────────────────────────────────────
class WindowsHost:
    """Real Win32 surface. Constructed only on Windows; every method that
    cannot answer authoritatively returns None so the caller fails closed."""

    def __init__(self, authorization: str = AUTH_INSTALLER) -> None:
        if os.name != "nt":
            raise M1Error("NOT_WINDOWS", "WindowsHost requires Windows")
        if authorization not in (AUTH_INSTALLER, AUTH_SERVICE):
            raise M1Error("UNKNOWN_AUTHORIZATION", repr(authorization))
        #: Which authorization context this adapter evaluates in. Declared at
        #: construction by the entrypoint, never inferred (G3-B3).
        self.authorization = authorization
        import ctypes
        import ctypes.wintypes as wintypes
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        #: A HANDLE is pointer-sized. Without these declarations ctypes
        #: truncates it to a C int on 64-bit Windows, which silently breaks
        #: every handle-based proof below.
        self._k32.OpenProcess.restype = wintypes.HANDLE
        self._k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL,
                                          wintypes.DWORD]
        self._k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._k32.CreateMutexW.restype = wintypes.HANDLE
        #: DWORD, not int: the INVALID_FILE_ATTRIBUTES sentinel is 0xFFFFFFFF
        #: and arrives as -1 under the default signed restype (G3-B2).
        self._k32.GetFileAttributesW.restype = wintypes.DWORD
        self._k32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
        self._k32.GetCurrentProcessId.restype = wintypes.DWORD
        self._k32.GetProcessTimes.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME)]
        self._k32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD)]
        self._k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self._k32.LocalFree.restype = wintypes.HANDLE
        self._k32.LocalFree.argtypes = [wintypes.HANDLE]

    # -- time / paths ------------------------------------------------
    def now_utc(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def path_ancestry(self, path) -> list[Path]:
        """Root-first, INCLUDING the drive root and the path itself.

        The root was previously excluded, which left a world-writable drive
        root unexamined; the ancestor role already tolerates the default
        `C:\\` DACL, so including it is strictly more coverage.
        """
        path = Path(path)
        return list(reversed([path, *path.parents]))

    def path_state(self, path) -> str:
        """ABSENT / DIRECTORY / FILE / REPARSE / UNKNOWN."""
        import ctypes
        ctypes.set_last_error(0)
        attributes = self._k32.GetFileAttributesW(str(path))
        return classify_attributes(int(attributes), ctypes.get_last_error())

    def is_reparse_point(self, path) -> bool | None:
        state = self.path_state(path)
        if state == PATH_UNKNOWN:
            return None                       # UNKNOWN is never "not a link"
        return state == PATH_REPARSE

    def path_exists(self, path) -> bool | None:
        state = self.path_state(path)
        if state == PATH_UNKNOWN:
            return None
        return state != PATH_ABSENT

    def is_file(self, path) -> bool:
        return Path(path).is_file()

    def is_dir(self, path) -> bool:
        return Path(path).is_dir()

    def read_bytes(self, path) -> bytes:
        return Path(path).read_bytes()

    def write_new_file(self, path, data: bytes) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        try:
            handle = os.open(path, flags, 0o600)
        except FileExistsError:
            raise M1Error("ALREADY_EXISTS", f"{path} already exists") from None
        try:
            if os.write(handle, data) != len(data):
                raise M1Error("SHORT_WRITE", f"{path}")
            os.fsync(handle)
        finally:
            os.close(handle)

    def replace_file(self, path, data: bytes) -> None:
        temporary = Path(f"{path}.tmp-{os.urandom(6).hex()}")
        self.write_new_file(temporary, data)
        os.replace(temporary, path)

    def copy_payload(self, bundle_root, dest_root, manifest) -> None:
        import shutil
        for member in manifest:
            source = Path(bundle_root) / member
            target = Path(dest_root) / member
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            #: A copied file is owned by its CREATOR, which on a default
            #: Windows 11 host is the administrator's USER account, not the
            #: Administrators group ("default owner for objects created by
            #: members of the Administrators group" is "object creator").
            #: An owner holds WRITE_DAC implicitly, so the service image is
            #: given an explicit, protected, administrator-only descriptor.
            self._apply_protected_sd(target)

    def _apply_protected_sd(self, path) -> None:
        import win32security
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            _PROTECTED_FILE_SDDL, win32security.SDDL_REVISION_1)
        try:
            win32security.SetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.GROUP_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.GetSecurityDescriptorOwner(),
                descriptor.GetSecurityDescriptorGroup(),
                descriptor.GetSecurityDescriptorDacl(), None)
        except Exception as ex:                              # noqa: BLE001
            raise M1Error("FILE_SD_APPLY_FAILED",
                          f"{path}: {ex}") from None

    def create_directory_protected(self, path) -> None:
        """CreateDirectoryW with a protected SD applied AT CREATION."""
        import ctypes
        security = self._protected_security_attributes()
        if not self._k32.CreateDirectoryW(str(path), ctypes.byref(security)):
            error = ctypes.get_last_error()
            if error == 183:                      # ERROR_ALREADY_EXISTS
                raise M1Error("ALREADY_EXISTS",
                              f"{path} already exists; M1 never installs "
                              "into an existing directory")
            raise M1Error("DIR_CREATE_FAILED", f"{path}: WinError {error}")

    def _protected_security_attributes(self):
        import ctypes
        import ctypes.wintypes as wintypes
        import win32security

        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD),
                        ("lpSecurityDescriptor", ctypes.c_void_p),
                        ("bInheritHandle", wintypes.BOOL)]

        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            _PROTECTED_DIR_SDDL, win32security.SDDL_REVISION_1)
        raw = bytes(descriptor)
        buffer = ctypes.create_string_buffer(raw, len(raw))
        attributes = SECURITY_ATTRIBUTES()
        attributes.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        attributes.lpSecurityDescriptor = ctypes.cast(buffer, ctypes.c_void_p)
        attributes.bInheritHandle = False
        attributes._buffer = buffer                 # keep the SD alive
        return attributes

    # -- P1-4 · filesystem security ----------------------------------
    def directory_security(self, path, role=ROLE_ANCESTOR):
        return path_security_verdict(self._read_path_descriptor(path),
                                     role, self)

    def file_security(self, path, role=ROLE_FILE):
        return path_security_verdict(self._read_path_descriptor(path),
                                     role, self)

    def _read_path_descriptor(self, path):
        """Parse a real filesystem descriptor. None means UNKNOWN, and every
        caller treats UNKNOWN as unsafe."""
        try:
            import win32security
        except ImportError:
            return None
        try:
            descriptor = win32security.GetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.GROUP_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION)
        except Exception:                                    # noqa: BLE001
            return None
        return self._parse_descriptor(descriptor)

    def _parse_descriptor(self, descriptor):
        """Normalise a PySECURITY_DESCRIPTOR into the dict the pure verdict
        functions consume. Anything that cannot be decoded is reported as
        malformed rather than guessed, which refuses."""
        import win32security
        try:
            control, _revision = descriptor.GetSecurityDescriptorControl()
            owner = descriptor.GetSecurityDescriptorOwner()
            group = descriptor.GetSecurityDescriptorGroup()
            dacl = descriptor.GetSecurityDescriptorDacl()
        except Exception:                                    # noqa: BLE001
            return {"malformed": True}

        def text(sid):
            try:
                return win32security.ConvertSidToStringSid(sid) if sid else None
            except Exception:                                # noqa: BLE001
                return None

        return normalise_descriptor(control, owner, group, dacl, text)

    def _descriptor_to_sd(self, descriptor, mapping):
        """Rebuild a real SD with every generic bit RESOLVED, because neither
        AccessCheck nor the SCM maps generic bits carried inside an ACE.

        Deny ACEs are emitted first so the ACL we hand to the OS is in
        canonical order; inherit-only ACEs are omitted because they do not
        apply to the object being evaluated."""
        import win32security
        if descriptor.get("malformed") or descriptor.get("dacl") is None:
            return None
        if descriptor.get("owner") is None or descriptor.get("group") is None:
            return None
        acl = win32security.ACL()
        ordered = sorted(descriptor["dacl"],
                         key=lambda ace: ace.get("type") != ACCESS_DENIED_ACE_TYPE)
        for ace in ordered:
            if ace.get("type") not in (ACCESS_ALLOWED_ACE_TYPE,
                                       ACCESS_DENIED_ACE_TYPE):
                return None
            if not isinstance(ace.get("mask"), int):
                return None
            flags = ace.get("flags", 0)
            if not isinstance(flags, int):
                return None
            if flags & INHERIT_ONLY_ACE:
                continue
            try:
                sid = win32security.ConvertStringSidToSid(ace["sid"])
            except Exception:                                # noqa: BLE001
                return None
            mask = map_generic(ace["mask"], mapping)
            if ace["type"] == ACCESS_ALLOWED_ACE_TYPE:
                acl.AddAccessAllowedAce(win32security.ACL_REVISION, mask, sid)
            else:
                acl.AddAccessDeniedAce(win32security.ACL_REVISION, mask, sid)
        security = win32security.SECURITY_DESCRIPTOR()
        security.SetSecurityDescriptorDacl(1, acl, 0)
        security.SetSecurityDescriptorOwner(
            win32security.ConvertStringSidToSid(descriptor["owner"]), 0)
        security.SetSecurityDescriptorGroup(
            win32security.ConvertStringSidToSid(descriptor["group"]), 0)
        if descriptor.get("protected"):
            security.SetSecurityDescriptorControl(SE_DACL_PROTECTED,
                                                  SE_DACL_PROTECTED)
        return security

    # -- SCM (structured; sc.exe text output is locale-dependent) -----
    def _service_handle(self, name, access):
        """(handle, manager, winerror). A winerror is never read as ABSENT
        unless it is literally ERROR_SERVICE_DOES_NOT_EXIST."""
        import win32service
        try:
            manager = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_CONNECT)
        except Exception as ex:                              # noqa: BLE001
            return None, None, getattr(ex, "winerror", -1)
        try:
            handle = win32service.OpenService(manager, name, access)
        except Exception as ex:                              # noqa: BLE001
            win32service.CloseServiceHandle(manager)
            return None, None, getattr(ex, "winerror", -1)
        return handle, manager, 0

    @staticmethod
    def _close(handle, manager):
        import win32service
        for item in (handle, manager):
            if item is not None:
                try:
                    win32service.CloseServiceHandle(item)
                except Exception:                            # noqa: BLE001
                    pass

    def service_lookup(self, name) -> tuple[str, str]:
        import win32service
        handle, manager, error = self._service_handle(
            name, win32service.SERVICE_QUERY_STATUS)
        if handle is None:
            if error == 1060:
                return PROBE_ABSENT, "ERROR_SERVICE_DOES_NOT_EXIST"
            return PROBE_UNKNOWN, f"OpenService WinError {error}"
        try:
            status = win32service.QueryServiceStatusEx(handle)
            return PROBE_PRESENT, f"state={status.get('CurrentState')}"
        except Exception as ex:                              # noqa: BLE001
            return PROBE_UNKNOWN, f"QueryServiceStatusEx: {ex}"
        finally:
            self._close(handle, manager)

    def scheduled_task_lookup(self, name) -> tuple[str, str]:
        """A scheduled task IS a file under System32\\Tasks, so this probe is
        locale-independent. `schtasks.exe` reports "cannot find" in the
        system language, and a text match would answer UNKNOWN on every
        non-English Windows, refusing a legitimate install."""
        tasks = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        try:
            if not tasks.is_dir():
                return PROBE_UNKNOWN, f"{tasks} is not readable"
            return (PROBE_PRESENT if (tasks / name).exists()
                    else PROBE_ABSENT), str(tasks / name)
        except OSError as ex:
            return PROBE_UNKNOWN, f"{type(ex).__name__}: {ex}"

    def self_process_identity(self) -> dict | None:
        """This installer's own verified identity, plus its parent's pid.

        None means the identity could not be established, which makes the
        worker probe UNKNOWN and refuses: without knowing who WE are, a
        matching process cannot be excluded.
        """
        pid = int(self._k32.GetCurrentProcessId())
        identity = self.process_identity(pid)
        if not isinstance(identity, dict):
            return None
        parent = self._parent_pid(pid)
        return {**identity, "parent_pid": parent}

    def _parent_pid(self, pid):
        for entry in self._enumerate_processes() or ():
            if entry["pid"] == pid:
                return entry["parent_pid"]
        return None

    def _enumerate_processes(self):
        """[{pid, parent_pid, name}] or None. None is UNKNOWN, not empty.

        Toolhelp, not `wmic`: wmic is deprecated and is absent from current
        Windows 11 images, where a wmic-based probe answers UNKNOWN forever
        and refuses every install.
        """
        import ctypes
        import ctypes.wintypes as wintypes

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD),
                        ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                        ("th32ModuleID", wintypes.DWORD),
                        ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", ctypes.c_long),
                        ("dwFlags", wintypes.DWORD),
                        ("szExeFile", ctypes.c_wchar * 260)]

        snapshot = self._k32.CreateToolhelp32Snapshot(0x00000002, 0)
        if not snapshot or snapshot == wintypes.HANDLE(-1).value:
            return None
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        found = []
        try:
            if not self._k32.Process32FirstW(snapshot, ctypes.byref(entry)):
                return None
            while True:
                found.append({"pid": int(entry.th32ProcessID),
                              "parent_pid": int(entry.th32ParentProcessID),
                              "name": entry.szExeFile})
                if not self._k32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
        finally:
            self._k32.CloseHandle(snapshot)
        return found

    def worker_processes(self):
        """Competing NivXForge processes, EXCLUDING this installer.

        The installer is itself called NivXForgeEDRSetup.exe, so a bare name
        match classified the running installer as a competing worker and made
        every clean-host check refuse (G3-B1). The installer is also a
        PyInstaller ONEFILE build, so its bootloader parent runs the same
        image and must be excluded too — but only after both are positively
        identified by pid, creation timestamp and image path.

        None means UNKNOWN, not "none found".
        """
        own = self.self_process_identity()
        if own is None:
            return None
        processes = self._enumerate_processes()
        if processes is None:
            return None
        parent = None
        if own.get("parent_pid"):
            candidate = self.process_identity(own["parent_pid"])
            parent = candidate if isinstance(candidate, dict) else None
        competitors = []
        for entry in processes:
            if "nivxforge" not in entry["name"].lower():
                continue
            identity = self.process_identity(entry["pid"])
            if identity == "ABSENT":
                continue                      # it exited during the sweep
            if not isinstance(identity, dict):
                #: A matching process whose identity cannot be established is
                #: reported, not ignored: it may be the very thing we must
                #: not install alongside.
                competitors.append(f"{entry['name']}:{entry['pid']}:unverified")
                continue
            if is_self_process({**identity, "parent_pid": entry["parent_pid"]},
                               own, parent):
                continue
            competitors.append(f"{entry['name']}:{entry['pid']}")
        return competitors

    def service_create(self, name, bin_path, *,
                       start_type=SERVICE_DISABLED) -> None:
        """Create-only, and DISABLED by default (P0-2)."""
        import win32service
        try:
            manager = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_CREATE_SERVICE)
        except Exception as ex:                              # noqa: BLE001
            raise M1Error("SERVICE_CREATE_FAILED",
                          f"OpenSCManager: {ex}") from None
        try:
            handle = win32service.CreateService(
                manager, name, "NivXForge Sensor (M1)",
                win32service.SERVICE_ALL_ACCESS,
                win32service.SERVICE_WIN32_OWN_PROCESS,
                start_type, win32service.SERVICE_ERROR_NORMAL,
                bin_path, None, 0, None, None, None)
        except Exception as ex:                              # noqa: BLE001
            raise M1Error("SERVICE_CREATE_FAILED",
                          f"CreateService({name}): {ex}") from None
        finally:
            self._close(None, manager)
        self._close(handle, None)

    def service_qc(self, name):
        """Structured configuration AND live status. None means UNKNOWN."""
        import win32service
        handle, manager, _error = self._service_handle(
            name, win32service.SERVICE_QUERY_CONFIG
            | win32service.SERVICE_QUERY_STATUS)
        if handle is None:
            return None
        try:
            config = win32service.QueryServiceConfig(handle)
            status = win32service.QueryServiceStatusEx(handle)
        except Exception:                                    # noqa: BLE001
            return None
        finally:
            self._close(handle, manager)
        start_code = int(config[1])
        return {"bin_path": config[3], "account": config[7],
                "service_type": int(config[0]),
                "start_type_code": start_code,
                "start_type": {SERVICE_AUTO_START: "AUTO_START",
                               SERVICE_DEMAND_START: "DEMAND_START",
                               SERVICE_DISABLED: "DISABLED"}.get(
                                   start_code, str(start_code)),
                "state": int(status.get("CurrentState", 0)),
                "pid": int(status.get("ProcessId", 0) or 0)}

    def service_set_start_type(self, name, start_type) -> None:
        import win32service
        handle, manager, error = self._service_handle(
            name, win32service.SERVICE_CHANGE_CONFIG)
        if handle is None:
            raise M1Error("SERVICE_CONFIG_FAILED",
                          f"OpenService for change-config: WinError {error}")
        try:
            win32service.ChangeServiceConfig(
                handle, win32service.SERVICE_NO_CHANGE, start_type,
                win32service.SERVICE_NO_CHANGE, None, None, 0, None,
                None, None, None)
        except Exception as ex:                              # noqa: BLE001
            raise M1Error("SERVICE_CONFIG_FAILED",
                          f"ChangeServiceConfig({start_type}): {ex}") from None
        finally:
            self._close(handle, manager)

    def service_set_security(self, name, descriptor) -> None:
        """P0-1 — apply the restrictive descriptor to the service object."""
        import win32security
        import win32service
        security = self._descriptor_to_sd(descriptor, GENERIC_MAPPING)
        if security is None:
            raise M1Error("SERVICE_SD_UNBUILDABLE",
                          "the approved descriptor could not be rendered as "
                          "a security descriptor")
        handle, manager, error = self._service_handle(
            name, win32service.SERVICE_ALL_ACCESS)
        if handle is None:
            raise M1Error("SERVICE_SD_APPLY_FAILED",
                          f"OpenService for WRITE_DAC: WinError {error}")
        try:
            win32service.SetServiceObjectSecurity(
                handle,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.GROUP_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                security)
        except Exception as ex:                              # noqa: BLE001
            raise M1Error("SERVICE_SD_APPLY_FAILED",
                          f"SetServiceObjectSecurity: {ex}") from None
        finally:
            self._close(handle, manager)

    def service_security(self, name):
        """P0-1 — read the descriptor BACK from the SCM. None is UNKNOWN."""
        import win32security
        import win32service
        handle, manager, _error = self._service_handle(
            name, win32service.SERVICE_QUERY_CONFIG | READ_CONTROL)
        if handle is None:
            return None
        try:
            security = win32service.QueryServiceObjectSecurity(
                handle,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.GROUP_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION)
        except Exception:                                    # noqa: BLE001
            return None
        finally:
            self._close(handle, manager)
        return self._parse_descriptor(security)

    def service_start(self, name) -> None:
        """Start and WAIT for the SCM to report RUNNING. A start request that
        is merely accepted is not a running service."""
        import win32service
        handle, manager, error = self._service_handle(
            name, win32service.SERVICE_START | win32service.SERVICE_QUERY_STATUS)
        if handle is None:
            raise M1Error("SERVICE_START_FAILED",
                          f"OpenService for start: WinError {error}")
        try:
            win32service.StartService(handle, None)
        except Exception as ex:                              # noqa: BLE001
            self._close(handle, manager)
            raise M1Error("SERVICE_START_FAILED",
                          f"StartService: {ex}") from None
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                status = win32service.QueryServiceStatusEx(handle)
                state = int(status.get("CurrentState", 0))
                if state == SERVICE_RUNNING:
                    return
                if state == SERVICE_STOPPED:
                    raise M1Error(
                        "SERVICE_START_FAILED",
                        "the service stopped immediately; exit code "
                        f"{status.get('Win32ExitCode')}/"
                        f"{status.get('ServiceSpecificExitCode')}")
                time.sleep(1)
            raise M1Error("SERVICE_START_TIMEOUT",
                          "the service did not reach RUNNING within 60s")
        finally:
            self._close(handle, manager)

    def service_stop(self, name) -> str:
        """'STOPPED' only when the SCM says so. Anything else is UNCERTAIN."""
        import win32service
        handle, manager, error = self._service_handle(
            name, win32service.SERVICE_STOP | win32service.SERVICE_QUERY_STATUS)
        if handle is None:
            return f"UNCERTAIN OpenService WinError {error}"
        try:
            try:
                win32service.ControlService(
                    handle, win32service.SERVICE_CONTROL_STOP)
            except Exception as ex:                          # noqa: BLE001
                if getattr(ex, "winerror", 0) != 1062:       # NOT_ACTIVE
                    return f"UNCERTAIN ControlService {ex}"
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                state = int(win32service.QueryServiceStatusEx(handle).get(
                    "CurrentState", 0))
                if state == SERVICE_STOPPED:
                    return "STOPPED"
                time.sleep(1)
            return "UNCERTAIN stop did not complete within 60s"
        except Exception as ex:                              # noqa: BLE001
            return f"UNCERTAIN {type(ex).__name__}: {ex}"
        finally:
            self._close(handle, manager)

    def service_delete(self, name) -> str:
        import win32service
        handle, manager, error = self._service_handle(name, DELETE)
        if handle is None:
            return f"UNCERTAIN OpenService WinError {error}"
        try:
            win32service.DeleteService(handle)
            return "DELETED"
        except Exception as ex:                              # noqa: BLE001
            if getattr(ex, "winerror", 0) == 1072:
                return "PENDING_DELETION"
            return f"UNCERTAIN DeleteService {ex}"
        finally:
            self._close(handle, manager)

    # -- P1-5 · process and image evidence ---------------------------
    def process_identity(self, pid):
        """{'pid','created','image'} | 'ABSENT' | None (UNKNOWN).

        The creation timestamp is what defeats PID REUSE: a later process
        that inherits the number has a different one."""
        import ctypes
        import ctypes.wintypes as wintypes
        if not pid:
            return "ABSENT"
        access = 0x1000 | 0x00100000      # QUERY_LIMITED_INFORMATION|SYNCHRONIZE
        handle = self._k32.OpenProcess(access, False, int(pid))
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:               # ERROR_INVALID_PARAMETER: no such pid
                return "ABSENT"
            return None                   # e.g. 5 ACCESS_DENIED: UNKNOWN
        try:
            created = wintypes.FILETIME()
            exited = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not self._k32.GetProcessTimes(
                    handle, ctypes.byref(created), ctypes.byref(exited),
                    ctypes.byref(kernel), ctypes.byref(user)):
                return None
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not self._k32.QueryFullProcessImageNameW(
                    handle, 0, buffer, ctypes.byref(size)):
                return None
            return {"pid": int(pid),
                    "created": (created.dwHighDateTime << 32)
                    | created.dwLowDateTime,
                    "image": buffer.value}
        finally:
            self._k32.CloseHandle(handle)

    def process_exited(self, pid, before=None):
        """True ONLY on authoritative evidence; None means UNKNOWN."""
        if not pid:
            return True if before in (None, "ABSENT") else None
        if before is None or before == "ABSENT":
            #: Without a pre-stop identity a live PID cannot be told apart
            #: from a reused one, so nothing can be asserted.
            return None
        return exit_verdict(before, self.process_identity(pid))

    def verify_running_image(self, name, expected, *, expected_sha256=None):
        """The SCM itself reports which PID belongs to THIS service, so the
        association is authoritative rather than inferred from a name."""
        qc = self.service_qc(name)
        if qc is None:
            return None
        if qc.get("state") != SERVICE_RUNNING:
            return {"verdict": "NOT_RUNNING",
                    "detail": f"SCM state {qc.get('state')}"}
        pid = qc.get("pid") or 0
        if not pid:
            return {"verdict": "NO_PROCESS",
                    "detail": "the SCM reports a running service with no "
                              "process id"}
        identity = self.process_identity(pid)
        if not isinstance(identity, dict):
            return None
        if not image_path_matches(identity["image"], expected):
            return {"verdict": "IMAGE_MISMATCH", "detail": identity["image"]}
        if expected_sha256 is not None:
            try:
                digest = file_digest(Path(identity["image"]))
            except OSError:
                return None
            if digest != expected_sha256:
                return {"verdict": "DIGEST_MISMATCH", "detail": digest}
        #: Re-read AFTER the inspection. If the PID or the process behind it
        #: changed meanwhile, the association just proven is stale.
        again = self.service_qc(name)
        if (again is None or again.get("pid") != pid
                or again.get("state") != SERVICE_RUNNING):
            return {"verdict": "ASSOCIATION_UNSTABLE",
                    "detail": f"pid {None if again is None else again.get('pid')}"}
        after = self.process_identity(pid)
        if (not isinstance(after, dict)
                or after.get("created") != identity.get("created")):
            return {"verdict": "ASSOCIATION_UNSTABLE",
                    "detail": "the process behind the pid changed during "
                              "verification"}
        return {"verdict": "MATCH", "pid": pid, "image": identity["image"],
                "created": identity["created"], "sha256": expected_sha256}

    def running_identity(self):
        """Who this process actually runs as. None is UNKNOWN."""
        try:
            import win32api
            import win32con
            import win32security
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
            user = win32security.GetTokenInformation(
                token, win32security.TokenUser)[0]
            sid = win32security.ConvertSidToStringSid(user)
        except Exception:                                    # noqa: BLE001
            return None
        return {"user_sid": sid, "is_local_system": sid == SID_LOCAL_SYSTEM}

    # -- P0-1 · token-aware effective access -------------------------
    def access_context(self):
        """A NON-ADMINISTRATOR probe principal, built the only way the
        current authorization context allows.

        installer — the caller is an elevated interactive administrator, so
            `CreateRestrictedToken` derives a filtered token from its own:
            the administrative groups become deny-only, exactly as Windows
            filters an unelevated logon. Deny-only and disabled SIDs are
            excluded from the reported context, so the probe cannot be
            satisfied by a SID that cannot grant anything.

        service — the caller is LocalSystem. S-1-5-18 carries neither
            INTERACTIVE nor Users, and group membership must NEVER be
            manufactured, so no meaningful principal can be filtered out of
            it. The context is instead built with Authz FROM A SID, which is
            the second mechanism the accepted R4 amendment names. Each
            required non-administrator principal is probed as its own
            context; see `_authz_contexts`.

        No SID the token does not carry is ever substituted. An incomplete
        context refuses.
        """
        if self.authorization == AUTH_SERVICE:
            return self._service_access_context()
        try:
            import ntsecuritycon
            import win32api
            import win32con
            import win32security
        except ImportError:
            return None
        try:
            process = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY)
            impersonation = win32security.DuplicateTokenEx(
                process, win32security.SecurityImpersonation,
                win32con.TOKEN_QUERY | win32con.TOKEN_DUPLICATE
                | win32con.TOKEN_IMPERSONATE,
                win32security.TokenImpersonation)
            disable = [(win32security.ConvertStringSidToSid(sid), 0)
                       for sid in (SID_ADMINISTRATORS, "S-1-5-32-549",
                                   "S-1-5-32-551", "S-1-5-32-550")]
            token = win32security.CreateRestrictedToken(
                impersonation,
                getattr(win32security, "DISABLE_MAX_PRIVILEGE", 0x1),
                disable, [], [])
        except Exception:                                    # noqa: BLE001
            return None
        deny_only = getattr(win32security, "SE_GROUP_USE_FOR_DENY_ONLY",
                            0x00000010)
        enabled = getattr(ntsecuritycon, "SE_GROUP_ENABLED", 0x00000004)
        sids: list[str] = []
        try:
            #: TOKEN_QUERY is requested above and is required by AccessCheck.
            #: Note that a failure of AccessCheck is treated as UNKNOWN
            #: regardless of its error code, so a missing-TOKEN_QUERY failure
            #: can never masquerade as a verified denial.
            for sid, attributes in win32security.GetTokenInformation(
                    token, win32security.TokenGroups):
                if attributes & deny_only or not attributes & enabled:
                    continue
                sids.append(win32security.ConvertSidToStringSid(sid))
            user = win32security.GetTokenInformation(
                token, win32security.TokenUser)[0]
            sids.append(win32security.ConvertSidToStringSid(user))
        except Exception:                                    # noqa: BLE001
            return None
        return {"token": token, "sids": sorted(set(sids)),
                "authorization": AUTH_INSTALLER,
                "source": "restricted-impersonation-token"}

    def _service_access_context(self):
        """Service-time probe principals, resolved with Authz from a SID.

        Refuses to pretend: if the process is not actually LocalSystem, the
        service authorization context does not apply.
        """
        identity = self.running_identity()
        if identity is None or not identity["is_local_system"]:
            return None
        contexts = self._authz_contexts(REQUIRED_CONTEXT_SIDS)
        if contexts is None:
            return None
        return {"token": None, "authz": contexts,
                "sids": sorted(contexts),
                "unprobed": sorted(set(REQUIRED_CONTEXT_SIDS) - set(contexts)),
                "authorization": AUTH_SERVICE,
                "source": "authz-context-from-sid"}

    def _authz_contexts(self, sids):
        """{sid: AUTHZ_CLIENT_CONTEXT_HANDLE} for each principal that could be
        resolved. None if the resource manager itself cannot be created.

        A principal that cannot be resolved is simply absent from the result
        and is reported as `unprobed`; it is never recorded as "checked".
        """
        import ctypes
        import ctypes.wintypes as wintypes
        try:
            import win32security
            authz = ctypes.WinDLL("authz", use_last_error=True)
        except Exception:                                    # noqa: BLE001
            return None

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD),
                        ("HighPart", ctypes.c_long)]

        authz.AuthzInitializeResourceManager.restype = wintypes.BOOL
        authz.AuthzInitializeResourceManager.argtypes = [
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        #: 7 parameters, and `Identifier` is an LUID BY VALUE.
        authz.AuthzInitializeContextFromSid.restype = wintypes.BOOL
        authz.AuthzInitializeContextFromSid.argtypes = [
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            LUID, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        manager = ctypes.c_void_p()
        #: AUTHZ_RM_FLAG_NO_AUDIT — M1 evaluates, it does not audit.
        if not authz.AuthzInitializeResourceManager(
                0x1, None, None, None, "NivXForgeM1", ctypes.byref(manager)):
            return None
        self._authz = authz
        self._authz_manager = manager            # keep both alive
        contexts: dict = {}
        for text in sids:
            try:
                raw = bytes(win32security.ConvertStringSidToSid(text))
            except Exception:                                # noqa: BLE001
                continue
            buffer = ctypes.create_string_buffer(raw, len(raw))
            handle = ctypes.c_void_p()
            #: AUTHZ_SKIP_TOKEN_GROUPS (0x2) — resolve the principal itself
            #: without an AD lookup; a local lab host has no directory.
            if authz.AuthzInitializeContextFromSid(
                    0x2, ctypes.cast(buffer, ctypes.c_void_p), manager, None,
                    LUID(), None, ctypes.byref(handle)):
                contexts[text] = handle
        return contexts

    def _authz_access_check(self, context, sddl, wanted):
        """One Authz evaluation. Three-way, per `authz_access_verdict`.

        The native call and the READING of its result are deliberately
        separated: `_authz_invoke` reports (ok, Error[0], GrantedAccessMask[0])
        and nothing else, and the verdict is decided by the pure contract
        function, where a per-result ERROR_ACCESS_DENIED is a verified denial
        and every other non-zero code is UNKNOWN.
        """
        security = self._sddl_to_descriptor(sddl)
        if security is None:
            return None
        try:
            native = self._authz_invoke(context, security, wanted)
        finally:
            #: The descriptor is freed on every path, including a raised call.
            self._k32.LocalFree(security)
        if native is None:
            return None                   # no resource manager, or no reply
        ok, reply_error, granted = native
        return authz_access_verdict(ok, reply_error, granted, wanted)

    def _authz_invoke(self, context, security, wanted):
        """The native AuthzAccessCheck call itself.

        Returns (ok, Error[0], GrantedAccessMask[0]) — raw, uninterpreted —
        or None if the resource manager was never built.
        """
        import ctypes
        import ctypes.wintypes as wintypes

        class AUTHZ_ACCESS_REQUEST(ctypes.Structure):
            _fields_ = [("DesiredAccess", wintypes.DWORD),
                        ("PrincipalSelfSid", ctypes.c_void_p),
                        ("ObjectTypeList", ctypes.c_void_p),
                        ("ObjectTypeListLength", wintypes.DWORD),
                        ("OptionalArguments", ctypes.c_void_p)]

        class AUTHZ_ACCESS_REPLY(ctypes.Structure):
            _fields_ = [("ResultListLength", wintypes.DWORD),
                        ("GrantedAccessMask", ctypes.POINTER(wintypes.DWORD)),
                        ("SaclEvaluationResults", ctypes.POINTER(wintypes.DWORD)),
                        ("Error", ctypes.POINTER(wintypes.DWORD))]

        authz = getattr(self, "_authz", None)
        if authz is None:
            return None
        authz.AuthzAccessCheck.restype = wintypes.BOOL
        #: Flags is a DWORD, not a pointer-sized integer: declaring it as
        #: c_longlong misdescribes the published ABI.
        authz.AuthzAccessCheck.argtypes = [
            wintypes.DWORD, ctypes.c_void_p,
            ctypes.POINTER(AUTHZ_ACCESS_REQUEST), ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(AUTHZ_ACCESS_REPLY), ctypes.c_void_p]
        request = AUTHZ_ACCESS_REQUEST()
        request.DesiredAccess = wanted
        granted = (wintypes.DWORD * 1)()
        error = (wintypes.DWORD * 1)()
        sacl = (wintypes.DWORD * 1)()
        reply = AUTHZ_ACCESS_REPLY()
        reply.ResultListLength = 1
        reply.GrantedAccessMask = ctypes.cast(
            granted, ctypes.POINTER(wintypes.DWORD))
        reply.SaclEvaluationResults = ctypes.cast(
            sacl, ctypes.POINTER(wintypes.DWORD))
        reply.Error = ctypes.cast(error, ctypes.POINTER(wintypes.DWORD))
        ok = authz.AuthzAccessCheck(
            0, context, ctypes.byref(request), None, security, None, 0,
            ctypes.byref(reply), None)
        #: Raw outputs only. Error[0] is the PER-RESULT status and is read by
        #: `authz_access_verdict`, which alone decides granted/denied/unknown.
        return bool(ok), int(error[0]), int(granted[0])

    def _sddl_to_descriptor(self, sddl):
        """A self-relative descriptor from SDDL, or None."""
        import ctypes
        import ctypes.wintypes as wintypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.restype = wintypes.BOOL
        convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                            ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(wintypes.DWORD)]
        security = ctypes.c_void_p()
        if not convert(sddl, 1, ctypes.byref(security), None):
            return None
        return security

    def access_check(self, descriptor, context, right, mapping):
        """True / False / None, per `access_check_verdict`.

        pywin32 does NOT wrap AccessCheck — it exposes MapGenericMask but not
        the check itself — so the call is made through advapi32 directly. A
        `win32security.AccessCheck` call would have raised AttributeError and
        been swallowed as UNKNOWN on every real host, leaving the token-aware
        mechanism permanently indeterminate.
        """
        token = (context or {}).get("token")
        authz = (context or {}).get("authz")
        if token is None and not authz:
            return None
        sddl = descriptor_to_sddl(descriptor, mapping)
        if sddl is None:
            return None
        try:
            wanted = map_generic(right, mapping)
            if authz:
                #: Service time: every resolved non-administrator principal is
                #: probed. GRANTED to any of them is a grant; DENIED requires
                #: every one of them to be denied; one indeterminate principal
                #: makes the whole answer UNKNOWN.
                verdicts = [self._authz_access_check(handle, sddl, wanted)
                            for handle in authz.values()]
                if not verdicts or None in verdicts:
                    return None
                return True if any(verdicts) else False
            return self._access_check_native(sddl, token, wanted, mapping)
        except Exception:                                    # noqa: BLE001
            #: Any failure here is UNKNOWN. It is never a denial.
            return None

    def _access_check_native(self, sddl, token, wanted, mapping):
        import ctypes
        import ctypes.wintypes as wintypes

        class PRIVILEGE_SET(ctypes.Structure):
            #: The buffer is NOT optional in practice: AccessCheck fails with
            #: ERROR_INSUFFICIENT_BUFFER (122) without a real 20-byte one.
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Control", wintypes.DWORD),
                        ("Privilege", ctypes.c_byte * 12)]

        class GENERIC_MAPPING(ctypes.Structure):
            _fields_ = [("GenericRead", wintypes.DWORD),
                        ("GenericWrite", wintypes.DWORD),
                        ("GenericExecute", wintypes.DWORD),
                        ("GenericAll", wintypes.DWORD)]

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.restype = wintypes.BOOL
        convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                            ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(wintypes.DWORD)]
        advapi.AccessCheck.restype = wintypes.BOOL
        advapi.AccessCheck.argtypes = [
            ctypes.c_void_p, wintypes.HANDLE, wintypes.DWORD,
            ctypes.POINTER(GENERIC_MAPPING), ctypes.POINTER(PRIVILEGE_SET),
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.BOOL)]
        security = ctypes.c_void_p()
        if not convert(sddl, 1, ctypes.byref(security), None):
            return None                      # could not build the descriptor
        try:
            privileges = PRIVILEGE_SET()
            privileges.PrivilegeCount = 0
            length = wintypes.DWORD(ctypes.sizeof(PRIVILEGE_SET))
            granted = wintypes.DWORD(0)
            status = wintypes.BOOL(0)
            generic = GENERIC_MAPPING(*self._mapping_tuple(mapping))
            ok = advapi.AccessCheck(
                security, wintypes.HANDLE(int(token)), wintypes.DWORD(wanted),
                ctypes.byref(generic), ctypes.byref(privileges),
                ctypes.byref(length), ctypes.byref(granted),
                ctypes.byref(status))
            #: The BOOL return reports whether the CALL succeeded; the verdict
            #: is AccessStatus. The two are read separately and a failure is
            #: never converted into a denial.
            return access_check_verdict(bool(ok), int(status.value),
                                        int(granted.value), wanted)
        finally:
            self._k32.LocalFree(security)

    @staticmethod
    def _mapping_tuple(mapping):
        return (mapping[GENERIC_READ], mapping[GENERIC_WRITE],
                mapping[GENERIC_EXECUTE], mapping[GENERIC_ALL])

    # -- identity / marker (delegated to the sensor) ------------------
    def read_identity(self, state_dir):
        path = Path(state_dir) / "identity.json"
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text())
        except ValueError:
            return None

    def read_attempt_marker(self, state_dir):
        import nivxforge_sensor as sensor
        return sensor.read_attempt_marker(Path(state_dir))

    def close_attempt_marker(self, state_dir, outcome, evidence):
        import nivxforge_sensor as sensor
        return sensor.close_attempt_marker(outcome, evidence,
                                           state_dir=Path(state_dir))

    def exclusive_lock(self):
        return _NamedMutex()


class _NamedMutex:
    """Exclusive M1 ownership, distinct from the enterprise installer mutex.
    An ABANDONED mutex is not a free lock: the caller refuses."""

    NAME = "Global\\NivXForgeM1Install"

    def __enter__(self):
        import ctypes
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._handle = self._k32.CreateMutexW(None, True, self.NAME)
        error = ctypes.get_last_error()
        if not self._handle or error == 183:        # ERROR_ALREADY_EXISTS
            return None
        return self

    def __exit__(self, *exc):
        if getattr(self, "_handle", None):
            self._k32.ReleaseMutex(self._handle)
            self._k32.CloseHandle(self._handle)
        return False
