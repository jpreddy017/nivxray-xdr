"""
DIE · LOLBAS knowledge base
────────────────────────────
Living, versioned registry of Living-Off-the-Land Binaries And Scripts
that are frequently abused for post-exploitation.  Every entry is
tagged with the MITRE ATT&CK techniques the binary participates in
when misused, plus a canonical "trust tier" (system|admin|browser|
otherwise-legit) so the verdict engine can weight the evidence.

Purely deterministic — no LLM, no network calls.  The registry is a
plain Python dict so lookups are O(1).  Extendable via the JSON file
at `die/lolbas_registry.json`; that file is loaded lazily on first
call (if present) and merged over the built-in defaults.

Design decision (owner-locked 2026-02-16): keep the built-in
seed-registry small enough to review by hand.  Growth happens through
DKP (Decoder Knowledge Pack) which is intentionally scoped as its own
milestone after DIE-2 lands.

Gate 2A extension (owner-locked 2026-09-02) — registry ARCHITECTURE
promoted to versioned + provenance-bearing:
  · REGISTRY_VERSION       — semver string; bumps on schema/content change.
  · Every entry carries `provenance` (source · sourced_at · notes).
  · New helpers `registry_version()`, `registry_provenance()`,
    `lolbas_meta(binary)` for consumers that need the trace.
  · Gate 2A adds SCHEMA + provenance ONLY.  Registry completeness
    (wildcard-resolution readiness) is Gate 2B territory — see
    `P0_1B_SCOPE.md`.
"""
from __future__ import annotations
import json, os
from pathlib import Path
from typing import Dict, List, Optional, Any

# Built-in seed registry — high-signal LOLBAS binaries observed in
# real intrusions.  Extend via lolbas_registry.json.
_BUILTIN: Dict[str, Dict[str, Any]] = {
    "powershell.exe": {
        "category": "script-host",
        "trust":    "admin",
        "mitre":    ["T1059.001"],
        "notes":    "PowerShell interpreter — most common first-stage host.",
    },
    "cmd.exe": {
        "category": "shell",
        "trust":    "system",
        "mitre":    ["T1059.003"],
        "notes":    "Windows Command Prompt.",
    },
    "wscript.exe": {
        "category": "script-host",
        "trust":    "system",
        "mitre":    ["T1059.005", "T1059.007"],
        "notes":    "Windows Script Host — VBS/JS execution.",
    },
    "cscript.exe": {
        "category": "script-host",
        "trust":    "system",
        "mitre":    ["T1059.005", "T1059.007"],
        "notes":    "Console Windows Script Host.",
    },
    "mshta.exe": {
        "category": "script-host",
        "trust":    "system",
        "mitre":    ["T1218.005"],
        "notes":    "HTA host — proxy execution.",
    },
    "regsvr32.exe": {
        "category": "signed-binary-proxy",
        "trust":    "system",
        "mitre":    ["T1218.010"],
        "notes":    "Squiblydoo — remote scriptlet proxy.",
    },
    "rundll32.exe": {
        "category": "signed-binary-proxy",
        "trust":    "system",
        "mitre":    ["T1218.011"],
        "notes":    "DLL execution proxy.",
    },
    "msiexec.exe": {
        "category": "signed-binary-proxy",
        "trust":    "system",
        "mitre":    ["T1218.007"],
        "notes":    "MSI installer — remote MSI execution proxy.",
    },
    "installutil.exe": {
        "category": "signed-binary-proxy",
        "trust":    "admin",
        "mitre":    ["T1218.004"],
        "notes":    ".NET install utility — code execution vector.",
    },
    "certutil.exe": {
        "category": "signed-binary-proxy",
        "trust":    "system",
        "mitre":    ["T1105", "T1140", "T1218"],
        "notes":    "Download / decode / execute.",
    },
    "bitsadmin.exe": {
        "category": "signed-binary-proxy",
        "trust":    "admin",
        "mitre":    ["T1197", "T1105"],
        "notes":    "BITS transfer download vector.",
    },
    "curl.exe": {
        "category": "network-utility",
        "trust":    "system",
        "mitre":    ["T1105"],
        "notes":    "Native curl on Win10+.",
    },
    "wmic.exe": {
        "category": "signed-binary-proxy",
        "trust":    "system",
        "mitre":    ["T1047", "T1218"],
        "notes":    "WMI command-line — remote execution proxy.",
    },
    "schtasks.exe": {
        "category": "persistence-utility",
        "trust":    "system",
        "mitre":    ["T1053.005"],
        "notes":    "Scheduled task creation.",
    },
    "reg.exe": {
        "category": "registry-utility",
        "trust":    "system",
        "mitre":    ["T1112", "T1547.001"],
        "notes":    "Registry modification.",
    },
    "netsh.exe": {
        "category": "network-utility",
        "trust":    "system",
        "mitre":    ["T1562.004", "T1547.007"],
        "notes":    "Windows firewall / network shell.",
    },
    "vssadmin.exe": {
        "category": "shadow-copy-utility",
        "trust":    "admin",
        "mitre":    ["T1490"],
        "notes":    "Shadow-copy deletion — ransomware precursor.",
    },
    "wbadmin.exe": {
        "category": "backup-utility",
        "trust":    "admin",
        "mitre":    ["T1490"],
        "notes":    "Backup deletion — ransomware precursor.",
    },
    "bcdedit.exe": {
        "category": "boot-utility",
        "trust":    "admin",
        "mitre":    ["T1490"],
        "notes":    "Boot configuration tampering — ransomware precursor.",
    },
    "ntdsutil.exe": {
        "category": "domain-utility",
        "trust":    "admin",
        "mitre":    ["T1003.003"],
        "notes":    "NTDS.dit dumping — credential access.",
    },
}

_JSON_PATH = Path(__file__).parent / "lolbas_registry.json"
_REGISTRY_CACHE: Optional[Dict[str, Dict[str, Any]]] = None

# ── Gate 2A · versioning + provenance ─────────────────────────────
REGISTRY_VERSION = "0.2.0-gate2a"
_REGISTRY_PROVENANCE: Dict[str, Any] = {
    "version":    REGISTRY_VERSION,
    "sources": [
        {
            "name":       "LOLBAS Project",
            "url":        "https://lolbas-project.github.io/",
            "license":    "CC BY-SA-4.0",
            "use":        "private-only (no public redistribution — "
                          "share-alike not triggered)",
            "sourced_at": "2026-09-02 (initial seed, versioned in Gate 2A)",
        },
        {
            "name":       "MITRE ATT&CK",
            "url":        "https://attack.mitre.org/",
            "license":    "Apache-2.0",
            "use":        "technique tagging per binary",
            "sourced_at": "2026-09-02",
        },
    ],
    "entry_count_builtin": None,   # filled in by _load_registry()
    "entry_count_json":    None,
    "gate":                "2A",
    "completeness":        "seed — wildcard-resolution readiness "
                           "gated by Gate 2B; do not claim complete.",
}


def _stamp_provenance(entry: Dict[str, Any],
                      source: str,
                      sourced_at: str) -> Dict[str, Any]:
    """Attach provenance to a registry entry, preserving existing keys."""
    out = dict(entry)
    prov = dict(out.get("provenance") or {})
    prov.setdefault("source",     source)
    prov.setdefault("sourced_at", sourced_at)
    prov.setdefault("registry_version", REGISTRY_VERSION)
    out["provenance"] = prov
    return out


def _load_registry() -> Dict[str, Dict[str, Any]]:
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is not None:
        return _REGISTRY_CACHE
    seed_stamp = "2026-09-02"
    reg = {
        k.lower(): _stamp_provenance(v, "builtin-seed", seed_stamp)
        for k, v in _BUILTIN.items()
    }
    _REGISTRY_PROVENANCE["entry_count_builtin"] = len(reg)
    json_count = 0
    if _JSON_PATH.exists():
        try:
            extra = json.loads(_JSON_PATH.read_text(encoding="utf-8"))
            for k, v in (extra or {}).items():
                merged = {**reg.get(k.lower(), {}), **v}
                reg[k.lower()] = _stamp_provenance(
                    merged, f"json:{_JSON_PATH.name}", seed_stamp)
                json_count += 1
        except Exception:
            # A malformed JSON file must not break the engine; fall
            # back to built-ins only.
            pass
    _REGISTRY_PROVENANCE["entry_count_json"] = json_count
    _REGISTRY_CACHE = reg
    return reg


def registry_version() -> str:
    """Public — expose current registry semver to consumers."""
    return REGISTRY_VERSION


def registry_provenance() -> Dict[str, Any]:
    """Public — expose sources / license / sourced_at metadata.

    Consumers MUST NOT alter the returned dict.
    """
    # Ensure the entry-count fields are populated.
    _load_registry()
    return dict(_REGISTRY_PROVENANCE)


def lolbas_meta(binary: str) -> Optional[Dict[str, Any]]:
    """Return the FULL registry entry (including `provenance`) for a
    binary name, or ``None``.
    """
    return lolbas_lookup(binary)


# Exposed frozen view for consumers wanting to iterate the full set.
LOLBAS_REGISTRY: Dict[str, Dict[str, Any]] = _load_registry()


def lolbas_lookup(binary: str) -> Optional[Dict[str, Any]]:
    """Return the registry entry for a binary name, or ``None``.

    Match is case-insensitive on the binary name only — path prefixes
    (``C:\\Windows\\System32\\powershell.exe``) are stripped before
    lookup.  Aliases (``pwsh.exe``) are not currently expanded.
    """
    if not binary:
        return None
    raw = binary.strip().strip('"').strip("'")
    # Normalize Windows-style backslashes so this works on any OS.
    raw = raw.replace("\\", "/")
    name = raw.rsplit("/", 1)[-1].lower()
    if not name.endswith(".exe") and "." not in name:
        # Best-effort: analysts frequently reference LOLBins without
        # the extension (``certutil`` instead of ``certutil.exe``).
        name = name + ".exe"
    return _load_registry().get(name)
