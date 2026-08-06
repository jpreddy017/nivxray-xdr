"""Resource Protection Policy — one place, every adapter reads.

Frozen 2026-02-06 per `/app/memory/NIVXRAY_ARCHITECTURE_V1.md` (Phase 4
requirement — enforced at the adapter layer as a first line of defense).

Configuration is generic (`defaults` + one section per adapter kind) so
adding limits for PDF / DOCX / EML / Image later is a values-only change,
never a schema change.  Every value can be overridden via environment
variable so operators tune SOC-appliance vs SaaS deployments without
touching code.

Environment variable convention:
    NIVX_RPP_<KIND>_<SETTING>          (uppercase, snake_case → SCREAMING)

Examples:
    NIVX_RPP_DEFAULTS_MAX_DEPTH=10
    NIVX_RPP_ZIP_MAX_MEMBERS=5000
    NIVX_RPP_ZIP_MAX_UNCOMPRESSED_SIZE_MB=2048
    NIVX_RPP_PDF_MAX_PAGES=500
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional


def _env(name: str, default: Any) -> Any:
    """Read env var with type coercion matching ``default``'s type."""
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    try:
        if isinstance(default, bool):
            return v.lower() in {"1", "true", "yes", "on"}
        if isinstance(default, int):
            return int(v)
        if isinstance(default, float):
            return float(v)
    except (ValueError, TypeError):
        return default
    return v


# ─── Defaults (apply to every adapter unless overridden per-kind) ─────
_DEFAULTS = {
    "max_depth":        _env("NIVX_RPP_DEFAULTS_MAX_DEPTH",        5),
    "timeout_seconds":  _env("NIVX_RPP_DEFAULTS_TIMEOUT_SECONDS",  60),
}


# ─── Per-adapter sections ─────────────────────────────────────────────
# Only ZIP has enforced values today; the other sections are stubs so
# adding limits later is a values-only change.
_ZIP = {
    "max_members":              _env("NIVX_RPP_ZIP_MAX_MEMBERS",              2000),
    "max_members_soft_warn":    _env("NIVX_RPP_ZIP_MAX_MEMBERS_SOFT_WARN",     500),
    "max_uncompressed_size_mb": _env("NIVX_RPP_ZIP_MAX_UNCOMPRESSED_SIZE_MB",  512),
    "max_compression_ratio":    _env("NIVX_RPP_ZIP_MAX_COMPRESSION_RATIO",     100),
    "max_filename_length":      _env("NIVX_RPP_ZIP_MAX_FILENAME_LENGTH",       400),
}

_PDF:   Dict[str, Any] = {}
_DOCX:  Dict[str, Any] = {}
_EML:   Dict[str, Any] = {}
_IMAGE: Dict[str, Any] = {}

_SECTIONS = {
    "defaults": _DEFAULTS,
    "zip":      _ZIP,
    "pdf":      _PDF,
    "docx":     _DOCX,
    "eml":      _EML,
    "image":    _IMAGE,
}


def get(kind: str, key: str, fallback: Any = None) -> Any:
    """Read a per-adapter setting, falling back to defaults, then ``fallback``.

    ``kind`` is one of ``zip``, ``pdf``, ``docx``, ``eml``, ``image``.
    Never raises — an unknown ``kind`` returns ``fallback`` immediately.
    """
    section = _SECTIONS.get(kind.lower())
    if section is None:
        return fallback
    if key in section:
        return section[key]
    if key in _DEFAULTS:
        return _DEFAULTS[key]
    return fallback


def section(kind: str) -> Dict[str, Any]:
    """Return a shallow copy of an adapter section (defaults merged in)."""
    out: Dict[str, Any] = dict(_DEFAULTS)
    out.update(_SECTIONS.get(kind.lower(), {}))
    return out


def snapshot() -> Dict[str, Any]:
    """Full policy — useful for admin visibility / debugging."""
    return {k: dict(v) for k, v in _SECTIONS.items()}
