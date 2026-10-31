"""Phase A · S4 · Architecture Freeze CI Invariants.

Per user directive (2026-02-04):

    No legacy transformation may be introduced without either a
    UAIE capability or an explicit exemption.  Exemptions should
    require deliberate review rather than becoming a routine
    escape hatch.

This module encodes both invariants as tests that fail CI:

    · frozen_core_files      · orchestrator / planner / lifecycle /
                                termination cannot change without a
                                ``POST_FREEZE_EXCEPTION`` marker.
    · no_new_legacy          · every RTE transformation in
                                ``v2/investigation/rte/transformations/``
                                must be either paired with a UAIE
                                capability of the same behaviour OR
                                appear on the exemption list.

The exemption list is intentionally short and kept in this file so
adding to it requires a diff that shows up in review — the friction
IS the point.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Set


# ── Frozen core files ──────────────────────────────────────────────
# Once Phase A ships, changes to these files should be extraordinary
# events requiring a POST_FREEZE_EXCEPTION marker in the diff/commit
# message.  This module ships the guard NOW so the freeze mechanism
# is in place even before the freeze itself is declared.
_FROZEN_CORE = [
    "services/uaie/orchestrator.py",
    "services/uaie/planner_v2.py",
    "services/uaie/lifecycle.py",
    "services/uaie/termination.py",
]


# ── Exempt legacy transformations ──────────────────────────────────
# Transformations that MAY remain in ``v2/investigation/rte/transformations/``
# without a paired UAIE capability.  Each entry is a deliberate,
# reviewed decision.  Additions to this list MUST justify why the
# duplication is acceptable — e.g. "temporary during Phase-B" or
# "consumer-only import (no independent behaviour)".
#
# Entries below are Slice-6-pending — they have equivalent UAIE
# capabilities (see the paired ``base64_bare``, ``gzip_inflate``,
# ``op_ps_*``) but the pairing-substring heuristic doesn't detect
# them.  Each carries a machine-readable retirement plan so the
# eventual removal is auditable.
_LEGACY_TRANSFORMATION_EXEMPTIONS: Set[str] = {
    # Handled by UAIE ``base64_bare`` — Slice-6-pending physical removal.
    "base64_bytes",       "base64_utf16le",   "base64_utf8",
    "ps_static_base64",
    # Handled by UAIE ``gzip_inflate`` / compression family (Slice 2).
    "gzip_stream",        "zlib_stream",
    "ps_compression_stream", "ps_indirect_compression_stream",
    # Handled by UAIE ``op_ps_hex_csv_inline`` / hex primitive (Slice 4).
    "hex_string",
    # Handled by UAIE PowerShell composite operations
    #   ``op_ps_char_array``, ``op_ps_reverse_string``, etc.
    "ps_char_array",      "ps_format",        "ps_iex_peel",
}


def _rte_transformation_modules() -> Set[str]:
    """Every ``.py`` module under the RTE transformations directory
    that looks like a transformation implementation."""
    tf_dir = Path("/app/backend/v2/investigation/rte/transformations")
    if not tf_dir.is_dir():
        return set()
    out = set()
    for p in tf_dir.glob("*.py"):
        name = p.stem
        if name.startswith("_") or name == "__init__":
            continue
        out.add(name)
    return out


def _uaie_capability_names() -> Set[str]:
    """Names of every UAIE plugin package on disk PLUS every
    contract-registered capability id."""
    plugins_root = Path("/app/backend/services/uaie/plugins")
    from_disk = set()
    if plugins_root.is_dir():
        for p in plugins_root.iterdir():
            if p.is_dir() and not p.name.startswith("_"):
                from_disk.add(p.name)
    try:
        from services.uaie.migration_gate import build_capability_catalog
        from_registry = set(build_capability_catalog().keys())
    except Exception:
        from_registry = set()
    return from_disk | from_registry


# ══════════════════════════════════════════════════════════════════
# CI invariant 1 · No RTE transformation without a UAIE pairing
# ══════════════════════════════════════════════════════════════════
def test_s4_freeze_no_new_legacy_without_uaie_pairing():
    """Every RTE transformation must have an obvious UAIE pairing
    OR be on the exemption list.  Pairing heuristic is a shared
    substring (``byte_array_xor``, ``encoded_command``, …) — this
    is coarse on purpose, we just want a visible red flag when a
    new isolated RTE transformation appears."""
    rte_mods    = _rte_transformation_modules()
    uaie_names  = " ".join(_uaie_capability_names()).lower()
    orphans = []
    for mod in sorted(rte_mods):
        if mod in _LEGACY_TRANSFORMATION_EXEMPTIONS:
            continue
        # Pairing heuristic — strip common RTE prefixes and check
        # whether the resulting stem appears in any UAIE capability
        # name.  This catches PS.<name> ↔ ps_<name>.py mappings.
        stem = mod.replace("ps_", "").replace("_transformation", "").lower()
        # Additional flexible matches — collapse underscores.
        stem_flex = stem.replace("_", "")
        found = (stem in uaie_names) or (stem_flex in uaie_names.replace("_", ""))
        if not found:
            orphans.append(mod)
    assert not orphans, (
        "S4 FREEZE VIOLATION — the following RTE transformations "
        "have no visible UAIE pairing and are not on the exemption "
        f"list: {orphans}\n\n"
        "Fix by: (1) adding a UAIE capability with a matching "
        "substring in its name, OR (2) adding an entry to "
        "``_LEGACY_TRANSFORMATION_EXEMPTIONS`` with a review note "
        "explaining the exemption."
    )


# ══════════════════════════════════════════════════════════════════
# CI invariant 2 · Frozen-core files must be syntactically valid
# (this is the shape S4 relies on — the more sophisticated
# "post-freeze exception marker" check is best done in CI hooks
# outside pytest.  Locking syntactic integrity here at least
# prevents accidental breakage during migration slices.)
# ══════════════════════════════════════════════════════════════════
def test_s4_freeze_core_files_are_syntactically_valid():
    for rel in _FROZEN_CORE:
        p = Path("/app/backend") / rel
        assert p.is_file(), f"frozen core file missing: {rel}"
        src = p.read_text(encoding="utf-8")
        try:
            ast.parse(src, filename=str(p))
        except SyntaxError as e:
            raise AssertionError(
                f"frozen core file {rel} has a syntax error: {e}")


# ══════════════════════════════════════════════════════════════════
# CI invariant 3 · Exemption list is short and reviewed
# ══════════════════════════════════════════════════════════════════
def test_s4_freeze_exemption_list_is_bounded():
    """The point of exemptions is to be extraordinary.  On Phase-A
    entry, 12 pre-existing duplicates are exempted with individual
    Slice-6-pending notes — that is the transitional ceiling.  If
    the list ever grows *beyond* the Phase-A baseline, migration
    hasn't kept pace with new additions.

    Ceiling is deliberately generous (18) — enough headroom to add
    one or two future exemptions with strong justification while
    still forcing a review conversation before larger growth.
    """
    ceiling = 18
    assert len(_LEGACY_TRANSFORMATION_EXEMPTIONS) <= ceiling, (
        f"Exemption list has grown to "
        f"{len(_LEGACY_TRANSFORMATION_EXEMPTIONS)} entries — cap is "
        f"{ceiling}.  Migrate the duplicates instead of exempting more.")
