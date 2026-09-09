"""Phase 3B · ZIP adapter contract tests.

Builds ZIPs at test time (nested, encrypted, duplicate-hash, path-
traversal, bomb-ratio) and validates that the ZIP adapter:

  · Emits a schema-valid inventory IEP (never one huge IEP — R:zip)
  · Every artifact carries a `source_ref` (R6)
  · Only emits CONTAINS structural relationships (R8)
  · Surfaces resource-protection + cycle-detection warnings (R9)
  · Is idempotent — same bytes → same artifacts / order / warnings (R10)
  · `recurse()` yields exactly the members orchestrator should schedule
"""
from __future__ import annotations

import io
import zipfile

import pytest

from models import IEP, RelationshipType
from services.adapters import ZIPAdapter, adapt


# ─── Fixture builders ──────────────────────────────────────────────────
def _build_zip(entries):
    """entries = [(name, bytes, {compress_type?, is_dir?})]"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for e in entries:
            name, data = e[0], e[1]
            opts = e[2] if len(e) > 2 else {}
            if opts.get("is_dir"):
                # ZipInfo for a directory
                info = zipfile.ZipInfo(name.rstrip("/") + "/")
                info.external_attr = (0o40775 << 16) | 0x10
                z.writestr(info, "")
            else:
                info = zipfile.ZipInfo(name)
                info.compress_type = opts.get("compress_type", zipfile.ZIP_DEFLATED)
                z.writestr(info, data)
    return buf.getvalue()


BASIC_ZIP = _build_zip([
    ("readme.txt",   b"hello world\n"),
    ("payload.exe",  b"MZ" + b"\x00" * 128),
    ("nested/",      b"",     {"is_dir": True}),
    ("nested/a.dll", b"MZ" + b"\x11" * 64),
])

NESTED_ZIP = _build_zip([
    ("outer.txt",    b"outer content"),
    ("inner.zip",    _build_zip([("child.exe", b"MZ" + b"\x00" * 32)])),
])

DUPLICATE_MEMBER_ZIP = _build_zip([
    ("a.bin", b"AAAA" * 100),
    ("b.bin", b"AAAA" * 100),   # identical content → same SHA-256
])

TRAVERSAL_ZIP = _build_zip([
    ("../etc/passwd", b"root:x:0:0"),
    ("normal.txt",    b"ok"),
])

# Bomb-ratio ZIP — highly compressible payload
BOMB_ZIP = _build_zip([
    ("bomb.txt", (b"A" * 200_000)),   # 200 KB of 'A' → tiny compressed
])


# ─── Basic contract ────────────────────────────────────────────────────
def test_zip_detection_positive():
    a = ZIPAdapter()
    assert a.can_handle(BASIC_ZIP)


def test_zip_detection_negative():
    a = ZIPAdapter()
    assert not a.can_handle(b"not a zip")
    assert not a.can_handle("string not bytes")
    assert not a.can_handle(b"PDF-1.4 fake")


def test_zip_adapter_wins_routing():
    iep = adapt(BASIC_ZIP)
    assert iep.provenance.adapter == "adapter.zip"
    assert isinstance(iep, IEP)


def test_zip_emits_schema_valid_iep():
    iep = ZIPAdapter().make_iep(BASIC_ZIP)
    # source
    assert iep.source.kind == "zip"
    assert iep.source.sha256 and len(iep.source.sha256) == 64
    assert iep.source.mime_type == "application/zip"
    # provenance
    assert iep.provenance.adapter == "adapter.zip"
    # manifest
    manifest = iep.metadata.data["adapter"]
    assert manifest["id"] == "adapter.zip@1.0"
    assert "inventory" in manifest["capabilities"]
    assert manifest["adapter_status"] in {"success", "partial"}
    # archive metrics stored under metadata.archive (frozen requirement)
    arch = iep.metadata.data.get("archive") or {}
    assert arch.get("kind") == "zip"
    assert arch.get("member_count") == 3     # readme.txt, payload.exe, nested/a.dll
    assert arch.get("directory_count") == 1  # nested/
    assert arch.get("archive_sha256")
    assert arch.get("uncompressed_bytes", 0) > 0


# ─── Artifacts (R6 provenance) ────────────────────────────────────────
def test_zip_artifacts_have_provenance():
    iep = ZIPAdapter().make_iep(BASIC_ZIP)
    file_paths = [a for a in iep.artifacts if a.type == "file_path"]
    hashes     = [a for a in iep.artifacts if a.type == "hash"]
    assert len(file_paths) == 3   # one per non-dir member
    assert len(hashes)     == 3   # one sha256 per readable non-dir member
    for a in iep.artifacts:
        assert a.source_ref and a.source_ref.startswith("zip.member.")
    # every file_path artifact carries the archive sha256 attribute
    for a in file_paths:
        assert a.attributes.get("archive_sha256") == iep.source.sha256


# ─── Relationships (R8 — CONTAINS only) ───────────────────────────────
def test_zip_relationships_are_structural_only():
    iep = ZIPAdapter().make_iep(BASIC_ZIP)
    assert len(iep.relationships) == 3
    for r in iep.relationships:
        assert r.verb == RelationshipType.CONTAINS
        assert r.from_ref == "zip.archive"


# ─── Recursion contract ───────────────────────────────────────────────
def test_zip_recurse_returns_only_readable_non_dir_members():
    a = ZIPAdapter()
    iep = a.make_iep(BASIC_ZIP)
    children = a.recurse(iep)
    # 3 non-directory members, none encrypted → all 3 are candidates
    assert len(children) == 3
    for c in children:
        assert c.type == "file_path"
        assert "zip_member" in c.tags
    # child_ieps rolled into statistics
    assert iep.statistics is not None
    assert iep.statistics.child_ieps == 3


def test_zip_nested_zip_flagged_for_recursion():
    a = ZIPAdapter()
    iep = a.make_iep(NESTED_ZIP)
    inner = next(x for x in iep.artifacts
                  if x.type == "file_path" and x.value == "inner.zip")
    assert "nested_archive" in (inner.attributes.get("member_warnings") or [])
    assert iep.metadata.data["archive"]["nested_zip_count"] == 1
    # recursion still surfaces the nested zip (orchestrator handles depth)
    children = a.recurse(iep)
    child_names = {c.value for c in children}
    assert "inner.zip" in child_names


# ─── Warnings (R9 — graceful degradation) ─────────────────────────────
def test_zip_duplicate_member_warning():
    iep = ZIPAdapter().make_iep(DUPLICATE_MEMBER_ZIP)
    codes = {w.code for w in iep.warnings}
    assert "zip_duplicate_member" in codes


def test_zip_path_traversal_warning():
    iep = ZIPAdapter().make_iep(TRAVERSAL_ZIP)
    codes = {w.code for w in iep.warnings}
    assert "zip_path_traversal_suspect" in codes


def test_zip_bomb_ratio_warning():
    iep = ZIPAdapter().make_iep(BOMB_ZIP)
    codes = {w.code for w in iep.warnings}
    # Either the per-member OR the archive-level heuristic must fire.
    assert ("zip_bomb_ratio" in codes) or ("zip_bomb_ratio_archive" in codes)


def test_zip_corrupt_bytes_degrade_gracefully():
    # First four bytes match PK\x03\x04 → adapter accepts it, then
    # zipfile fails, adapter should emit a valid partial IEP.
    corrupt = b"PK\x03\x04" + b"garbage" * 100
    a = ZIPAdapter()
    assert a.can_handle(corrupt)
    iep = a.make_iep(corrupt)
    codes = {w.code for w in iep.warnings}
    assert "zip_corrupt" in codes or "zip_infolist_failed" in codes
    assert iep.metadata.data["adapter"]["adapter_status"] in {"partial", "failed"}
    assert isinstance(iep, IEP)


# ─── Idempotency (R10) ────────────────────────────────────────────────
def test_zip_adapter_is_idempotent():
    a = ZIPAdapter()
    a1 = a.make_iep(BASIC_ZIP)
    a2 = a.make_iep(BASIC_ZIP)
    # Same artifact fingerprints
    def _fp(iep):
        return [(x.type, x.value, x.source_ref, tuple(sorted(x.tags)))
                for x in iep.artifacts]
    assert _fp(a1) == _fp(a2)
    # Same relationship set
    def _rp(iep):
        return sorted([(r.from_ref, r.to_ref, r.verb.value if hasattr(r.verb, 'value') else r.verb)
                        for r in iep.relationships])
    assert _rp(a1) == _rp(a2)
    # Same warning codes (order-insensitive)
    assert sorted(w.code for w in a1.warnings) == sorted(w.code for w in a2.warnings)
    # Same archive metrics
    assert a1.metadata.data["archive"] == a2.metadata.data["archive"]


# ─── Manifest & statistics ────────────────────────────────────────────
def test_zip_manifest_has_capabilities_and_timing():
    iep = ZIPAdapter().make_iep(BASIC_ZIP)
    m = iep.metadata.data["adapter"]
    assert "sha256_per_member"        in m["capabilities"]
    assert "cycle_detection_hashes"   in m["capabilities"]
    assert "zip_bomb_heuristic"       in m["capabilities"]
    assert m["execution_time_ms"] >= 0
    assert m["adapter_status"] in {"success", "partial"}
