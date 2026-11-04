"""
DIE Cycle B · Archive Recovery
──────────────────────────────
Deterministic recursive archive extraction — ZIP, TAR, GZIP.  7z and
RAR run only when the optional libraries are installed; those tests
are marked skip-if-unavailable so the suite passes on any host.
"""
import gzip
import io
import tarfile
import zipfile
import pytest

from services.die.archive_recovery import (
    detect_kind,
    recover,
    recover_recursive,
    _HAS_7Z, _HAS_RAR,
)


# ── magic-byte sniffing ───────────────────────────────────────────
def test_detect_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("hello.txt", "hi")
    assert detect_kind(buf.getvalue()) == "zip"

def test_detect_tar():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        data = b"hi"
        info = tarfile.TarInfo(name="hello.txt")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    assert detect_kind(buf.getvalue()) == "tar"

def test_detect_gzip():
    assert detect_kind(gzip.compress(b"hello world")) == "gzip"

def test_detect_pe():
    assert detect_kind(b"MZ\x90\x00" + b"\x00" * 60) == "pe"

def test_detect_pdf():
    assert detect_kind(b"%PDF-1.7\n%%EOF") == "pdf"

def test_detect_elf():
    assert detect_kind(b"\x7fELF" + b"\x00" * 100) == "elf"

def test_detect_office_by_content_types():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<x/>")
        z.writestr("word/document.xml", "<x/>")
    assert detect_kind(buf.getvalue()) == "office"

def test_detect_text():
    assert detect_kind(b"hello world\nsecond line") == "text"


# ── recovery ──────────────────────────────────────────────────────
def _mk_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()

def _mk_tar(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in entries:
            data = data if isinstance(data, bytes) else data.encode()
            info = tarfile.TarInfo(name=name); info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_recover_zip_children_sha256_stable():
    blob = _mk_zip([("a.txt", "hello"), ("b.txt", "world")])
    a = recover(blob); b = recover(blob)
    assert a["kind"] == "zip"
    assert a["supported"]
    assert len(a["children"]) == 2
    # deterministic — same output twice
    assert [c["sha256"] for c in a["children"]] == \
           [c["sha256"] for c in b["children"]]

def test_recover_zip_classifies_pe_child():
    pe_bytes = b"MZ\x90\x00" + b"\x00" * 512  # DOS stub
    blob = _mk_zip([("payload.exe", pe_bytes), ("readme.txt", "hello")])
    env = recover(blob)
    kinds = {c["name"]: c["kind"] for c in env["children"]}
    assert kinds["payload.exe"] == "nested_pe"
    assert kinds["readme.txt"] == "text"

def test_recover_tar():
    blob = _mk_tar([("a.txt", "hello"), ("b.bin", b"\x00" * 32)])
    env = recover(blob)
    assert env["kind"] == "tar"
    names = {c["name"] for c in env["children"]}
    assert names == {"a.txt", "b.bin"}

def test_recover_gzip_returns_payload():
    blob = gzip.compress(b"hello gzip payload")
    env = recover(blob)
    assert env["kind"] == "gzip"
    assert env["children"][0]["size"] == len("hello gzip payload")


# ── recursive ─────────────────────────────────────────────────────
def test_recursive_walk_finds_inner_archive():
    inner = _mk_zip([("secret.txt", "top-secret")])
    outer = _mk_zip([("child.zip", inner), ("readme.md", "note")])
    walk = recover_recursive(outer, name="outer.zip", max_depth=3)
    names = {w["name"] for w in walk["walked"]}
    assert "child.zip" in names
    assert "secret.txt" in names          # descended into inner zip
    depths = {w["name"]: w["depth"] for w in walk["walked"]}
    assert depths["child.zip"] == 0
    assert depths["secret.txt"] == 1

def test_recursive_walk_dedupes_by_sha256():
    # Two copies of the same file — sha-based dedup emits it once.
    dup = _mk_zip([("dup.txt", "identical"), ("dup2.txt", "identical")])
    walk = recover_recursive(dup, name="root")
    identicals = [w for w in walk["walked"] if w["sha256"] ==
                  walk["walked"][0]["sha256"]]
    assert len(identicals) == 1

def test_recursive_walk_respects_max_children():
    entries = [(f"f{i}.txt", "x") for i in range(500)]
    blob = _mk_zip(entries)
    walk = recover_recursive(blob, max_children=50)
    assert walk["total"] <= 50


# ── unsupported / graceful ────────────────────────────────────────
def test_recover_unknown_kind_is_graceful():
    env = recover(b"just random bytes not a container")
    assert env["kind"] in ("unknown", "text")
    assert env["supported"] is False
    assert env["children"] == []

@pytest.mark.skipif(_HAS_7Z, reason="py7zr installed — 7z path exercised elsewhere")
def test_seven_z_absent_returns_error_gracefully():
    # Fake 7z magic prefix — even without py7zr, no crash.
    env = recover(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)
    assert env["kind"] == "7z"
    assert env["error"] is not None
