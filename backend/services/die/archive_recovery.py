"""
DIE · Recursive Archive Recovery
────────────────────────────────
Deterministic extraction and light structural analysis of common
archive containers:

    ZIP  · via stdlib ``zipfile``
    TAR  · via stdlib ``tarfile``  (also .tar.gz / .tar.bz2 / .tar.xz)
    GZIP · via stdlib ``gzip``
    7z   · via optional ``py7zr`` (skipped gracefully if absent)
    RAR  · via optional ``rarfile`` + system ``unrar`` (skipped
           gracefully if absent)

Every recovered file is fingerprinted (sha256), classified into a
coarse kind bucket (``nested_pe`` / ``nested_office`` / ``nested_pdf``
/ ``nested_archive`` / ``text`` / ``other``), and returned as a plain
Python dict.  No filesystem side effects — all extraction is done
into memory.  Callers wanting a recursive walk pass the returned
child bytes back into ``recover(child_bytes, name=…)``.
"""
from __future__ import annotations
import hashlib, io, tarfile, zipfile
from services.decoder.bounded_codecs import gzip
from typing import Any, Dict, List, Optional, Tuple
from services.decoder.resource_limits import MAX_OUTPUT, MAX_RATIO, MAX_TOTAL, DecodeLimitExceeded, charge
from services.decoder.isolated import entry

try:
    import py7zr        # type: ignore
    _HAS_7Z = True
except Exception:       # pragma: no cover
    _HAS_7Z = False

try:
    import rarfile      # type: ignore
    _HAS_RAR = True
except Exception:       # pragma: no cover
    _HAS_RAR = False


# ── magic-byte sniffing (deterministic) ───────────────────────────
_MAGIC_ZIP = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_MAGIC_GZ  = b"\x1f\x8b"
_MAGIC_7Z  = b"7z\xbc\xaf\x27\x1c"
_MAGIC_RAR = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")
_MAGIC_TAR_USTAR_OFFSET = 257
_MAGIC_TAR_USTAR = b"ustar"

_MAGIC_PE   = b"MZ"
_MAGIC_PDF  = b"%PDF"
_MAGIC_ELF  = b"\x7fELF"
# Office 2007+ files are ZIP-shaped; classification checks for
# `[Content_Types].xml` in the ZIP directory to identify Office.


def detect_kind(blob: bytes) -> str:
    """Return one of ``zip|tar|gzip|7z|rar|pe|pdf|elf|office|text|
    unknown``.  Deterministic — never touches the filesystem."""
    if not blob:
        return "unknown"
    if blob.startswith(_MAGIC_ZIP):
        # Peek at the ZIP central directory to see if this is an
        # Office 2007+ file.
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                names = set(z.namelist())
                if "[Content_Types].xml" in names or any(
                        n.startswith("word/") or n.startswith("xl/") or
                        n.startswith("ppt/") for n in names):
                    return "office"
        except Exception:
            pass
        return "zip"
    if blob.startswith(_MAGIC_GZ):
        return "gzip"
    if blob.startswith(_MAGIC_7Z):
        return "7z"
    if blob.startswith(_MAGIC_RAR):
        return "rar"
    if (len(blob) > _MAGIC_TAR_USTAR_OFFSET + 5
            and blob[_MAGIC_TAR_USTAR_OFFSET:_MAGIC_TAR_USTAR_OFFSET + 5]
                == _MAGIC_TAR_USTAR):
        return "tar"
    if blob.startswith(_MAGIC_PE):
        return "pe"
    if blob.startswith(_MAGIC_PDF):
        return "pdf"
    if blob.startswith(_MAGIC_ELF):
        return "elf"
    # Very rough "text" heuristic — first 512 bytes are printable.
    sample = blob[:512]
    if sample and sum(b < 32 and b not in (9, 10, 13) for b in sample) / len(sample) < 0.05:
        return "text"
    return "unknown"


def _classify_child(blob: bytes) -> str:
    """Map a recovered child's magic bytes into a coarse bucket the
    Artifact Router and CEM can consume."""
    k = detect_kind(blob)
    return {
        "pe":       "nested_pe",
        "office":   "nested_office",
        "pdf":      "nested_pdf",
        "elf":      "nested_elf",
        "zip":      "nested_archive",
        "tar":      "nested_archive",
        "gzip":     "nested_archive",
        "7z":       "nested_archive",
        "rar":      "nested_archive",
        "text":     "text",
    }.get(k, "other")


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ── extractors ────────────────────────────────────────────────────
def _extract_zip(blob: bytes) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        infos = z.infolist()
        _check_members([(i.file_size, i.compress_size) for i in infos])
        for info in infos:
            if info.is_dir():
                continue
            try:
                with z.open(info) as member:
                    data = _read_member(member)
            except Exception:
                continue
            out.append(_record(info.filename, data, info.file_size))
    return out


def _extract_tar(blob: bytes) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r|") as t:
        for index, m in enumerate(t):
            if index >= 1024:
                raise DecodeLimitExceeded("Archive member count limit exceeded")
            _check_members([(m.size, len(blob))])
            if not m.isreg():
                continue
            f = t.extractfile(m)
            if f is None:
                continue
            data = _read_member(f)
            out.append(_record(m.name, data, m.size))
    return out


def _extract_gzip(blob: bytes) -> List[Dict[str, Any]]:
    data = gzip.decompress(blob)
    return [_record("gzip.payload", data, len(data))]


def _extract_7z(blob: bytes) -> List[Dict[str, Any]]:
    if not _HAS_7Z:
        return []
    out: List[Dict[str, Any]] = []
    with py7zr.SevenZipFile(io.BytesIO(blob), mode="r") as sz:  # type: ignore
        _check_members([(i.uncompressed, len(blob)) for i in sz.list()])
        for name, bio in (sz.readall() or {}).items():
            data = _read_member(bio)
            out.append(_record(name, data, len(data)))
    return out


def _extract_rar(blob: bytes) -> List[Dict[str, Any]]:
    if not _HAS_RAR:
        return []
    out: List[Dict[str, Any]] = []
    with rarfile.RarFile(io.BytesIO(blob)) as r:  # type: ignore
        infos = r.infolist()
        _check_members([(i.file_size, i.compress_size) for i in infos])
        for info in infos:
            if info.isdir():
                continue
            with r.open(info.filename) as member:
                data = _read_member(member)
            out.append(_record(info.filename, data, info.file_size))
    return out


def _record(name: str, data: bytes, declared_size: Optional[int]) -> Dict[str, Any]:
    charge(len(data))
    return {
        "name":  name,
        "size":  len(data),
        "declared_size": declared_size,
        "sha256": _sha256(data),
        "kind":   _classify_child(data),
        "preview": data[:256].hex() if data else "",
    }


# ── public API ────────────────────────────────────────────────────
@entry()
def recover(blob: bytes, name: Optional[str] = None) -> Dict[str, Any]:
    """Recover an archive's children if ``blob`` is an archive.

    Returns:
        {"kind": <container kind>, "supported": bool,
         "children": [ {name, size, sha256, kind, preview}, ... ],
         "error": <optional error string>,
         "capabilities": {"7z": bool, "rar": bool}}
    """
    kind = detect_kind(blob or b"")
    env = {
        "kind":         kind,
        "container":    name,
        "supported":    kind in ("zip", "tar", "gzip", "7z", "rar"),
        "children":     [],
        "error":        None,
        "capabilities": {"7z": _HAS_7Z, "rar": _HAS_RAR},
    }
    try:
        if kind == "zip":
            env["children"] = _extract_zip(blob)
        elif kind == "tar":
            env["children"] = _extract_tar(blob)
        elif kind == "gzip":
            env["children"] = _extract_gzip(blob)
        elif kind == "7z":
            env["children"] = _extract_7z(blob)
            if not _HAS_7Z:
                env["error"] = "py7zr not installed — 7z skipped."
        elif kind == "rar":
            env["children"] = _extract_rar(blob)
            if not _HAS_RAR:
                env["error"] = "rarfile / unrar not installed — RAR skipped."
    except Exception as e:
        env["error"] = f"{type(e).__name__}: {e}"
    return env


@entry()
def recover_recursive(blob: bytes, name: Optional[str] = None,
                      max_depth: int = 3,
                      max_children: int = 200) -> Dict[str, Any]:
    """Walk archives-inside-archives up to ``max_depth`` levels deep.

    Deterministic — traversal is depth-first over the alphabetical
    child list so repeated runs match.  ``max_children`` caps the
    total artifacts returned across the walk (defense against zip
    bombs).
    """
    if not (0 <= max_depth <= 12 and 1 <= max_children <= 256):
        raise DecodeLimitExceeded("Archive recursion/candidate limit exceeded")
    walked: List[Dict[str, Any]] = []
    seen_sha: set = set()

    def _walk(b: bytes, container: Optional[str], depth: int):
        if depth > max_depth or len(walked) >= max_children:
            return
        env = recover(b, name=container)
        for c in sorted(env["children"], key=lambda x: x["name"]):
            if len(walked) >= max_children:
                break
            if c["sha256"] in seen_sha:
                continue
            seen_sha.add(c["sha256"])
            record = {**c, "depth": depth, "parent": container}
            walked.append(record)
            if c["kind"] == "nested_archive":
                # Re-read the child bytes for recursion.
                # (Deterministic: we walk by name-sorted children.)
                # NB: children preview is hex-only, so we re-extract.
                try:
                    child_bytes = _reread_child(b, c["name"])
                    if child_bytes is not None:
                        _walk(child_bytes, c["name"], depth + 1)
                except Exception:
                    continue

    _walk(blob, name, 0)
    return {
        "root": name, "walked": walked, "total": len(walked),
        "max_depth": max_depth, "max_children": max_children,
        "capabilities": {"7z": _HAS_7Z, "rar": _HAS_RAR},
    }


def _reread_child(container: bytes, child_name: str) -> Optional[bytes]:
    """Best-effort re-read of a named child from any supported
    container.  Used by ``recover_recursive`` to descend without
    passing raw payloads through the JSON layer."""
    kind = detect_kind(container)
    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(container)) as z:
                info = z.getinfo(child_name)
                _check_members([(info.file_size, info.compress_size)])
                with z.open(info) as member:
                    return _read_member(member)
        if kind == "tar":
            with tarfile.open(fileobj=io.BytesIO(container)) as t:
                f = t.extractfile(child_name)
                return _read_member(f) if f else None
        if kind == "gzip":
            return gzip.decompress(container)
        if kind == "7z" and _HAS_7Z:
            with py7zr.SevenZipFile(io.BytesIO(container), mode="r") as sz:  # type: ignore
                _check_members([(i.uncompressed, len(container)) for i in sz.list()])
                got = sz.read([child_name]) or {}
                bio = got.get(child_name)
                return _read_member(bio) if bio else None
        if kind == "rar" and _HAS_RAR:
            with rarfile.RarFile(io.BytesIO(container)) as r:  # type: ignore
                info = r.getinfo(child_name)
                _check_members([(info.file_size, info.compress_size)])
                with r.open(info) as member:
                    return _read_member(member)
    except Exception:
        return None
    return None


def _check_members(sizes):
    if len(sizes) > 1024 or sum(s for s, _ in sizes) > MAX_TOTAL:
        raise DecodeLimitExceeded('Archive member/aggregate limit exceeded')
    if any(s > min(MAX_OUTPUT, max(1024, c*MAX_RATIO)) for s, c in sizes):
        raise DecodeLimitExceeded('Archive output/ratio limit exceeded')

def _read_member(stream):
    data = stream.read(MAX_OUTPUT+1)
    if len(data) > MAX_OUTPUT:
        raise DecodeLimitExceeded('Archive member output limit exceeded')
    return data
