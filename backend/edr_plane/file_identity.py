"""B3 · FILE IDENTITY — what we know about a FILE, and what we do not.

Three things this module refuses to confuse:

```
PROCESS IMAGE HASH      the hash of the executable that RAN
        !=
FILE-CREATE HASH        a hash the source reported for a file event
        !=
FILE CONTENT IDENTITY   the SHA-256 of the bytes on disk
```

A process-image SHA-256 says the binary that executed is known. It says
NOTHING about the bytes that process later wrote. So a file never
inherits a hash from the process that created it — when the source
reported none, this module reports `HASH_NOT_OBSERVED` and stops.

Path is not identity either: the same content appears under many names,
and the same name holds different content over time. Content identity is
the SHA-256; a path-only file is marked `PATH_IDENTITY_ONLY` so nothing
downstream can present a name match as a content match.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from v2.ingestion.canonical import (HASH_NOT_APPLICABLE, HASH_NOT_OBSERVED,
                                    HASH_OBSERVED)

#: WHICH OBJECT a hash identifies. Never merged.
PROCESS_IMAGE_HASH = "PROCESS_IMAGE_HASH"
FILE_CONTENT_HASH = "FILE_CONTENT_HASH"

#: How strongly a file is identified.
CONTENT_IDENTITY_SHA256 = "CONTENT_IDENTITY_SHA256"
CONTENT_IDENTITY_WEAK_HASH = "CONTENT_IDENTITY_NON_SHA256_ONLY"
PATH_IDENTITY_ONLY = "PATH_IDENTITY_ONLY"

#: How the WRITING process was established. `SOURCE_STATED_ON_FILE_EVENT`
#: is the only admissible basis: the source named the actor on the file
#: event itself. Proximity in time, path or trajectory row is not a basis.
WRITER_SOURCE_STATED = "SOURCE_STATED_ON_FILE_EVENT"
WRITER_NOT_OBSERVED = "WRITER_NOT_OBSERVED"

#: Kinds that are a FILE observation. Anything else has no file identity.
FILE_KINDS = frozenset({
    "file_create", "file_write", "file_delete", "file_rename",
    "file_creation_time_changed", "file_modify",
})


def _s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _norm_path(path: str) -> str:
    return path.replace("/", "\\").strip().lower()


def _basename(path: str) -> str:
    return _norm_path(path).split("\\")[-1] if path else ""


def _extension(name: str) -> str:
    return ("." + name.rsplit(".", 1)[1]) if "." in name.strip(".") else ""


def _iid(prefix: str, *parts: Any) -> str:
    joined = "\x1f".join(_s(p) for p in parts)
    return f"{prefix}_" + hashlib.sha256(joined.encode()).hexdigest()[:24]


@dataclass(frozen=True)
class FileObservation:
    """One OBSERVED file event, and the identity it actually supports."""
    file_key: Optional[str]
    identity_basis: str
    path: str = ""
    name: str = ""
    directory: str = ""
    extension: str = ""
    action: str = ""
    size: Optional[int] = None
    observed_at: str = ""
    hashes: dict[str, str] = field(default_factory=dict)
    hash_state: str = HASH_NOT_OBSERVED
    hash_class: str = FILE_CONTENT_HASH
    hash_reason: str = ""
    hash_provenance: dict[str, str] = field(default_factory=dict)
    signer: Optional[str] = None
    signature_state: str = "SIGNATURE_NOT_OBSERVED"
    writer_basis: str = WRITER_NOT_OBSERVED
    writer_process_guid: str = ""
    writer_pid: str = ""
    writer_image: str = ""
    tenant_id: str = ""
    endpoint_id: str = ""
    evidence_ref: str = ""
    source: str = ""
    field_provenance: dict[str, str] = field(default_factory=dict)

    @property
    def content_identified(self) -> bool:
        return self.identity_basis == CONTENT_IDENTITY_SHA256


def _identity(hashes: dict[str, str], path: str) -> tuple[Optional[str], str]:
    if hashes.get("sha256"):
        return (_iid("file", "sha256", hashes["sha256"].lower()),
                CONTENT_IDENTITY_SHA256)
    weak = hashes.get("sha1") or hashes.get("md5")
    if weak:
        # Usable as a join key, but it is NOT SHA-256 content identity and
        # says so, because collision resistance differs and downstream
        # reputation must know which digest it is trusting.
        return _iid("file", "weakhash", weak.lower()), CONTENT_IDENTITY_WEAK_HASH
    if path:
        return _iid("filepath", _norm_path(path)), PATH_IDENTITY_ONLY
    return None, PATH_IDENTITY_ONLY


def from_canonical(canonical: dict[str, Any], *, tenant_id: str = "",
                   endpoint_id: str = "",
                   evidence_ref: str = "") -> Optional[FileObservation]:
    """Canonical evidence → a FILE observation, or None if there is no file.

    Reads ONLY the `file` block. The `process` block on the same event is
    the ACTOR; its hashes are the process image's and are never promoted
    into the file's hash set.
    """
    fil = canonical.get("file") or {}
    path = _s(fil.get("path"))
    if not path:
        return None
    extra = canonical.get("additional_fields") or {}
    proc = canonical.get("process") or {}
    raw_hashes = {k.lower(): _s(v).lower()
                  for k, v in (fil.get("hashes") or {}).items() if _s(v)}
    prov = {k: _s(v) for k, v in (fil.get("field_provenance") or {}).items()}
    key, basis = _identity(raw_hashes, path)
    name = _s(fil.get("name")) or _basename(path)
    size = fil.get("size_bytes")
    if size is None:
        size = fil.get("size")
    writer_guid = _s(proc.get("process_guid"))
    writer_pid = _s(proc.get("pid"))
    writer_image = _s(proc.get("executable_path") or proc.get("name"))
    return FileObservation(
        file_key=key, identity_basis=basis, path=path, name=name,
        directory=_norm_path(path).rsplit("\\", 1)[0] if "\\" in _norm_path(path) else "",
        extension=_extension(name),
        action=_s(fil.get("action")) or _s(fil.get("operation"))
        or _s(extra.get("file_operation")) or _s(extra.get("operation")),
        size=int(size) if _s(size).isdigit() else None,
        observed_at=_s(canonical.get("event_time")),
        hashes=raw_hashes,
        hash_state=HASH_OBSERVED if raw_hashes else HASH_NOT_OBSERVED,
        hash_class=FILE_CONTENT_HASH,
        hash_reason=("the source reported a hash for this file event"
                     if raw_hashes else
                     "the source reported NO hash for this file event. The "
                     "process image hash on the same event identifies the "
                     "EXECUTABLE THAT RAN, not these bytes, and is not "
                     "promoted here"),
        hash_provenance={k: v for k, v in prov.items()
                         if k.startswith("hashes")},
        writer_basis=(WRITER_SOURCE_STATED
                      if (writer_guid or writer_pid or writer_image)
                      else WRITER_NOT_OBSERVED),
        writer_process_guid=writer_guid, writer_pid=writer_pid,
        writer_image=writer_image,
        tenant_id=_s(tenant_id or canonical.get("tenant_id")),
        endpoint_id=_s(endpoint_id or extra.get("endpoint_id")
                       or (canonical.get("host") or {}).get("host_id")),
        evidence_ref=_s(evidence_ref or canonical.get("event_id")),
        source=_s(canonical.get("source_product")
                  or canonical.get("source_vendor")),
        field_provenance=prov,
    )


def from_observation(doc: dict[str, Any]) -> Optional[FileObservation]:
    """A `v2_shadow_observations` document → a FILE observation."""
    ev = doc.get("event") or doc
    raw = ev.get("raw") or {}
    block = raw.get("file") or {}
    path = _s(block.get("path")) or _s(raw.get("target"))
    if not path or (ev.get("kind") not in FILE_KINDS and not block):
        return None
    hashes = {k.lower(): _s(v).lower()
              for k, v in (block.get("hashes") or {}).items() if _s(v)}
    key, basis = _identity(hashes, path)
    proc = ev.get("process") or {}
    name = _s(block.get("name")) or _basename(path)
    size = block.get("size")
    return FileObservation(
        file_key=key, identity_basis=basis, path=path, name=name,
        directory=_norm_path(path).rsplit("\\", 1)[0] if "\\" in _norm_path(path) else "",
        extension=_extension(name),
        action=_s(block.get("action")) or _s(ev.get("kind")),
        size=int(size) if _s(size).isdigit() else None,
        observed_at=_s(ev.get("ts") or doc.get("captured_at")),
        hashes=hashes,
        hash_state=_s(block.get("hash_state")) or (
            HASH_OBSERVED if hashes else HASH_NOT_OBSERVED),
        hash_class=FILE_CONTENT_HASH,
        hash_reason=("the source reported a hash for this file event"
                     if hashes else
                     "the source reported NO hash for this file event"),
        writer_basis=(WRITER_SOURCE_STATED
                      if (proc.get("guid") or raw.get("pid")
                          or proc.get("image")) else WRITER_NOT_OBSERVED),
        writer_process_guid=_s(proc.get("guid")),
        writer_pid=_s(raw.get("pid")),
        writer_image=_s(proc.get("image")),
        tenant_id=_s(doc.get("tenant_id")),
        endpoint_id=_s(doc.get("connector_id") or doc.get("collector_id")),
        evidence_ref=_s(doc.get("observation_id")
                        or doc.get("canonical_event_id")),
        source=_s((ev.get("provenance") or {}).get("source")),
        field_provenance=dict(raw.get("field_provenance") or {}),
    )


def process_image_identity(canonical: dict[str, Any]) -> dict[str, Any]:
    """The hash of the EXECUTABLE THAT RAN — a separate fact, kept apart.

    Returned as its own object with `hash_class=PROCESS_IMAGE_HASH` so no
    consumer can accidentally read it as the content identity of a file
    the process touched.
    """
    proc = canonical.get("process") or {}
    image = _s(proc.get("executable_path") or proc.get("name"))
    hashes = {k.lower(): _s(v).lower()
              for k, v in (proc.get("hashes") or {}).items() if _s(v)}
    if not image and not hashes:
        return {"hash_class": PROCESS_IMAGE_HASH,
                "hash_state": HASH_NOT_APPLICABLE,
                "reason": "this observation has no process image at all"}
    prov = {k: _s(v) for k, v in (proc.get("field_provenance") or {}).items()
            if k.startswith("hashes")}
    return {
        "hash_class": PROCESS_IMAGE_HASH,
        "image": image or None,
        "original_file_name": _s(proc.get("original_file_name")) or None,
        "hashes": hashes,
        "hash_state": HASH_OBSERVED if hashes else HASH_NOT_OBSERVED,
        "hash_provenance": prov,
        "image_content_key": (_iid("file", "sha256", hashes["sha256"])
                              if hashes.get("sha256") else None),
        "reason": ("the source stated the hash of the image that ran"
                   if hashes else
                   "the source stated no hash for the image that ran"),
    }


def coverage(items: Iterable[Optional[FileObservation]]) -> dict[str, Any]:
    """MEASURED file-identity coverage. No estimate, no projection."""
    rows = [i for i in items if i is not None]
    hashed = [i for i in rows if i.hash_state == HASH_OBSERVED]
    sha256 = [i for i in rows if i.hashes.get("sha256")]
    sized = [i for i in rows if i.size is not None]
    writer = [i for i in rows if i.writer_basis == WRITER_SOURCE_STATED]
    return {
        "file_observations": len(rows),
        "with_any_hash": len(hashed),
        "with_sha256": len(sha256),
        "content_identified": len(sha256),
        "path_identity_only": len(rows) - len(hashed),
        "with_size": len(sized),
        "with_source_stated_writer": len(writer),
        "hash_states": {
            HASH_OBSERVED: len(hashed),
            HASH_NOT_OBSERVED: len(rows) - len(hashed),
        },
        "note": ("`path_identity_only` files are NOT unknown-good and NOT "
                 "unknown-bad: their CONTENT was never identified, so no "
                 "reputation verdict about their bytes is possible"),
    }
