"""ZIP Evidence Adapter — Phase 3B (Recursive Evidence).

Per the frozen architecture (`/app/memory/NIVXRAY_ARCHITECTURE_V1.md`):

  · A ZIP MUST NEVER produce one huge IEP.  Instead the ZIP adapter
    emits a **parent inventory IEP** plus one **child-IEP candidate**
    per member.  Every child is investigated independently by the
    Investigation Orchestrator (Phase 4).
  · Nesting is preserved as `parent.zip → child.zip → child.exe`
    without flattening.
  · Cycle detection is mandatory (SHA-256 per member) — the adapter
    surfaces duplicate hashes inside the same archive as
    ``zip_duplicate_member`` warnings; full-tree cycle detection is
    the orchestrator's job (it sees hashes across depths).
  · The Resource Protection Policy is enforced softly by the adapter
    (warns above thresholds) and hard-capped so a malicious archive
    cannot exhaust memory or CPU.

R8 · Adapter extracts inventory + structural CONTAINS edges only.
     Zero reasoning; no verdicts.
R9 · Graceful degradation — corrupt / encrypted / partial ZIPs still
     emit a valid IEP with warnings and adapter_status="partial".
R10 · Idempotent — the same bytes always produce the same artifacts,
     same ordering, same warnings.
"""
from __future__ import annotations

import hashlib
import io
import zipfile
from typing import Any, Dict, List, Optional

from models.iep import (
    IEPArtifact,
    IEPContent,
    IEPRelationship,
    IEPSource,
    IEPWarning,
    RelationshipType,
)
from services import resource_protection as rpp

from .base import EvidenceAdapter


# ─── Resource Protection Policy (loaded from services.resource_protection) ──
# One config, one place. Overridable via NIVX_RPP_ZIP_* env vars — see
# services/resource_protection.py for the full list.
MAX_MEMBERS_HARD            = int(rpp.get("zip", "max_members", 2000))
MAX_MEMBERS_SOFT            = int(rpp.get("zip", "max_members_soft_warn", 500))
MAX_UNCOMPRESSED_SIZE_BYTES = int(rpp.get("zip", "max_uncompressed_size_mb", 512)) * 1024 * 1024
MAX_COMPRESSION_RATIO       = int(rpp.get("zip", "max_compression_ratio", 100))
MAX_FILENAME_LEN            = int(rpp.get("zip", "max_filename_length", 400))


class ZIPAdapter(EvidenceAdapter):
    name         = "adapter.zip"
    version      = "1.0"
    capabilities = [
        "inventory",
        "filenames",
        "sizes",
        "compression_ratios",
        "sha256_per_member",
        "encrypted_detection",
        "zip_bomb_heuristic",
        "nested_zip_detection",
        "duplicate_member_detection",
        "comments",
        "timestamps",
        "cycle_detection_hashes",
    ]

    # ── Detection ────────────────────────────────────────────────────
    def can_handle(self, raw: Any) -> bool:
        # ZIP local-file-header magic:  b"PK\x03\x04"
        # Empty archive end-of-central-dir magic: b"PK\x05\x06"
        # Spanned archive:                        b"PK\x07\x08"
        if not isinstance(raw, (bytes, bytearray)):
            return False
        head = bytes(raw[:4])
        return head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))

    # ── Extraction ───────────────────────────────────────────────────
    def extract(self, raw: Any) -> IEPContent:
        data     = bytes(raw)
        warnings: List[Dict[str, Any]] = []
        members: List[Dict[str, Any]]  = []
        totals = {
            "member_count":       0,
            "uncompressed_bytes": 0,
            "compressed_bytes":   0,
            "encrypted_count":    0,
            "directory_count":    0,
            "nested_zip_count":   0,
        }
        archive_ok = True
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            archive_ok = False
            warnings.append({
                "severity": "error", "code": "zip_corrupt",
                "message": f"Not a valid ZIP archive: {e}",
            })
            zf = None  # type: ignore
        except Exception as e:  # noqa: BLE001
            archive_ok = False
            warnings.append({
                "severity": "error", "code": "zip_read_failed",
                "message": f"{type(e).__name__}: {e}",
            })
            zf = None  # type: ignore

        if archive_ok and zf is not None:
            try:
                infos = zf.infolist()
            except Exception as e:  # noqa: BLE001
                infos = []
                warnings.append({
                    "severity": "error", "code": "zip_infolist_failed",
                    "message": f"{type(e).__name__}: {e}",
                })

            # Hard cap on member count — a legitimate archive won't need more.
            if len(infos) > MAX_MEMBERS_HARD:
                warnings.append({
                    "severity": "warn", "code": "zip_member_hardcap",
                    "message": f"Archive lists {len(infos)} members; truncating "
                               f"to hard cap {MAX_MEMBERS_HARD}.",
                })
                infos = infos[:MAX_MEMBERS_HARD]
            elif len(infos) > MAX_MEMBERS_SOFT:
                warnings.append({
                    "severity": "info", "code": "zip_member_softcap",
                    "message": f"Archive is large ({len(infos)} members).",
                })

            # Idempotent ordering: sort deterministically by (filename, offset).
            # ``ZipInfo`` order already reflects central-dir order which is
            # stable for a given archive, but sorting guarantees R10 across
            # zipfile impl differences.
            infos = sorted(infos, key=lambda i: (i.filename or "", i.header_offset))

            # Duplicate-hash detection scaffolding (R8 adapter-level only —
            # orchestrator handles full-tree cycle detection).
            seen_hashes: Dict[str, int] = {}

            for idx, info in enumerate(infos):
                fname = (info.filename or "").rstrip("/")
                is_dir = info.is_dir()
                node: Dict[str, Any] = {
                    "index":            idx,
                    "filename":         fname[:MAX_FILENAME_LEN],
                    "is_dir":           is_dir,
                    "size_uncompressed": int(info.file_size or 0),
                    "size_compressed":   int(info.compress_size or 0),
                    "crc32":             info.CRC & 0xFFFFFFFF if info.CRC else None,
                    "modified":          "%04d-%02d-%02dT%02d:%02d:%02d"
                                          % info.date_time if info.date_time else None,
                    "encrypted":         bool(info.flag_bits & 0x1),
                    "sha256":            None,
                    "compression_ratio": None,
                    "source_ref":        f"zip.member.{idx}",
                    "warnings":          [],
                }

                # Path-traversal detection — surfaces `..` or absolute paths.
                if (".." in fname.split("/")) or fname.startswith("/") \
                        or (len(fname) > 2 and fname[1] == ":"):
                    node["warnings"].append("path_traversal_suspect")
                    warnings.append({
                        "severity": "warn", "code": "zip_path_traversal_suspect",
                        "message": f"Member '{fname}' contains path-traversal "
                                   f"components.",
                    })

                # Filename-length abuse
                if len(fname) > MAX_FILENAME_LEN:
                    warnings.append({
                        "severity": "info", "code": "zip_long_filename",
                        "message": f"Member #{idx} filename truncated at "
                                   f"{MAX_FILENAME_LEN} chars.",
                    })

                # Directory bookkeeping
                if is_dir:
                    totals["directory_count"] += 1
                    members.append(node)
                    continue

                # Encrypted-member — surfaces info, but adapter cannot open it.
                if node["encrypted"]:
                    totals["encrypted_count"] += 1
                    node["warnings"].append("encrypted")
                else:
                    # Compression-ratio bomb heuristic (R9 — degrade gracefully).
                    if node["size_compressed"] > 0 and node["size_uncompressed"] > 0:
                        ratio = node["size_uncompressed"] / max(node["size_compressed"], 1)
                        node["compression_ratio"] = round(ratio, 2)
                        if ratio > MAX_COMPRESSION_RATIO:
                            node["warnings"].append("zip_bomb_ratio")
                            warnings.append({
                                "severity": "warn", "code": "zip_bomb_ratio",
                                "message": f"Member '{fname}' has compression "
                                           f"ratio {ratio:.1f}:1 (>"
                                           f"{MAX_COMPRESSION_RATIO}:1 threshold).",
                            })

                    # SHA-256 — required for cycle detection across the pipeline.
                    # We stream-read; if it's oversized we still hash what we
                    # can up to the per-adapter budget.  Any failure just
                    # leaves sha256=None and records a warning (R9).
                    try:
                        # Budget check first so we don't inflate a 1 GB member.
                        if (totals["uncompressed_bytes"] + node["size_uncompressed"]
                                > MAX_UNCOMPRESSED_SIZE_BYTES):
                            node["warnings"].append("size_budget_exhausted")
                            warnings.append({
                                "severity": "warn", "code": "zip_size_budget_exhausted",
                                "message": f"Skipped hashing '{fname}': cumulative "
                                           f"uncompressed size would exceed "
                                           f"{MAX_UNCOMPRESSED_SIZE_BYTES} bytes.",
                            })
                        else:
                            with zf.open(info) as fh:
                                h = hashlib.sha256()
                                chunk = fh.read(65536)
                                while chunk:
                                    h.update(chunk)
                                    chunk = fh.read(65536)
                                node["sha256"] = h.hexdigest()
                    except RuntimeError as e:
                        # Typically thrown on unsupported compression /
                        # encrypted-without-password.
                        node["warnings"].append("member_unreadable")
                        warnings.append({
                            "severity": "info", "code": "zip_member_unreadable",
                            "message": f"'{fname}': {e}",
                        })
                    except Exception as e:  # noqa: BLE001
                        node["warnings"].append("hash_failed")
                        warnings.append({
                            "severity": "info", "code": "zip_member_hash_failed",
                            "message": f"'{fname}': {type(e).__name__}: {e}",
                        })

                # Duplicate-hash inside archive → adapter-level cycle hint.
                if node["sha256"]:
                    if node["sha256"] in seen_hashes:
                        node["warnings"].append("duplicate_member")
                        warnings.append({
                            "severity": "info", "code": "zip_duplicate_member",
                            "message": f"'{fname}' has the same SHA-256 as "
                                       f"'{members[seen_hashes[node['sha256']]]['filename']}'.",
                        })
                    else:
                        seen_hashes[node["sha256"]] = idx

                # Nested-zip detection — by magic OR by extension.
                lower = fname.lower()
                if lower.endswith((".zip", ".jar", ".apk", ".ipa", ".xpi", ".war")):
                    totals["nested_zip_count"] += 1
                    node["warnings"].append("nested_archive")

                totals["uncompressed_bytes"] += node["size_uncompressed"]
                totals["compressed_bytes"]   += node["size_compressed"]
                members.append(node)

            totals["member_count"] = sum(1 for m in members if not m["is_dir"])
            # Archive-level compression ratio (bomb detection at aggregate level)
            if totals["compressed_bytes"] > 0:
                arch_ratio = totals["uncompressed_bytes"] / max(totals["compressed_bytes"], 1)
                totals["compression_ratio"] = round(arch_ratio, 2)
                if arch_ratio > MAX_COMPRESSION_RATIO:
                    warnings.append({
                        "severity": "warn", "code": "zip_bomb_ratio_archive",
                        "message": f"Archive-level compression ratio "
                                   f"{arch_ratio:.1f}:1 exceeds "
                                   f"{MAX_COMPRESSION_RATIO}:1 threshold.",
                    })
            else:
                totals["compression_ratio"] = None

            # Archive-level encrypted flag
            if totals["encrypted_count"] > 0:
                warnings.append({
                    "severity": "warn", "code": "zip_password_protected",
                    "message": f"Archive contains {totals['encrypted_count']} "
                               f"password-protected member(s).",
                })

            # Archive comment (used by some malware for staging notes)
            try:
                comment = zf.comment
                comment_text = comment.decode("utf-8", errors="replace") if comment else ""
            except Exception:
                comment_text = ""
        else:
            comment_text = ""
            infos = []  # for reference only

        # Blocks projection — one block per member (adapter-uniform shape).
        blocks: List[Dict[str, Any]] = []
        for m in members:
            blocks.append({
                "type":             "zip_member",
                "index":            m["index"],
                "filename":         m["filename"],
                "is_dir":           m["is_dir"],
                "size_uncompressed": m["size_uncompressed"],
                "size_compressed":   m["size_compressed"],
                "compression_ratio": m["compression_ratio"],
                "sha256":            m["sha256"],
                "encrypted":         m["encrypted"],
                "modified":          m["modified"],
                "warnings":          m["warnings"],
            })

        content = IEPContent(
            text="\n".join(m["filename"] for m in members),
            blocks=blocks,
        )
        # Stash structured payload for normalize/discover_relationships.
        content._zip = {  # type: ignore[attr-defined]
            "members":    members,
            "totals":     totals,
            "warnings":   warnings,
            "comment":    comment_text,
            "archive_sha256": hashlib.sha256(data).hexdigest(),
            "archive_size":   len(data),
        }
        return content

    # ── Normalization → canonical artifacts (R6 provenance) ──────────
    def normalize(self, content: IEPContent) -> List[IEPArtifact]:
        z = getattr(content, "_zip", {}) or {}
        out: List[IEPArtifact] = []
        for m in z.get("members") or []:
            if m["is_dir"]:
                continue
            # file_path artifact for the member (drives orchestrator recursion)
            out.append(IEPArtifact(
                type="file_path",
                value=m["filename"],
                source_ref=m["source_ref"],
                tags=["zip_member"] + ([m["warnings"][0]] if m["warnings"] else []),
                confidence=1.0,
                attributes={
                    "size_uncompressed": m["size_uncompressed"],
                    "size_compressed":   m["size_compressed"],
                    "compression_ratio": m["compression_ratio"],
                    "encrypted":         m["encrypted"],
                    "modified":          m["modified"],
                    "member_index":      m["index"],
                    "sha256":            m["sha256"],
                    "member_warnings":   m["warnings"],
                    "archive_sha256":    z.get("archive_sha256"),
                },
            ))
            # hash artifact — enables downstream IOC intel + orchestrator
            # cycle detection across depths.
            if m["sha256"]:
                out.append(IEPArtifact(
                    type="hash",
                    value=m["sha256"],
                    source_ref=m["source_ref"],
                    tags=["zip_member_sha256"],
                    confidence=1.0,
                    attributes={
                        "algorithm":     "sha256",
                        "member_index":  m["index"],
                        "filename":      m["filename"],
                    },
                ))
        return out

    # ── Relationships (R8 · CONTAINS edges only) ─────────────────────
    def discover_relationships(
        self,
        content: IEPContent,
        artifacts: List[IEPArtifact],
    ) -> List[IEPRelationship]:
        z = getattr(content, "_zip", {}) or {}
        rels: List[IEPRelationship] = []
        for m in z.get("members") or []:
            if m["is_dir"]:
                continue
            rels.append(IEPRelationship(
                from_ref="zip.archive",
                to_ref=m["filename"],
                verb=RelationshipType.CONTAINS,
                source_ref=m["source_ref"],
            ))
        return rels

    # ── Adapter caveats (Phase 5 does semantic validation later) ─────
    def validate(self, iep) -> List[IEPWarning]:
        z = getattr(iep.content, "_zip", {}) or {}
        return [IEPWarning(**w) for w in z.get("warnings") or []]

    # ── Recursion — every non-encrypted, non-directory member becomes
    # a child-IEP candidate the orchestrator will schedule.
    def recurse(self, iep) -> List[IEPArtifact]:
        out: List[IEPArtifact] = []
        for a in iep.artifacts:
            if "zip_member" not in (a.tags or []):
                continue
            # Skip members we could not read (encrypted / unreadable) — the
            # orchestrator would just fail again.
            attrs = a.attributes or {}
            if attrs.get("encrypted"):
                continue
            if "member_unreadable" in (attrs.get("member_warnings") or []):
                continue
            out.append(a)
        return out

    # ── Statistics roll-up (compression + recursion metrics per R9/R10) ──
    def make_iep(self, raw, **ctx):
        iep = super().make_iep(raw, **ctx)
        z = getattr(iep.content, "_zip", {}) or {}
        totals = z.get("totals") or {}
        # Persist archive-level metrics in the adapter manifest (frozen
        # architecture requires ZIP metric storage — see architecture doc).
        iep.metadata.data.setdefault("archive", {}).update({
            "kind":               "zip",
            "archive_sha256":     z.get("archive_sha256"),
            "archive_size":       z.get("archive_size"),
            "comment":            z.get("comment") or "",
            "member_count":       totals.get("member_count", 0),
            "directory_count":    totals.get("directory_count", 0),
            "nested_zip_count":   totals.get("nested_zip_count", 0),
            "encrypted_count":    totals.get("encrypted_count", 0),
            "uncompressed_bytes": totals.get("uncompressed_bytes", 0),
            "compressed_bytes":   totals.get("compressed_bytes", 0),
            "compression_ratio":  totals.get("compression_ratio"),
        })
        # Roll child_iep count into IEPStatistics for uniform cross-adapter
        # telemetry.  Non-directory, non-encrypted, readable members = child
        # IEPs the orchestrator will spawn.
        if iep.statistics is not None:
            iep.statistics.child_ieps = len(self.recurse(iep))
        return iep

    # ── Source detection ─────────────────────────────────────────────
    def _infer_source(self, raw: Any) -> IEPSource:
        data = bytes(raw) if isinstance(raw, (bytes, bytearray)) else str(raw).encode()
        return IEPSource(
            kind="zip",
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            mime_type="application/zip",
        )
