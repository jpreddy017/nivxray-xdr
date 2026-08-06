"""Investigation Evidence Package (IEP) — the canonical contract every
NivXRay component consumes downstream of the Universal Input Router.

Frozen 2026-02-06 per `/app/memory/NIVXRAY_ARCHITECTURE_V1.md`.  Every
downstream engine (IDA, DIE, ICE, IOC Intelligence, Evidence Reasoning
Engine) may only accept an ``IEP`` — never a raw PDF, image, EVTX, PCAP,
or any other native format.

Non-negotiable design rules (mirrored in WORKSPACE_ARCHITECTURE_RULES.md):

  R3  Every input must become a valid IEP.  No engine consumes native
      file formats.
  R5  Engines must remain input-format agnostic — they read
      ``iep.artifacts`` only.
  R6  Every finding must retain provenance back to the originating IEP
      object (see :class:`IEPProvenance`).

Schema versioning
─────────────────
Backwards-compatible additions bump the *minor* version.  Any breaking
change bumps the *major* version and MUST also update the frozen
architecture doc.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ─── Schema version ────────────────────────────────────────────────────
IEP_SCHEMA_VERSION = "1.0.0"


# ─── Canonical vocabularies ────────────────────────────────────────────
# Deliberately open string types so adapters can emit new sources /
# artifact families without a Pydantic bump — the validator (Phase 5)
# will constrain acceptance later.


class RelationshipType(str, Enum):
    """Authoritative enum of relationship verbs adapters may emit — R8.

    Frozen 2026-02-06.  New verbs must be added here (never as free-form
    strings on relationships).  If an adapter needs to describe an
    edge that isn't in the enum yet, it emits :attr:`UNKNOWN` and
    stores the intended label in
    :attr:`IEPRelationship.original_relationship`.

    Grouped by intent:

      Containment / composition — CONTAINS, ATTACHES, EMBEDS, EXTRACTED_FROM
      Data movement            — DOWNLOADS, UPLOADS, WRITES, READS
      Execution                — EXECUTES, SPAWNS, LOADS, INJECTS
      Code linkage             — IMPORTS, EXPORTS, CALLS
      Network                  — HOSTED_ON, RESOLVES_TO, CONNECTS_TO
      Referential              — REFERENCES, MENTIONS, ATTRIBUTED_TO
      Identity / signing       — SIGNED_BY, TRUSTS
    """

    # Containment / composition
    CONTAINS         = "contains"
    ATTACHES         = "attaches"
    EMBEDS           = "embeds"
    EXTRACTED_FROM   = "extracted_from"
    # Data movement
    DOWNLOADS        = "downloads"
    UPLOADS          = "uploads"
    WRITES           = "writes"
    READS            = "reads"
    # Execution
    EXECUTES         = "executes"
    SPAWNS           = "spawns"
    LOADS            = "loads"
    INJECTS          = "injects"
    # Code linkage
    IMPORTS          = "imports"
    EXPORTS          = "exports"
    CALLS            = "calls"
    # Network
    HOSTED_ON        = "hosted_on"
    RESOLVES_TO      = "resolves_to"
    CONNECTS_TO      = "connects_to"
    # Referential (article / report structural signals)
    REFERENCES       = "references"
    MENTIONS         = "mentions"
    ATTRIBUTED_TO    = "attributed_to"
    # Identity / signing
    SIGNED_BY        = "signed_by"
    TRUSTS           = "trusts"
    # Forward-compatibility escape hatch — see IEPRelationship docstring.
    UNKNOWN          = "unknown"


InputKind = Literal[
    # Text / structured
    "command",
    "text",
    "url",
    "json",
    "xml",
    "html",
    "yaml",
    "csv",
    # Binary / complex
    "image",
    "pdf",
    "docx",
    "eml",
    "evtx",
    "pcap",
    "zip",
    "memory_dump",
    "malware_sample",
    # Structured intel
    "stix",
    "sigma",
    "yara",
    # Fallback
    "unknown",
]

ArtifactType = Literal[
    "command",
    "url",
    "domain",
    "ip",
    "hash",
    "file_path",
    "registry_key",
    "email_address",
    "user_account",
    "process_name",
    "service_name",
    "port",
    "cve",
    "mitre_technique",
    "threat_actor",
    "malware_family",
    "certificate",
    "bitcoin_address",
    "yara_rule",
    "sigma_rule",
    "unknown",
]


# ─── Sub-models ────────────────────────────────────────────────────────
class IEPSource(BaseModel):
    """Origin of the evidence — populated by the UIL when the input first
    lands.  Once written, treat as immutable."""

    kind:         InputKind = "unknown"
    filename:     Optional[str] = None
    sha256:       Optional[str] = None
    size_bytes:   Optional[int] = None
    mime_type:    Optional[str] = None
    raw_preview:  Optional[str] = Field(
        default=None,
        description="First ~256 chars of the raw input for analyst review.",
    )
    url:          Optional[str] = None

    model_config = ConfigDict(extra="allow")


class IEPProvenance(BaseModel):
    """Chain-of-custody for R6.  Tells the analyst which adapter emitted
    the package, when, and how."""

    captured_at:      datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    adapter:          str = "uil"
    adapter_version:  str = "0.1"
    parent_iep_id:    Optional[str] = Field(
        default=None,
        description="If this IEP was produced by recursive investigation of an "
                    "artifact from a previous IEP, that IEP's id is recorded here.",
    )
    pipeline_depth:   int = 0

    model_config = ConfigDict(extra="allow")


class IEPMetadata(BaseModel):
    """Format-specific metadata harvested by the adapter — EXIF for
    images, author/producer for PDFs, MIME tree for EML, cert chain
    for binaries, ZIP structure for archives, etc.  Free-form because
    metadata differs by adapter."""

    data: Dict[str, Any] = Field(default_factory=dict)


class IEPContent(BaseModel):
    """Adapter-normalized content.  ``text`` is the flattened plaintext
    projection every engine can grep.  ``blocks`` preserves structural
    boundaries the adapter recovered (OCR blocks, PDF sections, EML
    parts, EVTX records, PCAP frames, …)."""

    text:    Optional[str] = None
    blocks:  List[Dict[str, Any]] = Field(default_factory=list)


class IEPArtifact(BaseModel):
    """A single canonical artifact extracted from the evidence.

    Every downstream engine reads ``artifacts`` — never the raw content.
    The ``source_ref`` field satisfies R6 (provenance to originating
    location within the IEP: OCR block index, PDF page, byte range, …).
    """

    id:           str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    type:         ArtifactType
    value:        str
    confidence:   float = Field(default=1.0, ge=0.0, le=1.0)
    source_ref:   Optional[str] = Field(
        default=None,
        description="Human-readable pointer (e.g. 'OCR Block 3', 'pdf.page.5', "
                    "'eml.attachment.1', 'text.line.42') to origin inside IEP.",
    )
    canonical:    Optional[str] = Field(
        default=None,
        description="Normalized / canonical form (e.g. HKLM → HKEY_LOCAL_MACHINE).",
    )
    tags:         List[str] = Field(default_factory=list)
    attributes:   Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class IEPRelationship(BaseModel):
    """Directed edge between two artifacts — powers the evidence graph
    and the correlation engine.

    Example: `curl.exe --downloads→ https://x/y.msi`

    ``verb`` uses the authoritative :class:`RelationshipType` enum.  If
    an adapter needs to describe an edge that isn't yet in the enum,
    it MUST emit ``verb=RelationshipType.UNKNOWN`` and record the
    original label in ``original_relationship``.  This preserves
    forward compatibility without free-form sprawl (per user
    directive 2026-02-06).
    """

    from_ref:  str = Field(description="Artifact id or artifact value the edge starts from")
    to_ref:    str = Field(description="Artifact id or artifact value the edge ends at")
    verb:      "RelationshipType" = Field(
        description="Canonical relationship type — see RelationshipType.",
    )
    original_relationship: Optional[str] = Field(
        default=None,
        description="When verb=UNKNOWN, the free-form label the adapter "
                    "wanted to emit (e.g. `calls_api`, `pins_certificate`).",
    )
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_ref: Optional[str] = None

    model_config = ConfigDict(extra="allow", use_enum_values=False)

    # Accept plain strings for `verb` — coerce into the enum, falling
    # back to UNKNOWN + original_relationship so adapters can pass
    # either shape safely.
    @field_validator("verb", mode="before")
    @classmethod
    def _coerce_verb(cls, v: Any) -> "RelationshipType":
        if isinstance(v, RelationshipType):
            return v
        if isinstance(v, str):
            try:
                return RelationshipType(v.lower())
            except ValueError:
                return RelationshipType.UNKNOWN
        return RelationshipType.UNKNOWN


class IEPWarning(BaseModel):
    """Adapter-level caveat surfaced to the analyst (OCR confidence low,
    encrypted PDF, password-protected ZIP, corrupt EVTX, missing pages)."""

    severity:  Literal["info", "warn", "error"] = "warn"
    code:      str = Field(description="Machine token e.g. 'ocr_low_confidence', 'pdf_encrypted'")
    message:   str

    model_config = ConfigDict(extra="allow")


class IEPStatistics(BaseModel):
    """Adapter-computed counts.  Populated automatically by
    :func:`make_iep` from ``artifacts`` if the adapter didn't set them."""

    commands:      int = 0
    urls:          int = 0
    domains:       int = 0
    ips:           int = 0
    hashes:        int = 0
    file_paths:    int = 0
    registry_keys: int = 0
    certificates:  int = 0
    cves:          int = 0
    mitre:         int = 0
    other:         int = 0

    model_config = ConfigDict(extra="allow")

    @classmethod
    def from_artifacts(cls, artifacts: List[IEPArtifact]) -> "IEPStatistics":
        buckets = {
            "command":       "commands",
            "url":           "urls",
            "domain":        "domains",
            "ip":            "ips",
            "hash":          "hashes",
            "file_path":     "file_paths",
            "registry_key":  "registry_keys",
            "certificate":   "certificates",
            "cve":           "cves",
            "mitre_technique": "mitre",
        }
        stats = {v: 0 for v in buckets.values()}
        other = 0
        for a in artifacts:
            key = buckets.get(a.type)
            if key:
                stats[key] += 1
            else:
                other += 1
        return cls(**stats, other=other)


# ─── Root model ────────────────────────────────────────────────────────
class IEP(BaseModel):
    """Investigation Evidence Package — the ONE object every downstream
    engine reads.  Constructed by the Evidence Adapter Layer, validated
    by the Evidence Validator, consumed by the Investigation Orchestrator
    and every engine below it.

    Do NOT pass raw bytes, native file formats, or per-adapter dicts to
    engines.  If your engine needs something it can't find in an IEP,
    add it to the schema — do not smuggle it in.
    """

    # Identity
    id:              str = Field(default_factory=lambda: f"iep_{uuid.uuid4().hex[:20]}")
    schema_version:  str = IEP_SCHEMA_VERSION

    # Origin & chain-of-custody
    source:          IEPSource
    provenance:      IEPProvenance = Field(default_factory=IEPProvenance)

    # Adapter output
    metadata:        IEPMetadata = Field(default_factory=IEPMetadata)
    content:         IEPContent  = Field(default_factory=IEPContent)
    artifacts:       List[IEPArtifact]     = Field(default_factory=list)
    relationships:   List[IEPRelationship] = Field(default_factory=list)

    # Analyst caveats
    warnings:        List[IEPWarning] = Field(default_factory=list)

    # Roll-ups (auto-derived if not set)
    statistics:      Optional[IEPStatistics] = None

    model_config = ConfigDict(extra="allow")

    # ── Convenience helpers ──────────────────────────────────────────
    def by_type(self, artifact_type: ArtifactType) -> List[IEPArtifact]:
        """Return every artifact of the given canonical type."""
        return [a for a in self.artifacts if a.type == artifact_type]

    def values_of(self, artifact_type: ArtifactType) -> List[str]:
        """Return the (canonical or raw) values for a type — engines
        that only need the string list use this."""
        return [(a.canonical or a.value) for a in self.by_type(artifact_type)]

    def refresh_statistics(self) -> None:
        """Recompute :class:`IEPStatistics` from current artifacts."""
        self.statistics = IEPStatistics.from_artifacts(self.artifacts)


# ─── Factory ───────────────────────────────────────────────────────────
def make_iep(
    *,
    source:        IEPSource,
    content:       Optional[IEPContent] = None,
    artifacts:     Optional[List[IEPArtifact]] = None,
    relationships: Optional[List[IEPRelationship]] = None,
    metadata:      Optional[Dict[str, Any]] = None,
    warnings:      Optional[List[IEPWarning]] = None,
    adapter:       str = "uil",
    adapter_version: str = "0.1",
    parent_iep_id: Optional[str] = None,
    pipeline_depth: int = 0,
) -> IEP:
    """Adapter-friendly constructor.  Every Evidence Adapter should
    emit its IEP via this helper so provenance, statistics, and schema
    versioning are populated uniformly."""
    arts = artifacts or []
    iep = IEP(
        source=source,
        provenance=IEPProvenance(
            adapter=adapter,
            adapter_version=adapter_version,
            parent_iep_id=parent_iep_id,
            pipeline_depth=pipeline_depth,
        ),
        metadata=IEPMetadata(data=metadata or {}),
        content=content or IEPContent(),
        artifacts=arts,
        relationships=relationships or [],
        warnings=warnings or [],
    )
    iep.refresh_statistics()
    return iep
