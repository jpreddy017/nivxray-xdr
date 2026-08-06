"""Evidence Adapter Contract.

Frozen 2026-02-06 per `/app/memory/NIVXRAY_ARCHITECTURE_V1.md` Phase 3.

Every adapter — Text, URL, PDF, DOCX, EML, ZIP, Image, and every future
adapter (APK, IPA, Mach-O, ELF, PCAP, memory dump, STIX, Sigma, YARA) —
implements this interface.  New evidence types become one-file plug-ins.

Design invariants:

  · Adapter never touches the Workspace UI, never persists to Mongo,
    never calls IDA / DIE / ICE.  Its only job is:  raw → IEP.
  · The IEP the adapter emits MUST pass the Phase 2.5 contract suite.
  · `extract()` is pure.  `normalize()` is pure.  Both are unit-testable
    without any I/O.  `make_iep()` glues them together and stamps
    provenance via ``models.iep.make_iep``.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from models.iep import (
    IEP,
    IEPArtifact,
    IEPContent,
    IEPRelationship,
    IEPSource,
    IEPWarning,
    make_iep,
)


class EvidenceAdapter(ABC):
    """Base class every Evidence Adapter must extend.

    Rule of thumb: if it's not deterministic, mark it clearly in
    ``version`` and add a ``warnings`` entry when confidence is low.
    """

    #: Machine-readable adapter name — used in provenance (e.g. ``adapter.text``).
    name: str = "adapter.base"

    #: Semver adapter version — bump on breaking output changes.
    version: str = "0.1"

    # ── Detection ────────────────────────────────────────────────────
    @abstractmethod
    def can_handle(self, raw: Any) -> bool:
        """Return True if this adapter recognises the input.

        Called by the UIL classifier during routing.  Must be cheap —
        no network I/O, no heavy parsing.
        """

    # ── Core transforms (pure, unit-testable) ────────────────────────
    @abstractmethod
    def extract(self, raw: Any) -> IEPContent:
        """Recover text + structural blocks from the raw input.

        Never calls into IDA/DIE/ICE.  Never mutates ``raw``.
        """

    @abstractmethod
    def normalize(self, content: IEPContent) -> List[IEPArtifact]:
        """Turn the extracted content into canonical artifacts.

        Every artifact MUST carry ``source_ref`` pointing back into the
        content (line number, block index, page, byte range …) — this
        is what satisfies Rule R6 (provenance).
        """

    # ── Relationships (structural edges only — R8) ───────────────────
    def discover_relationships(
        self,
        content: IEPContent,
        artifacts: List[IEPArtifact],
    ) -> List[IEPRelationship]:
        """Return the *obvious structural* edges the adapter already
        knows about — R8 forbids anything more.

        Examples the base class expects concrete adapters to emit:

          · URL → `downloads` → MSI            (URL adapter, from `curl … <URL>`)
          · DLL → `exports`   → `Run()`         (DLL / PE adapter)
          · Email → `contains` → Attachment    (EML adapter)
          · PDF → `contains`  → URL             (PDF adapter, link map)
          · ZIP → `contains`  → EXE             (ZIP adapter, inventory)

        This makes the IEP much richer without ever crossing into
        reasoning territory (which belongs to the Evidence Reasoning
        Engine).  Default: no relationships.
        """
        return []

    # ── Glue ─────────────────────────────────────────────────────────
    def make_iep(
        self,
        raw: Any,
        *,
        source: Optional[IEPSource] = None,
        parent_iep_id: Optional[str] = None,
        pipeline_depth: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> IEP:
        """Default glue — subclasses rarely override this.

        Chains: ``extract → normalize → discover_relationships →
        validate → make_iep``.
        """
        content        = self.extract(raw)
        artifacts      = self.normalize(content)
        relationships  = self.discover_relationships(content, artifacts)
        src            = source or self._infer_source(raw)
        iep = make_iep(
            source=src,
            content=content,
            artifacts=artifacts,
            relationships=relationships,
            metadata=metadata or {},
            adapter=self.name,
            adapter_version=self.version,
            parent_iep_id=parent_iep_id,
            pipeline_depth=pipeline_depth,
        )
        iep.warnings.extend(self.validate(iep))
        return iep

    # ── Validation (per-adapter caveats, NOT the Phase 5 validator) ──
    def validate(self, iep: IEP) -> List[IEPWarning]:
        """Return adapter-level caveats (OCR confidence low, PDF
        encrypted, ZIP password-protected, EVTX record corrupt …).

        Phase 5 · Evidence Validator does the *semantic* validation of
        artifact values (`l0.0.0.l` → reject) — this method only
        surfaces adapter limitations.
        """
        return []

    # ── Recursion hook (Phase 4 orchestrator invokes this) ───────────
    def recurse(self, iep: IEP) -> List[IEPArtifact]:
        """Return artifacts that themselves warrant a new investigation.

        Example: an EML adapter returns attachment artifacts so the
        orchestrator can spawn child IEPs.  Default: no recursion.
        """
        return []

    # ── Internal helpers ─────────────────────────────────────────────
    def _infer_source(self, raw: Any) -> IEPSource:
        """Fallback source detection when the caller didn't supply one.
        Subclasses SHOULD override for correct ``kind`` and ``filename``.
        """
        return IEPSource(kind="unknown")
