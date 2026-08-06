# NivXRay Investigation Architecture v1.0 (FROZEN)

> **Frozen 2026-02-06 by user directive.**
> This document is the single, authoritative architectural spec for NivXRay.
> Any code change that violates it must first change this document AND the
> WORKSPACE_ARCHITECTURE_RULES.md.

## Three Permanent Principles

1. **The Workspace never changes again.** Paste · Upload · URL · Drag & Drop, forever.
2. **Every input becomes the same Investigation Evidence Package (IEP).**
3. **Every downstream engine only understands IEP.** No engine ever parses PDFs, images, EVTX, PCAP, etc.

Everything else is implementation detail.

---

## Pipeline

```
                         NivXRay Workspace
               (Paste • Upload • URL • Drag & Drop)
                                │
                                ▼
                  Universal Input Router (UIL)
                                │
                                ▼
                       Input Classification
        ┌───────────────────────┴────────────────────────┐
        ▼                                                ▼
   Text / Structured                              Binary / Complex
(Command, URL, JSON, XML)        (Image, PDF, DOCX, EML, EVTX, PCAP,
                                         ZIP, Memory, Malware...)
        │                                                │
        │                                                ▼
        │                                   Evidence Adapter Layer
        │                                                │
        │                        ┌─────────────────────────────────┐
        │                        │ Content Extraction              │
        │                        │ Structure Extraction            │
        │                        │ Metadata Extraction             │
        │                        │ Artifact Extraction             │
        │                        │ Normalization                   │
        │                        └─────────────────────────────────┘
        │                                                │
        └───────────────────────────────┬────────────────┘
                                        ▼
                Investigation Evidence Package (IEP)
                                        │
                                        ▼
                          Evidence Validation Layer
                                        │
                           (Quality • Confidence • Sanity)
                                        │
                                        ▼
                    Investigation Orchestrator (Recursive)
                                        │
          ┌─────────────────────────────┼─────────────────────────────┐
          ▼                             ▼                             ▼
        IDA                           DIE                            ICE
 Decode / Analyze          Investigation Engine          Correlation Engine
          └─────────────────────────────┼─────────────────────────────┘
                                        ▼
                         IOC Intelligence Engine
                                        ▼
                    Evidence Reasoning Engine (SSOT)
                                        ▼
                  Investigation Session + Workspace
```

---

## IEP Schema (canonical)

```jsonc
{
  "source":        { "kind": "image|pdf|url|command|...",
                     "filename": "...", "sha256": "..." },
  "provenance":    { "captured_at": "...", "adapter": "...",
                     "adapter_version": "..." },
  "metadata":      { /* EXIF, PDF author, MIME tree, cert chain, ... */ },
  "content":       { "text": "...", "blocks": [ ... ] },
  "artifacts":     [ { "type": "command|url|hash|ip|domain|registry|...",
                        "value": "...", "confidence": 0.98,
                        "source": "OCR Block 3" } ],
  "relationships": [ { "from": "curl.exe", "verb": "downloads",
                        "to": "update.msi" } ],
  "warnings":      [ "OCR confidence low", "Encrypted PDF", ... ],
  "statistics":    { "commands": 12, "urls": 7, "hashes": 18,
                       "registry_keys": 5, "certificates": 2 }
}
```

**Do not shrink this schema.** These fields solve future problems before they happen.

---

## Component Responsibilities (short form)

| # | Component | Responsibility | May NOT do |
|---|---|---|---|
| 1 | **Workspace** | Collect analyst input (paste/upload/URL/DnD) | Analyze anything |
| 2 | **UIL (Universal Input Router)** | Only entry point → `POST /api/investigate` | Bypass to legacy paths |
| 3 | **Evidence Adapter Layer** | Convert raw evidence → IEP (content/structure/metadata/artifacts/normalize) | Perform investigation |
| 4 | **IEP** | Canonical package all engines consume | Contain raw bytes without normalization |
| 5 | **Evidence Validation** | Reject OCR garbage (`l0.0.0.l`, `PowerShe11`), enforce format sanity | Modify content |
| 6 | **Investigation Orchestrator** | Schedule, recurse, prioritize, fan out | Parse formats |
| 7 | **IDA / DIE / ICE / IOC Intel** | Deterministic analysis of IEP artifacts only | Read PDFs/images/EVTX/PCAP |
| 8 | **Evidence Reasoning Engine (SSOT)** | Produce every summary, story, report, conclusion | Have any peer generator |

---

## Non-Negotiable Design Rules (mirrored in WORKSPACE_ARCHITECTURE_RULES.md)

1. **Workspace never performs analysis.** It only collects evidence.
2. **All inputs must enter through the Universal Input Router.** No bypasses. No legacy paths.
3. **Every input must become a valid IEP.** No downstream engine may consume native file formats.
4. **The Investigation Orchestrator is the only component allowed to recursively schedule investigations.**
5. **IDA, DIE, ICE, IOC Intelligence, and the Evidence Reasoning Engine must remain input-format agnostic.**
6. **Every finding must retain provenance back to the originating IEP object.** Every conclusion must be explainable.
7. **The Evidence Reasoning Engine is the single source of truth for all summaries, reports, and conclusions.**
8. **Adapters may extract evidence and obvious structural relationships, but they must never infer attacker intent, malware behavior, or analytical conclusions.** All reasoning belongs exclusively to the Evidence Reasoning Engine.

   Concrete separation:
   - **Evidence Adapter** — "I found `curl.exe` downloading `update_ms.msi`."
   - **Investigation Orchestrator** — "Investigate both artifacts recursively."
   - **ICE** — "Correlate the results."
   - **Evidence Reasoning Engine** — "This likely represents ingress tool transfer and payload delivery."

---

## Investigation Output — Identical for Every Input

Every input — image, PDF, URL, EML, EVTX, PCAP, command — must end with exactly the same analyst experience:

- Investigation Summary
- Observed Facts
- Extracted Artifacts
- Artifact Relationships
- Attack Story
- Timeline
- MITRE
- IOC Intelligence
- Confidence
- Recommendations
- Investigation Conclusion
- Evidence Graph

No exceptions.

---

## Why This Freeze

Today: Command, URL, PDF, Image.
Tomorrow: EVTX, PCAP, Memory Dump, APK, Mach-O, Office Macro, STIX bundle.
Future: any new evidence type only requires an Evidence Adapter that emits an IEP.
The Workspace remains unchanged, the investigation engines remain deterministic and artifact-first, and every investigation — regardless of its source — produces the same consistent, explainable analyst experience.

---

## Phased Migration Plan (FROZEN ORDER)

Approved 2026-02-06. Each phase establishes a stable contract for the next.
No phase may start before the previous phase has passed its contract tests.

### Phase 1 — Freeze the Contract ✅ DONE
- [x] Architecture v1.0 document
- [x] Rules R1-R7 in `WORKSPACE_ARCHITECTURE_RULES.md`

### Phase 2 — IEP Canonical Model  ← *in progress*
Foundation. Nothing else may start before this exists.
- [ ] `backend/models/iep.py` with schema + versioning
- [ ] Every UIL branch emits an IEP
- [ ] IDA / DIE / ICE consume only IEPs
- [ ] Contract tests for the model

### Phase 2.5 — IEP Contract & Validation Suite
- [ ] For every input type, a test: Input → IEP → schema-valid → artifact-count-valid → relationship-valid → provenance-valid
- [ ] Catches regressions before they reach IDA / DIE / ICE

### Phase 3 — Evidence Adapter Layer
Every adapter implements the same **Adapter Contract** interface so
new evidence types (APK, IPA, Mach-O, ELF, PCAP, memory dumps) later
become one-file plug-ins.

**Adapter Contract** (`backend/services/adapters/base.py`):
```python
class EvidenceAdapter(Protocol):
    name:            str
    version:         str
    def can_handle(raw) -> bool: ...
    def extract(raw)  -> IEPContent: ...
    def normalize(content) -> List[IEPArtifact]: ...
    def discover_relationships(content, artifacts) -> List[IEPRelationship]: ...
    def make_iep(raw, **ctx) -> IEP: ...
    def validate(iep) -> List[IEPWarning]: ...
    def recurse(iep)  -> List[Artifact]: ...  # artifacts requiring child IEP
```

**Relationship discovery** — adapters emit *obvious structural* edges
they already know from their input shape.  This makes the IEP much
richer without any reasoning-engine involvement (R8):
- URL → `downloads` → MSI
- DLL → `exports` → `Run()`
- Email → `contains` → Attachment
- PDF → `contains` → URL
- ZIP → `contains` → EXE
- `curl.exe` → `downloads` → `update_ms.msi`

**ZIP recursion policy** — a ZIP MUST NEVER produce one huge IEP.
Instead the ZIP adapter emits a parent inventory IEP plus one child IEP
per member.  Every child is investigated independently:

```
invoice.zip → Parent IEP (inventory + relationships)
               ├── PDF IEP  (child)
               ├── JS  IEP  (child)
               └── PNG IEP  (child)
```

Order within Phase 3 (deterministic-first, OCR last):

#### Phase 3A · Deterministic Adapters
1. Text (pass-through)
2. URL (leverages existing `acquisition.py`)
3. PDF (pdfplumber + PyMuPDF)
4. DOCX (python-docx)

#### Phase 3B · Recursive Evidence  *(proves the recursion pipeline)*
5. EML (email.parser + attachment recursion — phishing / header / SPF / DKIM / DMARC value)
6. ZIP (inventory + child-IEP recursion)

#### Phase 3C · Visual Evidence  *(only introduced after 3A + 3B are proven)*
7. Image (Tesseract OCR + EXIF + layout + diagram parsing)

Rationale: OCR carries the most uncertainty (layout, confidence, false
positives).  Building it first would mask whether bugs originate in the
IEP, the adapter, the OCR engine, or the downstream pipeline.  Landing
deterministic adapters first isolates OCR-specific issues.

### Phase 4 — Investigation Orchestrator
- [ ] Validate → normalize → deduplicate artifacts
- [ ] Schedule recursive investigations, control recursion depth, merge results
- [ ] The traffic controller of the platform

### Phase 5 — Evidence Validator
Own phase because it protects the recursive engine.
- [ ] Reject OCR-garbage IPs (`l0.0.0.l`), corrupted hashes, bad URLs, false OCR commands, malformed email headers
- [ ] Only validated artifacts become investigation inputs

### Phase 6 — Evidence Reasoning Engine (SSOT)
- [ ] Unify Investigation Summary · Executive · Technical · NIST · PDF · Recommendations · Confidence · Observed vs Inferred
- [ ] One reasoning object, many projections

### Phase 7 — Legacy Purge (Last)
Only after all regression tests pass.
- [ ] Remove legacy convergence decoder path
- [ ] Remove old routing / duplicate models / deprecated endpoints
- [ ] Freeze the Workspace behavior
