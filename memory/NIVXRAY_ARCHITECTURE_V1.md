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

## Phased Migration Plan

The codebase already has most primitives (UIL, IDA-2/4, DIE, ICE, IOC Intelligence, session_narrative). What remains:

### Phase 1 — Freeze the contract (docs + rules)  ← *this commit*
- [x] Save architecture v1.0 doc
- [x] Update WORKSPACE_ARCHITECTURE_RULES.md with the 7 rules
- [ ] Kill the legacy convergence workspace decoder path for binary uploads

### Phase 2 — IEP canonical model
- [ ] Add `backend/models/iep.py` with the exact schema above
- [ ] Refactor UIL to emit IEP (not per-type dicts) from every classification branch
- [ ] Update IDA/DIE/ICE signatures to accept IEP only

### Phase 3 — Evidence Adapter Layer
- [ ] Rename `backend/services/uil/preprocess/` → `backend/services/adapters/`
- [ ] Adapters: `image_adapter` (Tesseract OCR + EXIF), `pdf_adapter` (pdfplumber + PyMuPDF), `docx_adapter` (python-docx), `eml_adapter` (email.parser + attachments)
- [ ] Every adapter returns an IEP

### Phase 4 — Evidence Validation Layer
- [ ] New `backend/services/validation/` — hash-format, domain-syntax, IP-syntax, URL-validity, registry-format, command-confidence, OCR-confidence
- [ ] Runs between adapter output and orchestrator input
- [ ] Emits `warnings[]` into the IEP

### Phase 5 — Investigation Orchestrator
- [ ] Rename `SessionAdapter` → `InvestigationOrchestrator`
- [ ] Consolidate recursive fan-out into it
- [ ] Ensure only it schedules downstream engines

### Phase 6 — Evidence Reasoning Engine consolidation
- [ ] Merge `summary_narrative.py` + `nist_report.py` executive/analyst/technical generators into a single `evidence_reasoning_engine.py`
- [ ] Every projection (Investigation Summary, Attack Story, PDF, NIST report, Executive Summary, Analyst Summary) reads from ONE synthesizer
- [ ] Kill any duplicate narrative producers

### Phase 7 — Legacy purge
- [ ] Remove old convergence decoder from workspace flow
- [ ] Remove `/api/session/investigate` in favour of `/api/investigate`
- [ ] Freeze `WorkspacePage.jsx` — no per-format branches allowed
