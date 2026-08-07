# NivXRay Investigation Architecture v1.0 (FROZEN — FINAL)

> **Officially frozen 2026-02-06 by user directive.**
> Architecture, Contracts, and Rules are complete.  Remaining work is
> disciplined implementation of the frozen contracts.  No new
> architectural concepts may be added unless implementation uncovers a
> concrete limitation.
> Any code change that violates this document must first change this
> document AND the `WORKSPACE_ARCHITECTURE_RULES.md`.

## Status Summary

| Layer | State |
|---|---|
| Architecture | ✅ Frozen |
| Contracts    | ✅ Frozen |
| Rules        | ✅ Frozen |
| Engineering  | 🚧 In progress (Phases 3A → 7) |

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

## Views vs. Model — a Note on Projections

The **evidence graph** is a *view* of the reasoning model produced by
the Evidence Reasoning Engine — not a primary data structure.  Any
frontend visualisation (Cytoscape, React Flow, Graphviz, Mermaid,
GraphML export, …) is a projection of the same reasoning object.  This
keeps the backend independent of any specific visualisation library
and means new renderers never require touching the reasoning engine.

Consequence: helpers like `to_graph()` / `to_cytoscape_json()` /
`to_mermaid()` are Phase 6 *implementation details* of the Evidence
Reasoning Engine.  They are NOT architectural components.

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

**Adapter Manifest** — every adapter MUST emit a small self-describing
manifest into the IEP metadata under key ``adapter``.  Purpose:
debugging, provenance, upgrades, regression testing, support cases,
performance telemetry — all without inspecting logs.

```jsonc
{
  "adapter": {
    "id":                "adapter.pdf@1.0",   // stable across renames
    "name":              "adapter.pdf",
    "version":           "1.0",
    "capabilities":      ["text", "tables", "metadata", "embedded_files",
                            "javascript", "launch_actions", "signatures"],
    "warnings":          ["pdf_contains_javascript"],
    "execution_time_ms": 82,
    "adapter_status":    "success"    // success | partial | failed  (R9)
  }
}
```

The stable ``adapter.id`` (of the form ``<name>@<version>``) survives
if we ever rename an adapter, so historical investigations remain
replayable.

**Relationship model** — the ``verb`` field on every
:class:`IEPRelationship` uses the authoritative ``RelationshipType``
enum (see ``backend/models/iep.py``).  Adapters may emit either the
enum value or its lowercase string equivalent; unknown labels coerce
to ``RelationshipType.UNKNOWN`` and record their original label in
``original_relationship``.  This preserves forward compatibility
without free-form verb sprawl and gives IDE autocomplete + runtime
validation everywhere.

**Frozen verb set** (grouped by intent — extend the enum, never
introduce free-form strings):

  - Containment / composition — ``CONTAINS``, ``ATTACHES``, ``EMBEDS``, ``EXTRACTED_FROM``
  - Data movement — ``DOWNLOADS``, ``UPLOADS``, ``WRITES``, ``READS``
  - Execution — ``EXECUTES``, ``SPAWNS``, ``LOADS``, ``INJECTS``
  - Code linkage — ``IMPORTS``, ``EXPORTS``, ``CALLS``
  - Network — ``HOSTED_ON``, ``RESOLVES_TO``, ``CONNECTS_TO``
  - Referential — ``REFERENCES``, ``MENTIONS``, ``ATTRIBUTED_TO``
  - Identity / signing — ``SIGNED_BY``, ``TRUSTS``
  - Escape hatch — ``UNKNOWN`` (+ ``original_relationship``)

**ZIP recursion policy** — a ZIP MUST NEVER produce one huge IEP.
Instead the ZIP adapter emits a parent inventory IEP plus one child IEP
per member.  Every child is investigated independently.  Nesting is
preserved (`invoice.zip → child.zip → child.exe`) up to the Resource
Protection Policy limits.

Order within Phase 3 (deterministic-first, OCR last):

#### Phase 3A · Deterministic Adapters
1. Text (pass-through)
2. URL (leverages existing `acquisition.py`)
3. PDF (pdfplumber + PyMuPDF) — also extracts embedded files, embedded
   JavaScript, launch actions, annotations, forms, digital signatures,
   embedded fonts (optional), embedded images
4. DOCX (python-docx) — also comments, tracked changes, custom
   properties, document properties, external template references,
   embedded OLE, macros (.docm), embedded packages

#### Phase 3B · Recursive Evidence  *(proves the recursion pipeline)*
5. EML — flagship differentiator.  Pipeline:
   `header parsing → SPF → DKIM → DMARC → Received chain → URLs →
   attachments → each attachment becomes a child IEP → recursive
   investigation → unified Investigation Summary`.
6. ZIP (inventory + child-IEP recursion, hierarchical — no flattening) — **LANDED 2026-02-06** (`adapter.zip@1.0`, 14 contract tests)

#### Phase 3C · Visual Evidence  *(only introduced after 3A + 3B are proven)*
7. Image (Tesseract OCR + EXIF + layout + diagram parsing) — **LANDED 2026-02-06** (`adapter.image@1.0`, 13 contract tests · deterministic-first order · orientation preservation · OCR confidence + characters_detected)

Rationale: OCR carries the most uncertainty (layout, confidence, false
positives).  Building it first would mask whether bugs originate in the
IEP, the adapter, the OCR engine, or the downstream pipeline.  Landing
deterministic adapters first isolates OCR-specific issues.

### Phase 3.5 — Adapter Validation Pack
Before orchestration, prove every adapter independently against a
**real-world corpus** (not just synthetic fixtures).

Real corpus buckets:
- **PDF** — benign report, encrypted PDF, JS-carrying PDF, PDF with
  embedded executable, digitally signed PDF
- **DOCX** — normal, macro-enabled, OLE-embedded, external template,
  with comments / tracked changes
- **EML** — phishing, spoofed SPF, DKIM fail, with attachment, nested EML
- **ZIP** — nested ZIP, password-protected, zip-bomb simulation,
  duplicate hashes for cycle detection
- **Image** — malware diagram, PowerShell screenshot, IOC screenshot,
  blurry OCR, rotated image

Acceptance criteria:
- Every adapter emits a schema-valid IEP
- Every artifact carries `source_ref` (R6)
- Relationship discovery emits only structural verbs (R8)
- Adapter Manifest present in every IEP
- Resource limits are respected
- No adapter performs reasoning
- Every adapter passes the Phase 2.5 contract suite

### Phase 4 — Investigation Orchestrator
- [ ] Validate → normalize → deduplicate artifacts
- [ ] Schedule recursive investigations, control recursion depth, merge results
- [ ] The traffic controller of the platform
- [ ] Enforces the **Resource Protection Policy** (frozen):
  - Maximum recursion depth
  - Maximum extracted members (per archive)
  - Maximum expanded archive size (bytes)
  - Maximum child IEPs (per investigation)
  - Maximum execution timeout (per adapter, per orchestrator run)
  - Maximum nested archive depth
- [ ] **Cycle detection** (mandatory): SHA-256 of every child input is
      tracked; a repeat hash short-circuits recursion, emits an
      `IEPWarning(code="cycle_detected")`, and continues the rest of
      the investigation.  Guards ZIP loops, nested EML loops,
      symbolic-link loops, and repeated attachment processing.

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
rmed email headers
- [ ] Only validated artifacts become investigation inputs

### Phase 6 — Evidence Reasoning Engine (SSOT)
- [ ] Unify Investigation Summary · Executive · Technical · NIST · PDF · Recommendations · Confidence · Observed vs Inferred
- [ ] One reasoning object, many projections

### Phase 7 — Legacy Purge (Last)
Only after all regression tests pass.
- [ ] Remove legacy convergence decoder path
- [ ] Remove old routing / duplicate models / deprecated endpoints
- [ ] Freeze the Workspace behavior

---

## 🔒 Reinforced Prime Directive (2026-02-06)

Architecture v1.0 is **PERMANENTLY FROZEN**. No redesign, rename, or new
architectural concepts without a concrete implementation limitation.

### 10 Non-Negotiable Rules (R1–R10)
Kept verbatim in this file's earlier sections. Every commit MUST answer:
  1. Does this preserve Architecture v1.0?
  2. Does the Workspace stay unchanged for new evidence types?
  3. Does this preserve the IEP contract?
  4. Does this introduce reasoning into adapters? (If yes → reject.)
  5. Can the same behavior graph regenerate Timeline / MITRE / Graph / Story / Reports without recomputation?

### Canonical Behavior Model (backend source of truth · SSOT)
    Behavior {
      id, name, category,
      evidence[], commands[], artifacts[], source_refs[],
      kill_chain_phase,
      mitre_tactics[],           # PLURAL — a behavior may belong to multiple tactics
      mitre_techniques[],
      confidence,
    }

Behaviors are first-class objects. Commands are evidence.
Every visualization (Attack Story · MITRE 14-tactic matrix · Kill Chain
· Evidence Graph · Timelines · Reports) is a projection of the SAME
behavior model — never recomputed independently.

### Delta from current implementation (to be closed)
- ▸ `behavior_extractor.Behavior` currently uses `kill_chain: str[]`
  (already plural) + `mitre_tactic: str` (SINGULAR). Rename to
  `mitre_tactics: str[]` and allow multiple tactics per behavior.
  Non-breaking — add plural field, keep singular as an alias, migrate
  callers over subsequent changes.
- ▸ MITRE-tactic swim-lane component must render all 14 tactics
  (Recon, Resource Dev, Initial Access, Execution, Persistence, PrivEsc,
  Defense Evasion, Cred Access, Discovery, Lateral Movement, Collection,
  C2, Exfiltration, Impact). Collapse empty lanes automatically.
- ▸ Behavior Knowledge Base — mapping like `Base64 Decode → T1140`,
  `Registry Run Key → T1547.001`, `Shadow Copy Deletion → T1490` — lives
  ONLY in `services/reasoning/behavior_extractor.py`. Never in adapters,
  never in UI code.

═════════════════════════════════════════════════════════════════════
## R23 · Complete Decoding Contract (2026-08-07 · PERMANENTLY FROZEN)
═════════════════════════════════════════════════════════════════════

Non-negotiable end-to-end guarantees for EVERY input the analyst
provides — regardless of size, encoding depth, nesting, or number of
stages.

### Backend guarantees
1. **No partial decode surfaced as blocker.**  Every decoder / adapter /
   engine that fails MUST log the failure and continue.  A single
   decoder crashing NEVER prevents the SSOT from being emitted.
2. **Bounded resource envelope.**  Deterministic hard caps prevent any
   single input from consuming unbounded CPU/RAM:
     • Behaviors emitted           ≤ 60 per SSOT
     • Evidence per behavior       ≤ 12 rows
     • Base64 recursive depth       ≤ 8 layers
     • Regex catastrophic-backtrack watchdog: 250 ms per rule.
3. **Deterministic output.**  Same input + same engine versions →
   byte-identical SSOT.  Truncation, when it occurs, is stable
   (highest-severity first, kill-chain-earliest first).
4. **Top-level try/except in render pipeline.**  Any unexpected
   exception in `investigation_results.render()` returns a
   `partial_ssot` envelope with error breadcrumbs — never a 5xx.
5. **Never mask real failures.**  When decoding genuinely cannot
   proceed (unsupported binary, corrupt input), SSOT carries an
   explicit `decode_status: "failed"` block with reason.  Never silent.

### Frontend guarantees
1. **No black screen.**  Every projection (Trajectory, Timeline, NIST
   report, Evidence Explorer, MITRE lanes) is wrapped in a
   React ErrorBoundary that falls back to an in-place error card + a
   RELOAD button.  The workspace shell itself is unaffected.
2. **Hard render caps.**  Trajectory SVG renders ≤ 200 nodes total;
   when exceeded the diagram shows a "truncated for visibility"
   banner and links to the raw behavior list.
3. **Progressive rendering.**  Tabs are lazy; a slow projection
   never blocks the summary / timeline tabs.
4. **Every crash logged to console.**  ErrorBoundary emits the raw
   Error + component stack via `console.error` so remote debugging
   can always diagnose without an analyst screenshot.

### Testing rule
Every new adapter / behavior rule / decoder MUST ship with:
  ✓ a positive test (recognises the pattern),
  ✓ a negative test (does NOT fire on lookalikes),
  ✓ a scale test (10 KB → 1 MB input runs in < 3s and produces
      ≤ 60 behaviors).

### Enforcement
Any PR that violates R23 is rejected.  Any regression that
re-introduces a black screen or a swallowed decoder failure is a
P0 hotfix.
