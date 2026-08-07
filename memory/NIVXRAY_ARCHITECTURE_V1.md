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

═════════════════════════════════════════════════════════════════════
## R24 · Investigation Performance Contract (2026-08-07 · PERMANENTLY FROZEN)
═════════════════════════════════════════════════════════════════════

Every investigation MUST emit an immutable, projectable
``metadata.performance{}`` block that captures the full life-cycle
performance of the case — backend AND frontend — so historical
cases are as reproducible in HOW they executed as they are in
WHAT evidence they produced.

### Mandatory schema
```
metadata.performance {
  backend_ms:            float   // total render time
  stages_ms:             {stage → ms}
  warnings:              string[]
  budget_total_ms:       float   // = 3000
  budget_hit:            bool
  peak_memory_mb:        float   // tracemalloc peak during render
  peak_rss_kb:           int     // OS-level RSS at end of render
  decode_layers:         [{stage, bytes_in, bytes_out, ratio, elapsed_ms}]
  truncation:            {behaviors_capped, budget_hit}
  engine_health:         {engine → "ok" | "error:*"}
  input_bytes:           int
  frontend_layout_ms:    float | null  // set by /api/telemetry/frontend
  frontend_render_ms:    float | null
  frontend_paint_ms:     float | null
  frontend_total_ms:     float | null
}
```

### Client contract
1. Every workspace paint MUST fire
   ``POST /api/telemetry/frontend`` with `{case_id, session_id,
   backend_ms, layout_ms, render_ms, paint_ms, total_ms, renders,
   layouts}`.  Fire-and-forget; never blocks the UI.
2. Frontend timings are stored under
   ``workspace_cases.performance_history[]`` (rolling 500-entry
   window) and mirrored on ``frontend_telemetry`` collection
   (rolling 5000-entry window).
3. `window.__NIVXRAY_TRAJ_TELEM__ = { renders, layouts,
   lastLayoutMs }` is exposed for DevTools inspection at any time.

### Server contract
1. Backend timings emitted by ``investigation_results.render()``.
2. Peak memory captured via `tracemalloc` + `resource.getrusage()`.
3. Decode layers recorded during recursive base64 / gzip /
   powershell decoding by the DIE preprocessor.
4. All engines wrapped in an isolating stage wrapper — one engine
   failing NEVER prevents the SSOT from emitting.

### Regression contract
1. A file-based corpus harness (``tests/test_r24_raw_corpus.py``)
   auto-discovers every ``.txt`` / ``.raw`` / ``.b64`` under
   ``tests/user_reported_corpus/`` and asserts R23 + R24 SLOs.
2. Optional ``<slug>.slo.json`` overrides SLO defaults.
3. Adding a payload = dropping a file — NO code changes.
4. Determinism assertion built in: same input → byte-identical
   SSOT (excluding perf timings) across two renders.

### Non-negotiable rules
- No investigation may emit a SSOT without
  ``metadata.performance``.  A missing block is a P0 hotfix.
- Backend budget is 3000 ms.  Anything over is logged with warnings.
- Behaviors are capped at 60 (R23) — truncation is recorded on
  ``metadata.performance.truncation.behaviors_capped``.
- The user's canonical hard-payloads (including the one that
  motivated R23/R24) MUST live permanently in
  ``tests/user_reported_corpus/`` with their measured SLOs
  pinned — never remove, never weaken.

═════════════════════════════════════════════════════════════════════
## R25 · Universal Artifact Intelligence Engine (2026-08-07 · FROZEN)
═════════════════════════════════════════════════════════════════════

The core engine has ONE responsibility:
    Given any digital artifact, maximise deterministic evidence
    extraction until no further meaningful new artifact or evidence
    can be produced.

Not "universal decoder."  Not "universal analyser."  UAIE.

### Five permanent contracts (immutable)

#### 1. Artifact Contract
Every discovered object is an immutable ``Artifact``:
    { id, parent_id, lineage[], type, bytes|text, sha256, sha1, size,
      entropy, meta{}, discovered_at, discovered_by }
Immutable — new observations produce NEW artifacts, never mutate old.

#### 2. Recognizer Contract
Recognizers answer ONE question: "what is this artifact?"
    recognize(artifact) → [ {type, confidence, reasons[]} ]
Reasons are EXPLAINABLE:
    reasons = [
      {"signal": "magic_bytes",         "score": +35, "detail": "1f 8b"},
      {"signal": "powershell_grammar",  "score": +20, "detail": "IEX / FromBase64String"},
      {"signal": "utf16le_pattern",     "score": +18, "detail": "…"},
      {"signal": "entropy",             "score":  +6, "detail": "H=7.9"},
    ]
Confidence = sum(reasons.score) / max_possible.
Recognizers NEVER execute analysis.  They only classify.

#### 3. Capability Contract
Capabilities perform ONE bounded analysis on ONE artifact type:
    execute(artifact) → {evidence[], child_artifacts[]}
Examples:
    · b64_decode, utf16le_decode, gzip_inflate, zlib_inflate
    · shellcode_strings, shellcode_entropy, shellcode_disasm
    · pe_parse, dotnet_parse, pdf_extract_js, office_extract_macros
    · beacon_config_parse, donut_unpack, srdi_unpack
    · xor_bruteforce_gated, rc4_recognize, aes_recognize
    · pcap_sessions, exif, ocr, lsb_steg, ja3
Capabilities emit BOTH evidence AND new child artifacts back onto
the queue.  Adding one is configuration, not architecture.

#### 4. Evidence Contract
All findings normalise into a single Evidence shape:
    { id, artifact_id, kind, value, source_capability, confidence,
      severity, reasons[], mitre_techniques[], mitre_tactics[],
      kill_chain[], location, discovered_at }
Independent of artifact type / malware family.
Family attribution is DOWNSTREAM of evidence, never upstream.

#### 5. Orchestrator Contract
Work queue (deque, FIFO).  Fingerprint-then-recognize-then-plan-
then-execute loop:

    while queue not empty AND budget remaining:
        art        = queue.pop()
        fingerprint = hash+entropy+size+magic          (cheap)
        matches    = recognizers.score(art, fingerprint)
        plan       = planner.select(matches)           (which capabilities?)
        for cap in plan:
            ev, kids = cap.execute(art)
            evidence.extend(ev)
            queue.extend(kids)
        stop_conditions:
          · no recognizer scores above threshold, OR
          · no capability produced new artifacts / new evidence, OR
          · budget (time / memory / depth) exhausted

Deterministic.  Same input → same evidence graph.  Every node in
the graph explains WHY it exists (reasons[] chain).

### Non-negotiable rules

- Recognizers never execute; capabilities never classify.
- Every confidence score has an explainable reasons[] chain.
- Evidence-before-family: no capability may depend on a family
  label being set upstream.
- Shellcode / PE / .NET / config-blob are ARTIFACTS, not termini —
  their analyzers emit child artifacts back onto the queue.
- The core engine is deterministic.  AI Copilot lives ABOVE it
  and CONSUMES the evidence graph — never produces it.
- Adding format support = adding a Recognizer + optional Capabilities.
  Never a change to the orchestrator or contracts.
- The engine's product is the EVIDENCE GRAPH, not a text report.
  Text reports / STIX / NIST / analyst summaries are downstream
  projections of the graph.

### Migration mapping (what exists → where it lands)

    Existing                              → UAIE role
    ────────────────────────────────────────────────────────────
    recursive_decoder.peel_recursively    → Orchestrator (v0)
    _DECODERS[]                           → Recognizer + Capability pair
    IUE (services.iue.understand_input)   → Recognizer.powershell_ish
    behavior_extractor rules              → Capability.behavior_scan
    ICE _build_behavior_clusters          → Downstream evidence-graph projection
    metadata.performance.decode_layers    → Orchestrator execution trace
    convergence / rc22 orchestrator       → v0 fast path (kept behind UAIE)

R25 is the destination.  R23/R24 remain in force as guardrails
(never freeze the tab, always emit performance).  R22 remains as
the UI-projection rule (behaviors → 14 MITRE lanes).

═════════════════════════════════════════════════════════════════════
## R26 · UAIE Migration Contract "B+" (2026-08-07 · PERMANENTLY FROZEN)
═════════════════════════════════════════════════════════════════════

The move from today's linear recursive decoder → the UAIE (R25) is
an ENGINE MIGRATION, not a feature sprint.  Behaviour is preserved
by contract; architecture evolves underneath.

### Governing principle
    Architecture may change.  Behavior must not.

Any commit that violates this rule is auto-reverted.

### Six-phase migration

**Phase 0 · Baseline Freeze** (must land BEFORE any Phase 1 code)
- Capture current API responses for a corpus of 20+ payloads
  (canary, multi-stage PS, encoded, gzip, shellcode, ransomware,
  PDF, DOCX, EML, ZIP, image, URL, plus every user-reported case).
- Snapshot: full SSOT JSON, decoded `output`, `iocs`, `mitre`,
  `verdict`, `verdict_card`, `metadata.performance` (excl. timings),
  `incident.behaviors[]`, `incident.timeline[]`.
- Store snapshots under ``tests/uaie_baseline/`` — immutable.
- This becomes the GOLDEN BASELINE the UAIE engine MUST match.

**Phase 1 · Contract Scaffolding**
- Implement the 5 R25 contracts as pure Python protocols:
    · ``services.uaie.artifact.Artifact``
    · ``services.uaie.recognizer.Recognizer``
    · ``services.uaie.capability.Capability``
    · ``services.uaie.evidence.Evidence``
    · ``services.uaie.orchestrator.Orchestrator``
- Nothing else.  No PE.  No Capstone.  No XOR.  No AI.  No UI.
- All modules under ``services/uaie/`` — new tree, no touching the
  legacy tree.

**Phase 2 · Port Existing Decoders Unchanged**
- Migrate today's 5 decoders to the new contracts:
    · powershell_encodedcommand → Recognizer + Capability pair
    · utf16le                    → Capability
    · base64                     → Recognizer + Capability
    · from_base64_string         → Recognizer + Capability
    · gzip                       → Recognizer + Capability
    · zlib                       → Recognizer + Capability
    · shellcode_string_scan      → Recognizer + Capability
- ZERO behaviour change.  Same input → same output.

**Phase 3 · Parallel Run + Compatibility Gate**
- Both engines run on every request.
- ``services.uaie.compat.compare(legacy_ssot, uaie_ssot)`` diffs:
    evidence, IOCs, behaviors, MITRE, timeline, verdict, report.
- Any mismatch → CI fails, PR blocked.
- Legacy engine stays the source of truth for user-facing responses.
- UAIE runs in shadow mode until deep-compare reaches 100%.

**Phase 4 · Format Plugins (only after Phase 3 passes)**
- PE, .NET, PDF, Office, Registry, ELF, MSI, LNK, MSI, CAB, ISO.
- Each plugin = one folder under ``plugins/`` with:
    · ``recognizer.py``  · ``capability.py``  · ``tests/`` · ``README.md``
- Zero core changes.  Auto-discovered at startup.

**Phase 5 · Evidence Plugins**
- Capstone, Beacon Config Parser, YARA, Sigma, Entropy, Cert,
  Imports, Resources, JA3, ImpHash, Authentihash.
- Same plugin shape.  Zero core changes.

**Phase 6 · Family Intelligence**
- Family attribution runs LAST — reads the evidence graph only.
- Cobalt Strike, Metasploit, Emotet, Qakbot, IcedID, Bumblebee, …
- Pure downstream projection.  Never gates a capability.

### Non-negotiable rules

1. **PR classification header REQUIRED.**  Every PR title / body
   must declare:  ``[CORE]``  |  ``[PLUGIN]``  |  ``[TEST]``  |
   ``[DOC]``.  CORE PRs require architectural sign-off.  PLUGIN
   PRs may merge independently once tests pass.

2. **Compatibility gate is CI-blocking.**  ``pytest
   tests/uaie_baseline_compat.py`` must pass on every PR.

3. **Zero UI changes during Phases 0-3.**  The analyst workspace
   sees the SAME data structures.  UI evolution is Phase 7+.

4. **Zero API schema changes during Phases 0-3.**  Consumers of
   ``/api/*`` see identical responses.

5. **Delete nothing during Phases 0-3.**  Both engines coexist.
   Legacy is retired ONLY after Phase 3 reaches 100% match on
   the full baseline corpus for 7 consecutive days.

6. **Plugins are device drivers.**  The core NEVER imports a
   specific recognizer by name.  Auto-discovery via
   ``plugins/*/manifest.json`` + a well-known entry point.

7. **Immutable artifacts.**  Once created, an Artifact is never
   mutated.  New observations produce new artifacts with lineage
   links.

### CI Acceptance criteria (all six required)

- ✅ Zero UI changes (git diff of frontend/src returns 0)
- ✅ Zero API schema changes (OpenAPI diff = 0)
- ✅ Zero behavioural regressions (baseline_compat.py passes)
- ✅ Existing recognizers migrated with byte-identical outputs
- ✅ Legacy + UAIE parallel-run diff = 0 for 7 consecutive days
- ✅ New capabilities land only after Phase 3 completion

### Migration is DONE when
- Legacy engine deleted (Phase 7).
- All 8 planned format plugins land as pure additions.
- Family classifier reads only the evidence graph.
- Adding a new format = drop a plugin folder, restart, done.
- Adding a new capability = drop a plugin folder, restart, done.

R26 replaces every previous decoder-related migration plan.  Any
attempt to skip Phase 0 or bypass the compatibility gate is
architecturally invalid and must be rejected in review.

### R26 Amendment (2026-08-07) — Baseline enhancements

Approved refinements to Phase 0:

**1. Baseline is a living contract** — new production cases are added
   incrementally, never a reason to delay the migration.

**2. Corpus organised by ARTIFACT CLASS (not source):**
   ``tests/uaie_baseline/01_text/`` · ``02_powershell/`` ·
   ``03_commandline/`` · ``04_archives/`` · ``05_office/`` ·
   ``06_pdf/`` · ``07_images/`` · ``08_binaries/`` ·
   ``09_shellcode/`` · ``10_network/`` · ``11_user_reported/``

**3. Per-case folder shape (4 files):**
   ``NNN_slug/{input.txt, expected.json, slo.json, metadata.json}``
   ``metadata.json``: artifact_type, origin, description,
   introduced_in, owner.

**4. Five-layer compatibility compare (all must pass):**
   - L1 Evidence          — URLs/IPs/domains/hashes/files/registry
                             /commands: EXACT match.
   - L2 Behavior          — behaviors, MITRE, timeline, children: EXACT.
   - L3 Graph structure   — parent→child topology: EXACT (ids may differ).
   - L4 Verdict           — severity EXACT, family EXACT when detected,
                             confidence MAY INCREASE never decrease
                             (a legitimate new recognizer may raise it).
   - L5 Explainability    — recognizer path, capability path,
                             evidence provenance: EXACT sequence.

**5. Execution-plan baseline** — every case snapshots not just the
   output but the ordered Recognizer → Capability chain so a
   silent chain re-routing is caught by CI.

**6. Two additional CI gates:**
   - **Determinism gate:** every payload runs 5×; artifact graph +
     evidence + verdict + execution plan MUST be byte-identical.
   - **Plugin-independence gate:** disabling any single plugin
     leaves core recognizers running; only that plugin's specific
     evidence disappears.

Any regression on L1-L3 or L5 = P0.  L4 confidence drop = P0 unless
explicitly approved in the PR.

### R25 Amendment (2026-08-07) — Investigation Ledger + 9 refinements

Approved architectural refinements before Phase 1 begins:

1. **Recognizer ≠ Capability (hard split).**
   Recognizer answers *"what is this?"* — never decodes.
   Capability answers *"given this type, what can I do?"* — decodes,
   parses, extracts, disassembles.  A single artifact type may map
   to N capabilities; the Capability Registry is the map.

2. **Artifact Store.**  Artifacts live in a store keyed by URI.
   Modules receive an ``artifact_uri``, not raw bytes.  Enables
   replay, resume, caching, distributed execution.

3. **Planner.**  The orchestrator dispatches via a Planner that
   scores queued artifacts by ``(confidence · severity · depth)``.
   FIFO is a fallback, not the contract.

4. **Global Confidence semantics.**
       0.00 Unknown · 0.25 Possible · 0.50 Likely · 0.75 High · 0.90+ Certain
   Every plugin uses the same scale.  No local buckets.

5. **Capability Registry.**  Recognizers do NOT know which
   capabilities exist.  Registry answers ``for_type(t) → [Cap…]``.

6. **Family engine is projection-only.**  Family classifiers read
   the evidence graph and emit ``Family(label, confidence, reasons[])``.
   They MUST NOT create new IOCs / URLs / MITRE entries.

7. **Investigation Ledger (NEW · 6th core contract).**  Immutable,
   append-only chronological log:
       LedgerEntry(seq, ts, artifact_uri, action, actor,
                     input_summary, output_summary, evidence_ids[],
                     children_uris[], confidence, elapsed_ms, reasons[])
   Every recognition · capability · scheduling decision · evidence
   emission appends one entry.  The ledger is the single source of
   truth for: explainability · replay · debugging · regression compare
   · AI Copilot context · audit.

8. **Capability dependencies declared, resolved by engine.**
   Capabilities declare ``requires_artifact_type: List[str]`` and
   optional ``requires_evidence: List[str]``.  Never call each other.

9. **Parallel-safe APIs.**  Contracts allow concurrent execution
   even though Phase 1 stays sequential.  No shared mutable state
   in Recognizer / Capability signatures.

10. **Stable Artifact URIs.**  Every artifact addressable as
    ``uaie://artifact/<sha256-16-hex>``.  Evidence references URIs,
    never in-memory refs.

Phase 1 deliverables (six files, protocols only, no plugins yet):
    services/uaie/{artifact.py, recognizer.py, capability.py,
                    evidence.py, ledger.py, orchestrator.py}


---

## R27 · SSOT Persistence Contract (2026-02 · PERMANENTLY FROZEN)

> "Never build a new engine while the current product cannot reliably
> restore its complete investigation state."

**Rule.**  Every saved case in ``workspace_cases`` MUST persist the full
analyst-facing Single-Source-Of-Truth bundle (``ssot``) so that reopening
a case restores 100 % of the investigation surface WITHOUT re-running
any decoder, understanding, narrative or analyze pipeline.

### Acceptance Criteria (frozen)
1. Timeline, Evidence, IUE (Input Understanding), Decoder Trace, Attack
   Story, ATT&CK Trajectory, SOC Verdict, Analyst Narrative, IEDDE Decision
   Trace and every deterministic panel render from the stored SSOT.
2. Zero calls to ``/api/die/understand``, ``/api/die/analyze`` or
   ``/api/die/narrate`` fire on case restore when ``case.ssot`` is present.
3. Workspace remains the analyst cockpit with no UI regression and no
   behavioural change vs. a freshly-analysed session.
4. Backward-compat: cases saved before R27 (no ``ssot`` field) fall back
   to the legacy recompute path — never fail.

### Persisted SSOT shape (``workspace_cases.ssot``)
```
{
  "version":                     "1.0",
  "persisted_at":                <ISO8601-UTC>,
  "understanding":               {...},   # /die/understand result
  "analyst_narrative":           {...},   # /die/narrate result
  "inline_story_preproc":        {...},   # preprocessor stages
  "investigation_object":        {...},   # canonical IEP
  "investigation_mode":          <bool>,
  "verdict_card":                {...},
  "decode_trace":                [...],
  "decode_winner_engine":        <str>,
  "decode_confidence":           <int>,
  "iedde":                       {...},
  "iedde_terminal_state":        <str>,
  "canonical_confidence":        <float>,
  "canonical_confidence_reason": <str>,
  "mitre":                       [...],
  "lolbas":                      [...],
  "semantic":                    {...},
  "reached_shellcode":           <bool>,
  "corrupted_container":         {...} | null,
  "chain":                       [...],
  "steps":                       [...],
  "predicted_tree":              {...},
  "analysis":                    {...},
  "dropped_for_size":            [...]    # optional — audit trail
}
```

### Size Safety
- Middleware allowlists ``/api/cases/save`` up to the 50 MB large-body cap.
- Backend enforces an 8 MB pickled-JSON ceiling; over-large bundles drop
  the least-critical sub-fields first (``predicted_tree`` →
  ``semantic`` → ``decode_trace`` → ``inline_story_preproc`` →
  ``analyst_narrative`` → ``investigation_object`` → ``understanding``)
  and record which ones were dropped in ``ssot.dropped_for_size``.

### Enforcement Suite
``backend/tests/test_ssot_persistence.py`` (5 tests) covers:
- Round-trip preserves every SSOT key.
- ``/api/cases`` surfaces ``has_ssot`` + ``ssot_version``.
- Oversized bundles drop gracefully.
- Upserts (re-save same name) replace SSOT.
- Legacy path (no SSOT) still saves + restores.

### R27 → UAIE
Once R27 is green, UAIE (R25/R26) can eventually replace the execution
engine WITHOUT changing how Workspace behaves — the SSOT contract is
the migration guardrail.



---

## R28 · Restore is Rendering (2026-02 · PERMANENTLY FROZEN)

> "Restore is not analysis.  Restore is rendering."

**Rule.**  When re-opening a persisted investigation (case, history,
report, deep-link) the platform MUST only deserialize, validate and
render.  It MUST NOT invoke any decoder, classifier, AI enricher,
preprocessor or LLM.

### Allowed during restore
- deserialize (load the SSOT from Mongo / immutable store)
- validate (schema, checksum, version stamp)
- render (project into UI panels)

### Forbidden during restore
- ``/api/die/understand`` / ``/die/analyze`` / ``/die/narrate``
- ``/api/decode/*`` / ``/api/analyze/*``
- ``/api/ai/*`` / any LLM call
- ``/api/troubleshoot/*``
- IOC re-enrichment / MITRE re-classification / any preprocessor

### Enforcement
- Frontend guard: ``beginRestoreMode(label)`` / ``endRestoreMode()`` in
  ``frontend/src/lib/api.js``.  Any request to a forbidden path while
  restore mode is active logs a red console banner AND fires
  ``POST /api/telemetry/frontend`` with ``kind='r28_violation'``.
- Backend guard: the dereference endpoint ``routers/ssot.py`` is
  AST-checked to import only ``load_ssot`` + ``project_artifact_trace``
  from ``services.ssot_store``.  See
  ``tests/test_ssot_persistence.py::test_ssot_endpoint_does_not_touch_business_logic``.

### Compound Version Stamp (R28.B)
Every persisted SSOT records a four-way version:
```
{ schema: "1.0",
  engine:   "legacy" | "uaie-plugin",
  uaie:     "phase0" | "phase1" | "phase2" | "phase3",
  baseline: "R27" | "R27.1" | ... }
```
Legacy R27 cases stored ``version="1.0"`` — coerced on read via
``services.ssot_store.coerce_version``.

### Artifact Trace Projection (R28.C)
The persisted ``decode_trace`` is lifted at read-time into the
canonical shape:
```
Artifact ─▶ Recognizer ─▶ Capability ─▶ Evidence ─▶ Child Artifact
```
Rendered by ``frontend/components/investigation/ArtifactTracePanel.jsx``.
The projection is future-proof: PowerShell, PE, PDF, Office, Shellcode,
Memory, and PCAP artifacts use the same shape once UAIE (R25/R26) lands.

---

## R28.1 · Immutable SSOT Store (2026-02 · PERMANENTLY FROZEN)

> "The Investigation Package is the single source of truth.
> Workspace, History, Reports and Exports reference it — they do
> not duplicate it."

**Rule.**  Every SSOT bundle is persisted into a single
content-addressable collection ``investigation_ssot`` keyed by
``investigation_id`` (UUID) with ``checksum = sha256(canonical_json)``.
Consumer documents (``workspace_cases``, ``investigations``, future
``reports`` and ``exports``) carry only a lightweight ``ssot_ref``
pointer.

### Progressive migration (Option c)
1. **Write-through** — new saves persist to ``investigation_ssot`` AND
   keep the inline ``ssot`` copy on the consumer doc for rollback
   safety and parallel-run validation.
2. **Read-preference** — reads dereference via ``ssot_ref`` when
   present; fall back to inline ``ssot`` for R27 cases; fall back to
   legacy flat fields for pre-R27 cases.
3. **Retirement** — the inline copy is dropped ONLY after the Phase 3
   compatibility gate has passed for 7 consecutive clean days (0
   graph diffs, 0 analyst-visible regressions).

### Dedupe
The content-hash address means two identical investigations collapse
to one row.  ``ref_count`` is incremented on collision and
``last_seen_at`` refreshed.

### Endpoint
``GET /api/ssot/{investigation_id}`` returns
``{ investigation_id, checksum, version, ssot, artifact_trace }`` —
pure IO + projection, R28-compliant.

### Enforcement suite
``backend/tests/test_ssot_persistence.py`` (13 tests) covers:
- Compound version stamp round-trip.
- Immutable store dereference endpoint.
- Content-hash dedupe (two identical bundles → one investigation_id).
- 404 on unknown investigation_id.
- Artifact Trace projection shape.
- Restore-is-rendering contract on the dereference router.

