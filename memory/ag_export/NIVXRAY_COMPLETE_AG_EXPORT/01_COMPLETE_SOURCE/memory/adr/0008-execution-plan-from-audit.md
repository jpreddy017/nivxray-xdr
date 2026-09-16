# ADR-0008 — Post-Audit Execution Plan (NivXRay)

**Status**: Accepted · 2026-08-11
**Author**: E1 (agent) under owner direction · Session-8
**Baseline**: [`0007-current-state-master-snapshot.md`](./0007-current-state-master-snapshot.md)
**Scope**: **planning artifact only.** No product code changes are authorised by this ADR itself. Downstream sessions consume it as their execution constitution.

---

## §1 · Purpose

Convert the 360° current-state audit (ADR-0007) into an operational execution plan that:

1. Preserves the honest strengths NivXRay ships today.
2. Prevents accidental deletion of correctly-shadowed architecture.
3. Sequences the two next-generation capabilities (Security Hardening · Server-Side File Mode) as **gates**, not as parallel feature work.
4. Defines how each shadow subsystem is promoted from shadow to authoritative, and under what evidence.
5. Locks the target promotion architecture so all future work maps onto one destination.

---

## §2 · Governing Principles (locked)

The following rules apply to every downstream session until this ADR is superseded.

### P1 · Shadow ≠ dead
No shadow-flagged subsystem may be deleted on the basis of "zero production documents." A shadow flag means the code observes without influencing outputs — that is a design choice, not a bug. Deletion requires evidence that the subsystem's contract is broken, superseded, or duplicated by a live one.

### P2 · Workspace behavior is regression-locked
Any change that reaches the Workspace request path (`WorkspacePage.jsx`, `/api/die/*`, `/api/investigation/*`, `/api/upload`, `/api/analyze/*`, `/api/cases/*`) must:
- ship with a matching test in `backend/tests/canonical/api/` or `frontend/src/**/__tests__/`.
- preserve the P0.3 payload allow-list (`iocs · lolbas · mitre · narrative · ida · confidence · health · incident_tactics · metadata · input`).
- preserve the P0.2 evidence chain gate.
- preserve Sample1 byte-identity.

### P3 · Security is a production gate, not a feature
The four security softnesses documented in ADR-0007 §12 (CORS `*` + credentials · no login throttle · unbounded archive unpack · same-process parser isolation) block external-customer exposure. They do **not** block internal development. Enterprise SoW / SaaS pricing conversations must not proceed until the P0 Security Hardening Gate closes.

### P4 · Server-Side File Mode is the foundation, not an increment
The 32 KB / 256 KB / 512 KB caps are architectural, not cosmetic. Increasing them in place would be treating the symptom. A file-store + provenance envelope + input router is required before any real telemetry adapter (Sysmon, EVTX, EDR export) can be built honestly.

### P5 · Route removal requires classification, never route-count intuition
466 operations with only ~74 frontend consumers looks like waste but is not evidence. A route may serve integration, admin, test, or machine-to-machine consumers not visible in `WorkspacePage.jsx`. Deletion only follows an evidence-backed DEAD classification from ADR-0009.

### P6 · Determinism must be test-proven
NivXRay reports carry a SHA-256 signature. Until a CI test proves that byte-for-byte re-render produces the same signature, the determinism claim is asserted, not demonstrated. This gap must be closed before any customer sees a signed report.

### P7 · No opportunistic feature expansion
No new subsystem, engine, adapter, or panel may start until (a) the current shadow subsystems have a documented promotion criterion (see §4) and (b) the security gate strategy is in place. Rationale: NivXRay's compounding cost today is duplicate pipelines, not missing capabilities.

### P8 · Documentation must track implementation
Every change to a shipping code path updates ADR-0007 (or its successor) in the same commit. `memory/PRD.md` remains the handoff pointer. Docs marked "aligned" in ADR-0007 §22 may not silently regress to "drift."

---

## §3 · The Two Realities (locked terminology)

For the remainder of NivXRay's development lifecycle, every capability is described using this two-column terminology:

```
                           NivXRay
                              │
        ┌─────────────────────┴─────────────────────┐
        │                                           │
   RC5 / DIE PATH                              v2 PATH
   ──────────────                             ────────
   LIVE                                       IMPLEMENTED
   CONNECTED                                  BUT SHADOW
   REGRESSION-LOCKED                          DISCONNECTED
        │                                           │
        ▼                                           ▼
   • services/die/*                           • v2/investigation/ikg.py
   • canonical/* (SSOT + projections)         • v2/verdict/ (engine v3)
   • /api/die/* (21 routes)                   • v2/case_engine/
   • /api/investigation/* (21 routes)         • v2/routers/ingest.py
   • WorkspacePage.jsx                        • v2/artifact_store/
```

Both realities are **preserved**. The path from RC5 to v2 is a promotion path, not a replacement.

---

## §4 · The Five Shadow Subsystems — Preservation & Promotion Criteria

Each shadow subsystem below is **kept** by default. Promotion from shadow to authoritative requires all listed criteria to be met with evidence.

### 4.1 · IKG (`NIVX_FLAG_CASE_ENGINE=shadow`)

- **State today**: 13 node types + 14 edge types coded in `backend/v2/investigation/ikg.py`. Persistence collections (`v2_case_events/entities/behaviors/relationships/reports`) contain 0 documents.
- **Recommendation**: KEEP SHADOW.
- **Promotion criteria**:
  1. Persistence writer live end-to-end (all 5 v2 case collections receive rows for a canonical test case).
  2. Every IKG node passes P0.2-equivalent provenance check.
  3. Timeline / Attack Chain / Attack Story can be re-projected from IKG and produce byte-identical output to the current canonical projections for the Sample1 case.
  4. Regression test proving Workspace output is unchanged when IKG writer is active.

### 4.2 · Verdict Engine v3 (`NIVX_FLAG_VERDICT_ENGINE_V3=shadow`)

- **State today**: full engine at `backend/v2/verdict/{engine,weights,profiles,correlation,progressions,signals}.py`. Endpoints return 503.
- **Recommendation**: KEEP SHADOW.
- **Promotion criteria**:
  1. Replay pack: for the last N canonical investigations, v3 must produce a verdict that either matches the canonical projection or has a documented, explainable delta.
  2. Adaptive Weight Profile default (`soc_balanced`) is locked and versioned.
  3. Negative-explainability path (`why_is_this_not`) has ≥ 10 registered patterns.
  4. `contributors[]` field mapping documented for every band.
  5. CI parity test between canonical projection and v3 default profile.

### 4.3 · Case Engine (`NIVX_FLAG_CASE_ENGINE=shadow` — shared with IKG)

- **State today**: schema + store scaffolding in `backend/v2/case_engine/`.
- **Recommendation**: KEEP SHADOW.
- **Promotion criteria**:
  1. All Workspace case CRUD (`/api/cases/*`, `/api/investigation/*`) can be re-served from `v2_cases` without behavior change (parity test).
  2. Dual-write on for 30 days without regressions.
  3. Read cutover shipped behind a per-tenant flag (future — when tenancy exists).

### 4.4 · Adapters (`NIVX_FLAG_ADAPTERS=shadow`)

- **State today**: 6 ingest routes; EVTX returns 501; no FE consumer.
- **Recommendation**: KEEP SHADOW.
- **Promotion criteria** — **cannot promote until Server-Side File Mode exists**:
  1. Server-Side File Mode is live (see §5.2).
  2. Real Sysmon / EVTX / CSV-Splunk adapter converts to the canonical event bag.
  3. Timeline / Query panels consume events from adapter-produced canonical events without code changes.

### 4.5 · Artifact Store (`NIVX_FLAG_ARTIFACT_STORE=shadow`)

- **State today**: `v2_artifact_store` has 15 rows from shadow observation.
- **Recommendation**: KEEP SHADOW.
- **Promotion criteria**:
  1. Coupled with Server-Side File Mode — the file store *is* the artifact store's persistence layer.
  2. Every uploaded artifact and every decoded child artifact carries a provenance envelope (see §5.2).
  3. Recursive discovery termination proof.

### 4.6 · Feature-flag governance (added in this ADR)

- Any promotion (`shadow → enabled`) requires an ADR update documenting the flip.
- Any regression (`enabled → shadow`) requires a rollback ADR.
- Any deletion (`shadow → removed`) requires evidence per P1.

---

## §5 · Sequenced Execution (post-ADR-0008)

The following sequence applies to the **next implementation sessions** (i.e., NOT this session; this session ends at ADR-0009).

### 5.1 · P0 · Security Hardening Gate (implementation session S+1)

Contained, high-signal, gate-shaped. Ship together; do not split.

- Login rate-limit (`/api/auth/login`) — sliding-window Redis-alternative in-memory + monotonic counter with lockout after N failures per IP + email.
- Archive-recursion cap on `/api/upload` — max member count, max total uncompressed bytes, max nesting depth. Fail-loud on breach.
- CORS explicit-origin allow-list — replace `["*"]` with a configured list of allowed origins from env; keep `allow_credentials=True` only for allow-listed origins.
- Same-process parser isolation review — document (in ADR-0010) the residual risk and set a policy about which parsers require future subprocess/sandbox isolation.
- Regression tests for each of the above, added to the P0.3 firewall.

**Gate condition:** All four items green + Workspace regression suite green + no new failure in the canonical suite. Once green, NivXRay is production-safe for single-tenant SaaS.

### 5.2 · P1 · Server-Side File Mode (implementation session S+2)

**Architecture (owner-mandated):**

```
Browser
   │  upload (multipart)
   ▼
Backend File Store          ← GridFS (or dedicated collection)
   │
   ├── file_id           (UUIDv4)
   ├── sha256            (content-addressed)
   ├── size
   ├── mime_type
   ├── original_filename
   ├── uploaded_by       (user email)
   ├── uploaded_at       (ISO-8601 UTC)
   └── provenance        (source · original path in archive · parent_file_id)
        │
        ▼
Input Router (new)          ← inspects sha256 + mime; dispatches to
   │                          the right analyzer/adapter without the
   ▼                          frontend seeing raw bytes
Adapter / Analyzer
   │
   ▼
Canonical Event Bag         ← same bag Timeline / Query consume today
```

**Non-goals for this session:**
- Do not increase the client-side cap. The cap disappears because file bytes never go through React state.
- Do not delete `/api/upload` — extend it. The old endpoint continues to work for ≤ 256 KB text pastes.

**Deliverables:**
- New router `routers/files.py` (`POST /api/files`, `GET /api/files/{file_id}`, `DELETE /api/files/{file_id}` — admin/owner).
- Input Router module `services/input_router.py`.
- Frontend upload flow returns a `file_id` reference; existing panels resolve it on demand.
- Regression: existing 32 KB paste path unchanged.

### 5.3 · P2 · Real Telemetry Adapter (implementation session S+3)

Only after §5.1 + §5.2 close. Two candidates, in priority order:

1. **Sysmon / EVTX adapter** — feeds canonical event bag. `python-evtx` is the missing dependency called out in `v2/routers/ingest.py::ingest_evtx_stub`.
2. **Splunk `_raw` CSV recognizer** — extends `csv_edr_analyzer.py` to unwrap Splunk / Cisco AMP exports currently silently falling into the prose path.

### 5.4 · P3 · Shadow Promotion Waves (implementation sessions S+4 to S+N)

Only after §5.3 close. Each subsystem promoted with its ADR-0008 §4 criteria met and a dedicated wave-report ADR.

### 5.5 · Parallel small-scope quality work (any session)

- Determinism CI gate (produced in this session — see ADR-0008 companion test).
- Route classification review (ADR-0009).
- Documentation drift closure (ADR-0007 §22 items).
- Workspace regression protection expansion.

---

## §6 · Target Architecture (locked)

The following is the destination. Every downstream ADR must map new work onto this diagram.

```
                             INPUT (paste · upload · adapter · webhook)
                                            │
                                            ▼
                         ┌─────────────── Input Router ───────────────┐
                         │  (sha256 · provenance · mime · size)        │
                         └─────────────────┬───────────────────────────┘
                                           │
                                           ▼
                        Adapter / Analyzer / Artifact Router
                                           │
                                           ▼
                              Canonical Event Bag
                                           │
                                           ▼
                    Recursive Artifact Discovery (fixed-point)
                                           │
                                           ▼
                     Investigation Knowledge Graph (IKG)
                                           │
                            ┌──────────────┼──────────────┐
                            │              │              │
                            ▼              ▼              ▼
                       Correlation     Verdict v3      ATT&CK
                            │              │              │
                            └──────────────┼──────────────┘
                                           ▼
                                     Attack Story
                                           │
                                           ▼
                                      Mitigation
                                           │
                                           ▼
                          Report (STIX · Sigma · YARA · Nav · MDR · MD · PDF)
                                           │
                                           ▼
                                       Workspace
```

**Rules of the target:**
- Every arrow is a pure function of its input at its layer.
- Every node writes to persistence with `evidence_ref` provenance.
- Every projection consumer reads from the layer above it — never a peer layer.
- No layer invents facts; when evidence is absent, the layer emits `None` or `"no evidence"` (never a generic fallback).

---

## §7 · Migration Boundaries (do NOT cross prematurely)

- **Adapter tier does not go live before Server-Side File Mode** (P4).
- **IKG persistence does not go live before Case Engine parity is proven** (§4.3).
- **Verdict v3 does not go authoritative before replay parity is CI-locked** (§4.2).
- **Multi-tenancy does not begin before security gate closes** (§5.1).
- **STIX/TAXII pull ingestion does not begin before determinism CI passes** (§5.5).

---

## §8 · Do-NOT-Build-Yet List

The following are explicitly deferred, with rationale:

| Item | Deferred until | Rationale |
|---|---|---|
| Multi-tenant / SSO / Google OAuth | after §5.1 | Security gate must close first |
| CrowdStrike / Defender / S1 / Cisco XDR adapters | after §5.3 | Sysmon/EVTX proves the ingest pipeline first |
| STIX/TAXII pull ingestion | after §5.5 | Determinism must be provable first |
| Cross-case / fleet-scale hunt | after §5.3 | No telemetry corpus yet |
| Saved-query UI | after Query/Hunt v2 | Backend needs a `saved_queries` collection first |
| New AI feature (auto-triage, LLM summarizer v2) | after §5.3 | No new engines until existing engines are one product |
| Nivxforge section pages (Threat Intel / Threat Hunting / KB / Reports / History) | after §5.3 | Convert placeholder pages to real capability only when telemetry ingestion exists |
| Any new NIVX_FLAG_* | after §4.6 | Governance discipline first |

---

## §9 · Session Discipline

- No implementation session may exceed one "gate" from §5 without owner approval.
- No implementation session may modify Workspace behavior without a matching regression test in the same commit.
- No implementation session may bypass an ADR update for the docs it touches.
- Sessions that discover contradictions with ADR-0007 must open an ADR-0007-addendum in the same session.

---

## §10 · Success Metrics (measurable, testable)

By the time §5.1 + §5.2 + §5.3 + §5.5 close, NivXRay demonstrably:

1. Refuses malformed archives with a size/depth guard test.
2. Refuses login brute-force with a rate-limit test.
3. Rejects non-allow-listed origins under CORS.
4. Accepts a real EVTX file end-to-end and produces a canonical Timeline.
5. Recognises a Splunk `_raw` CSV and produces a canonical Timeline.
6. Emits byte-identical Markdown / STIX for the same canonical envelope (determinism CI green).
7. Reveals none of the four ADR-0007 §12 softnesses under the security regression suite.
8. Adds zero new shadow flags without an ADR entry.

---

## §11 · What This ADR Does NOT Do

- Does not authorise deletion of any route.
- Does not authorise promotion of any shadow flag.
- Does not modify Workspace behavior.
- Does not add new features.
- Does not deprecate legacy modules.
- Does not commit to a specific timeline — sessions are gated by evidence, not date.

---

## §12 · Companion Artifacts (Session-8)

- `0007-current-state-master-snapshot.md` — reality baseline.
- `0009-route-classification.md` — evidence-backed API surface reality (this session).
- `backend/tests/canonical/api/test_report_determinism.py` — determinism CI gate (this session).

*End of ADR-0008.*
