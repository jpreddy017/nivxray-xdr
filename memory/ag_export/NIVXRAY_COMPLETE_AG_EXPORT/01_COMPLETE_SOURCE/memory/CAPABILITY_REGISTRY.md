# Capability Registry

**Status:** Governance discipline (adopted 2026-02-28)
**Owner:** Operator
**Purpose:** Treat each Accepted ADR as a **versioned capability** with end-to-end
traceability from real-world evidence → pattern → ADR → implementation →
regression → deployed behaviour.

---

## 1 · Why a Capability Registry

Once the platform is under governance lock, code changes and product
capabilities diverge. A single feature the analyst sees ("verdict is now gated
by behavioural evidence") is the surface expression of a capability that has:

- **Evidence** — the real cases that justified it
- **Governance** — the ADR that authorised it
- **Implementation** — the code changes that landed it
- **Regression** — the pinned tests that protect it
- **Version** — the corpus baseline it was validated against
- **Status** — Proposed / Accepted / Active / Deprecated / Superseded

Without a registry, this history dissolves into commit messages. The registry
makes it queryable.

---

## 2 · Registry format

Every Accepted ADR that introduces or modifies analytical behaviour receives a
row. New rows are appended; historical rows are never edited (except to add a
`Superseded-by` reference or to record `Introduced In` when a capability first
reaches Active).

| Capability | ADR | Status | Evidence (cases) | Corpus | Regression pins | Non-regression pins | Component | Introduced In | Superseded By |
|---|---|---|---|---|---|---|---|---|---|
| Command Obfuscation Framework | ADR-0001 | Active | Case 0001 | v1 | see ADR §2 | — | Decoder / Handler Registry | v1.5.0 | — |
| PowerShell XOR Attribution Fix | ADR-0004 | Active | Case 0001 | v1 | `test_ps_ascii_xor_iex_output_selection` | — | Decoder attribution | v1.5.0 | — |
| NivXForge Router Mount | ADR-0005 | Active | (infra) | v1 | isolation tests | — | Backend router | v1.5.0 | — |
| NivXForge Analyst-Parity Surface | ADR-0006 (Phase 1) | Active | (positioning) | v1 | `test_parity_endpoints` | — | NivXForge frontend | v1.6.0 | — |
| **Verdict-Evidence Gating** | ADR-0007 | **Implemented** (2026-02-28) | 0005, 0006, 0013, 0017, 0022 | v1 | see ADR §6 · 15/15 pins green | 0003, 0009, 0018, 0019, 0020 | Verdict Engine | 15/15 pinned + 114/114 unified pins + zero net regressions across 14-file sample + live e2e on `/api/decode/smart` + `explainability` field wired | — |
| **IOC Extraction Validation** | ADR-0008 | **Implemented** (2026-02-28) | 0007, 0011, 0012, 0014 | v1 | see ADR §6 | 0009 | IOC Extractor | 7/7 pins green + parity + perf ≤0.5% + zero regressions across 160-test diff sample | — |
| **Canonical Investigation Model (CIM) & Investigation Workspace** | ADR-0009 | **Implemented** (2026-02-28) | 0002, 0006, 0013 + North Star + UX diagnostic | v1 | see ADR §6 · 22/22 pytest pins green | 0003, 0009, 0018, 0019, 0020 | `nivxforge/cim/` composer + `<CIMSection>` frontend | 99/99 pins green (CIM 22 + ADR-0008 7 + IOC filters 21 + NivXForge 49); zero-orphan invariant; live e2e wire-in on `/api/decode/smart` + `/api/v2/auto-investigate` | — |

### Lifecycle field semantics

- **Introduced In** — the product version at which the capability first
  transitioned to `Active`. Recorded once, then immutable. `pending` while
  Accepted but not yet implemented.
- **Superseded By** — the ADR (and, optionally, product version) that replaces
  or materially changes this capability. Recorded when the superseding ADR
  reaches Active. Original row is never deleted; both rows coexist for
  historical traceability.

Status transitions:

```
Proposed → Accepted → (implementation) → Active → (later) → Deprecated / Superseded
```

- **Proposed**: ADR drafted, awaiting operator review.
- **Accepted**: ADR approved; implementation authorised but not yet green.
- **Active**: implementation landed, Exit Criteria met, regression protecting it. `Introduced In` populated at this transition.
- **Deprecated**: capability is being wound down but still present.
- **Superseded**: replaced by a later ADR — row keeps its history and `Superseded By` links to the replacement ADR.

---

## 3 · The end-to-end traceability chain

Every Active capability must be answerable to these five questions:

```
Real Investigation
        │
        ▼
REAL_WORLD_LOG      ← "Which real-world cases justified this?"
        │
        ▼
Recurring Pattern    ← "Which pattern in the register did this address?"
        │
        ▼
ADR                  ← "Which architectural decision authorised it?"
        │
        ▼
Implementation       ← "Which code changes deliver it?"
        │
        ▼
Regression Suite     ← "Which tests protect it?"
        │
        ▼
Capability           ← "What behaviour did the analyst gain?"
        │
        ▼
Production
```

If any link in the chain is missing, the capability is not eligible to be
marked **Active**. Silent capabilities (code that ships without an ADR row) are
a governance defect.

---

## 4 · Queries the registry must support

Once populated, the registry answers questions like:

- *Which capability produced this finding?* — trace via `Component` column and
  the ADR's Rule section.
- *Which ADR introduced this behaviour?* — direct row lookup.
- *Which real-world cases justified it?* — `Evidence (cases)` column.
- *Which regression tests protect it?* — `Regression pins` column.
- *Which corpus version was it validated against?* — `Corpus` column.
- *Has this capability been superseded?* — `Superseded-by` column.

These queries close the loop between what analysts see today and the evidence
that made it possible.

---

## 5 · Update rules

- **Every future ADR that changes analytical behaviour MUST add a row** to
  §2 before status can transition to Active.
- Rows are **never deleted**. If a capability is retired, mark it
  `Deprecated` or `Superseded` — do not remove it.
- When a capability is superseded, the new ADR's row references the old one
  in its Evidence column (e.g. "supersedes ADR-0007 · same cases 0005, 0006, …").
- **Corpus version bumps** propagate: when v1 → v2 activates, all Active v1
  capabilities are re-validated against v2's regression before v2 is declared.
- The registry lives in this file; there is no separate database. This keeps
  it under the same governance and immutability rules as the ADRs it indexes.

---

## 6 · Relationship to other memory files

- `REAL_WORLD_LOG.md` — the source of evidence rows this registry cites.
- `CORPUS_VERSIONING.md` — defines what `v1` / `v2` / `v3` in the Corpus column mean.
- `OPERATIONAL_LOOP.md` — defines the process that populates the Evidence and Pattern columns.
- `/app/memory/adr/` — the ADRs indexed by every row.

The registry is the **surface index** that ties them together. Analysts and
future maintainers should be able to start from this table and reach every
supporting document in one hop.
