# NivXForge EDR — Dependency-First, Copy-First Isolation Directive

**Status:** NON-OVERRIDABLE · **Recorded:** 2026-10-30 · **Applies to:** every future EDR source extraction, engine migration, database separation, service replacement and repository restructuring.
**Governing goal:** NivXForge EDR becomes a fully independent product **without damaging** NivXRay XDR, NivXRay Workspace, NivX Machines or any existing functionality.

This directive outranks any plan, phase document, assessment or convenience. Where an earlier document (A0-v0.1, A0-v0.2, A0-01, A0-02) conflicts with it, this directive wins.

---

## 1 · Mandatory sequence (no step may be skipped or reordered)

| # | Step | Done only when |
|---|---|---|
| 1 | Document the full **direct and transitive** dependency chain | every edge is evidence-backed, no `UNKNOWN` remains in the chain being moved |
| 2 | Identify every necessary source module, engine, library, configuration, schema, test, worker and data relationship | the inventory is complete for the dependency actually being moved, not approximated |
| 3 | **Preserve** the original implementation and verify required recovery backups | a tested restore path exists and has been proven, not assumed |
| 4 | **Copy** approved dependencies into EDR-owned source/infrastructure boundaries — originals untouched | `git status` on the original paths is clean; no original file edited, moved or deleted |
| 5 | Adapt the **copies** to EDR-owned auth, database, configuration, runtime and service interfaces | the copy no longer calls any XDR or Workspace runtime surface |
| 6 | Compare original vs EDR-owned implementation — deterministic fixtures, API contracts, data provenance, behavioural equivalence, regression tests | equivalence is demonstrated by evidence, not inferred from a green build |
| 7 | Validate isolated end-to-end EDR functionality, including native endpoint testing and failure simulations | EDR enrols, ingests, processes, detects and serves with XDR/Workspace unreachable |
| 8 | Obtain independent verification under approved **G0–G6** governance | an independent reviewer signs off; self-certification is not sufficient |
| 9 | Authorized, **reversible** cutover of **one dependency at a time** | rollback has been rehearsed before the switch, not designed after it |
| 10 | Keep the original implementation until the replacement is verified **and its rollback period is complete** | the retirement decision is a separate authorized task |

---

## 2 · Strict prohibitions

1. Never break first and repair afterward.
2. Never remove or modify another product's dependencies merely to make EDR independent.
3. Never copy incomplete engines without their supporting code and tests.
4. Never introduce new runtime dependencies on XDR or Workspace.
5. Never blindly duplicate entire production databases or telemetry histories.
6. Never remove legacy implementations before the replacement is independently proven.
7. Never assume a passing build proves functional equivalence.

## 3 · Stop condition

If the dependency chain, preservation evidence, test result or recovery procedure is **incomplete**, the separation remains on **HOLD**. Incompleteness is a stop, not a risk to accept.

## 4 · Final acceptance

EDR operates independently **and** the original XDR, Workspace and NivX Machines capabilities remain unaffected. Both halves are required; either one alone is a failure.

---

## 5 · How this binds the evidence already collected

| Prior finding (A0-01 / A0-02) | What this directive requires of it |
|---|---|
| Backend deployment revision and production `DB_NAME`/Mongo identity are **UNKNOWN** | Step 1 is **not** complete. Separation stays on HOLD until these are known. |
| EDR, XDR and Workspace share one backend runtime, one Motor client, one auth surface | Isolation proceeds by **copying** EDR modules into an EDR-owned runtime (step 4) — never by trimming the shared runtime the other products rely on (prohibition 2). |
| **Reverse dependencies:** `detection_content.telemetry.nivxforge_sensor_dsm` and `detection_content.xdr_pipeline` import `edr_plane`; 8 XDR UI files import `src/nivxforge` | These originals **stay exactly as they are and keep working**. EDR gets a copy; XDR keeps the module it imports today. No inbound edge may be cut to suit EDR. |
| `edrApi.js` calls `/xdr/rbac/session-context` and three `/xdr/respond/*` endpoints | Step 5 replaces these with EDR-owned authority **in the EDR copy**. Prohibition 4 forbids carrying them into the new runtime. |
| `v2.ingestion.*`, `services.mitre_catalogue`, `detection_content` registry, `security.secret_policy` | Copy **with their supporting code and tests** (prohibition 3) or consume as versioned libraries. No partial engine lift. |
| `backend/nivxforge/` is the NivXRay analysis engine, not the EDR product | Out of scope for any EDR copy. Moving it would damage Workspace/XDR. |
| Canonical bridge writes `xdr_canonical_evidence` / `v2_shadow_observations` | Data-relationship mapping (step 2) must precede any database separation; prohibition 5 forbids bulk cloning telemetry history. |
| Frozen candidate `d2f8b742` and M1 `388bb3d6` / `4cfb7cb0` | Preserved as frozen originals (step 3/10). Candidates are copied forward, never rewritten in place. |
| Preview, production and the Windows VM | Unchanged throughout. Production remains on HOLD. |

## 6 · Current standing

**HOLD.** Step 1 is incomplete: the deployed backend revision, the production MongoDB identity and database name, three un-traced backend packages (`canonical/`, `engine/`, `security_state/`), feature-flag effectiveness and collection-level reader/writer ownership are all still open. No copy, adaptation, cutover or retirement is authorized until those are closed and independently verified.
