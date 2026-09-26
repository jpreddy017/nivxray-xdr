# NivXForge EDR · Architecture Decisions (AD-01 … AD-08)

> **Gate 0.5 · Read-only.** No decision is executed until owner explicitly approves. No code changed.

Every AD row uses the same fields: **Decision · Options · Recommendation · Rationale · Impact (Core / EDR / Sandbox / UBAE) · Security · Multi-tenancy · Migration · Reversibility · Risks · Exact owner decision required.**

---

## AD-01 · EDR / Sandbox API Namespace

- **Decision:** Which URL prefix hosts new EDR & Sandbox routes?
- **Options:**
  - **A · Extend `/api/xdr/*`** (`/api/xdr/edr/telemetry/stream`, `/api/xdr/edr/enrollment/*`, `/api/xdr/sandbox/detonate`, …).
  - **B · Reserve `/api/v2/edr/*` and `/api/v2/sandbox/*`** (as the handoff proposes).
  - **C · New top-level `/api/edr/*` and `/api/sandbox/*`** (parallel).
- **Recommendation:** **A**.
- **Rationale:** `_principal(req)` extraction, cross-tenant guard (already coded in `routers/xdr_ingest.py`), and `require_permission()` are all wired for `/api/xdr/*`. Option A reuses them without change. Option B collides with the existing `backend/v2/routers/*` sub-tree (different concern). Option C fragments the surface.
- **Impact — NivXRay Core:** Zero change. Existing `/api/xdr/*` routes untouched.
- **Impact — EDR:** New EDR routes registered under `/api/xdr/edr/*`. Client SDK path convention aligns with existing collectors.
- **Impact — Sandbox:** New routes under `/api/xdr/sandbox/*`.
- **Impact — UBAE:** UBAE data lands via existing `xdr_ingest` (as `event_type=user_session/persistence`) — no dedicated namespace needed.
- **Security implications:** Reuse of existing rate-limit + audit + rbac dependencies.
- **Multi-tenancy implications:** Reuse of existing `_principal` + cross-tenant guard. Blocks the class of bugs where a new prefix accidentally bypasses tenant enforcement.
- **Migration:** No migration; all new routes.
- **Reversibility:** Full — routes can be aliased or removed via feature flag.
- **Risks:** Slightly longer URLs vs option B; documentation drift with handoff (mitigated by publishing the naming decision in an ADR).
- **Owner decision required:** Approve **A**, or approve **B** with an explicit disambiguation rule vs `backend/v2/routers/*`, or approve **C** (not recommended).

---

## AD-02 · Canonical Envelope Evolution

- **Decision:** Extend `CanonicalEnvelope` in `backend/routers/xdr_ingest.py` in-place, or fork a new `envelope_v2` model?
- **Options:**
  - **A · Extend in place** — add new optional fields to the existing Pydantic model, `envelope_version` values negotiated (`"1.0"` legacy, `"2.0.0"` EDR/Sandbox).
  - **B · Fork** — new file/model `envelope_v2.py`, new writer, coexist with existing.
- **Recommendation:** **A**.
- **Rationale:** New fields are purely additive; version-branched validation is cheap. Fork doubles maintenance and forces the ingest pipeline to switch on model type.
- **Impact — Core:** Zero downstream change — new fields are ignored by existing consumers unless they opt-in.
- **Impact — EDR:** EDR sensors emit `envelope_version="2.0.0"` with all mandatory EDR fields (`device_id`, `process_id`, `provenance`, `event_type`, `canonical_event`).
- **Impact — Sandbox:** Same envelope shape with `event_type=sandbox_*`.
- **Impact — UBAE:** Same envelope shape with `event_type=user_session|persistence`.
- **Security implications:** Server-side `tenant_id` derivation (from mTLS cert `OU` at ingest gateway) still authoritative. Any client-supplied `tenant_id` in body is IGNORED.
- **Multi-tenancy implications:** Unchanged; existing guard applies.
- **Migration:** None — legacy collectors keep sending `"1.0"`.
- **Reversibility:** Full — new fields can be marked `deprecated` in a future revision without breakage.
- **Risks:** Field-name collisions if handoff schema evolves; mitigate with a schema-conformance test.
- **Owner decision required:** Approve **A**, or approve **B** with an explicit rationale.

---

## AD-03 · Security State module location

- **Decision:** Retain FSM at `backend/routers/rc5_entities.py` (+ `rc5_diag.py`) — do we rename/refactor to `backend/security_state/contracts.py` (as handoff claims) or reuse in place?
- **Options:**
  - **A · Reuse in place**, correct the handoff paths.
  - **B · Rename/refactor** rc5 → `security_state/` module.
- **Recommendation:** **A**.
- **Rationale:** rc5 is IMPLEMENTED_AND_WORKING; a rename is a reasoning-engine change explicitly forbidden by the "do not rebuild" rule (see §7 reconfirmation). Doc drift is easier to fix than a rename that risks silently altering state-transition semantics.
- **Impact — Core:** Zero.
- **Impact — EDR:** EDR derives intervention plans from rc5 read APIs (no writes).
- **Impact — Sandbox:** Same.
- **Impact — UBAE:** Same, plus UBAE can extend rc5 transition labels only in a later phase with explicit owner approval.
- **Security implications:** None (read side only).
- **Multi-tenancy implications:** None.
- **Migration:** None.
- **Reversibility:** Trivially reversible (docs).
- **Risks:** Documentation may keep drifting unless the addendum is enforced.
- **Owner decision required:** Approve **A** and enforce doc addendum. If **B**, provide an explicit migration ADR because rc5 semantics are frozen.

---

## AD-04 · UI-freeze exception scope for EDR

- **Decision:** Does Phase 1 require UI implementation, or does it ship backend + API contract only?
- **Options:**
  - **A · Phase 1 = backend + API contract only** (UI freeze fully honoured).
  - **B · Limited UI-freeze exception** for EDR-critical screens (Endpoint Inventory, Sensor Health, Response Drawer additions).
  - **C · Full UI-freeze lift** for EDR/Sandbox surfaces.
- **Recommendation:** **A**.
- **Rationale:** UI freeze locked in `GA_BLOCKERS.md`. Phase 1 does not need UI to prove sensor-enrollment and telemetry ingest. Deferring UI to a later gate reduces blast radius and preserves review discipline.
- **Impact — Core:** Zero.
- **Impact — EDR:** New surfaces stay unreachable until UI freeze is lifted; sensors and API can be validated by curl and integration tests.
- **Impact — Sandbox:** Phase 4 — not in scope now.
- **Impact — UBAE:** Phase 3 — not in scope now.
- **Security implications:** Fewer UI attack surfaces during Phase 1.
- **Multi-tenancy implications:** None.
- **Migration:** None.
- **Reversibility:** Trivial — flip a feature flag when the UI lifts.
- **Risks:** Analysts have no visibility; mitigate by publishing curl-based runbooks + adding readonly OpenAPI links.
- **Owner decision required:** Approve **A**, or approve **B** with an itemized surface list + acceptance criteria.

---

## AD-05 · Missing audit scripts (`run_content_truth_audit.py`, `verify_decoder_truth_e2e.py`)

- **Decision:** Ship the scripts or replace with introspection endpoints?
- **Options:**
  - **A · Introspection endpoints** (`GET /api/xdr/detection/inventory`, `GET /api/decode/registry/inventory`).
  - **B · Ship the scripts** as pytest-invocable CLIs in `backend/tests/` or `backend/scripts/`.
  - **C · Both**.
- **Recommendation:** **A**.
- **Rationale:** Endpoints are consumable by dashboards, curl, and automation; scripts require shell access. The endpoint approach also aligns with the honest-state rule — the number reported is always live-truth, not a cached CI artifact.
- **Impact — Core:** Zero (additive routes only).
- **Impact — EDR:** EDR acceptance tests can hit these endpoints deterministically.
- **Impact — Sandbox:** Same.
- **Impact — UBAE:** Same.
- **Security implications:** Endpoints must be RBAC-gated (recommend `require_permission("detection.inventory.read")` and `require_permission("decode.registry.read")`).
- **Multi-tenancy implications:** Content inventory is tenant-neutral (rules are pooled); decoder registry is tenant-neutral. Neither leaks tenant data. Still gated by RBAC.
- **Migration:** None.
- **Reversibility:** Endpoints can be removed via feature flag.
- **Risks:** Owner may still expect a static "615" number even after introspection lands; mitigate by publishing endpoint output as the canonical figure.
- **Owner decision required:** Approve **A**, or specify **B/C**. Also confirm which count (SoT) becomes the canonical number.

---

## AD-06 · P0-D adversarial cross-tenant test — HARD prerequisite?

- **Decision:** Must the P0-D adversarial test pass before Phase 1 EDR ingest lands?
- **Options:**
  - **A · Hard prereq** (Phase 1 code cannot merge until P0-D negative test suite is green).
  - **B · Soft prereq** (Phase 1 can land behind a feature flag; P0-D fixed in parallel).
- **Recommendation:** **A**.
- **Rationale:** New endpoint-sensor traffic dramatically increases the blast radius of any tenant-isolation bug. Better to close P0-D first, then flip the switch. This aligns with the "Tenant isolation proof → Current-State contract → New Technology build" ordering the owner previously set for Antigravity.
- **Impact — Core:** No new features; existing `_principal` pattern extended into a global tenant-scope middleware.
- **Impact — EDR:** Delays Phase 1 kickoff by the P0-D duration (estimated small; the guard pattern is already coded in `xdr_ingest.py`).
- **Impact — Sandbox:** Same.
- **Impact — UBAE:** Same.
- **Security implications:** Substantially reduces risk of a cross-tenant data leak on Phase 1 day one.
- **Multi-tenancy implications:** This IS the multi-tenant proof.
- **Migration:** None.
- **Reversibility:** N/A — safety gate.
- **Risks:** Small schedule delay in exchange for a large risk reduction.
- **Owner decision required:** Approve **A**.

---

## AD-07 · Response safety-gate data source

- **Decision:** Where does the safety-gate get "is-Domain-Controller" and "is-ICU / Healthcare" data?
- **Options:**
  - **A · AD adapter (LDAP / Kerberos)** for DC-status + endpoint tag registry (`edr_endpoints.tags`) for ICU/Healthcare/SCADA.
  - **B · Manual admin list** (curated collection `xdr_safety_locks`) — no live directory dependency.
  - **C · Hybrid** — AD adapter primary, admin list fallback.
- **Recommendation:** **C · Hybrid, FAIL-CLOSED**.
- **Rationale:** AD may be unreachable at exactly the moment a responder must isolate a host; a fail-CLOSED hybrid ensures containment is refused when neither source can confirm the target is safe. Any relaxation (`FAIL_OPEN`) is FORBIDDEN.
- **Impact — Core:** New adapter + collection. Zero change to reasoning engines.
- **Impact — EDR:** Real containment can proceed only after AD adapter + tag registry land. Until then, `capability_available=false`.
- **Impact — Sandbox:** N/A (Sandbox does not isolate real hosts).
- **Impact — UBAE:** UBAE may enrich tags but MUST NOT override them.
- **Security implications:** Prevents accidental isolation of AD-critical or life-safety hosts.
- **Multi-tenancy implications:** Tag registry is tenant-scoped; AD adapter must be tenant-scoped (each tenant provides its own AD reachability).
- **Migration:** New collection + new adapter — additive.
- **Reversibility:** Feature flag `NIVX_EDR_SAFETY_GATE_FAIL_MODE=CLOSED` (default) / `OPEN` (forbidden).
- **Risks:** AD adapter integration complexity. Mitigate by shipping tag-registry first; AD adapter can arrive in Phase 2.
- **Owner decision required:** Approve **C** and confirm `FAIL_MODE=CLOSED` is non-negotiable.

---

## AD-08 · Sensor kernel-driver signing

- **Decision:** How is the Windows / Linux / macOS sensor code-signed?
- **Options:**
  - **A · Emergent-issued dev signing certificate for Phase 1 only**, with a Microsoft-attested EV code-signing cert and a Linux-kernel-signing key for production.
  - **B · Skip signing in Phase 1** (unsigned dev builds only; enterprise-side installs disabled).
  - **C · Full production signing from day 1**.
- **Recommendation:** **A**.
- **Rationale:** Phase 1 focus is enrollment + ingest; production sensor deployment is Phase 2+. Signing infrastructure needs Emergent-Labs sign-off (cert procurement, key custody, attestation).
- **Impact — Core:** Zero.
- **Impact — EDR:** Phase 1 sensors only run in test tenants; production rollout gated on production signing.
- **Impact — Sandbox:** N/A.
- **Impact — UBAE:** N/A.
- **Security implications:** Unsigned dev sensors MUST NOT touch production endpoints.
- **Multi-tenancy implications:** None (signing is per-artifact, not per-tenant).
- **Migration:** Ship signed sensor as a new binary; enrollment token accepts both signed/unsigned in dev, signed-only in prod.
- **Reversibility:** Any sensor version can be revoked via CRL (`edr_endpoints.status=REVOKED`).
- **Risks:** Ordering EV cert takes weeks; do not block Phase 1 on it.
- **Owner decision required:** Approve **A** and set a hard deadline to procure the EV cert before Phase 2 rollout.

---

## Summary owner-decision checklist

| # | Decision | Emergent recommendation | Owner sign-off |
|---|---|---|---|
| AD-01 | API namespace | A (extend `/api/xdr/*`) | ☐ |
| AD-02 | Envelope evolution | A (extend in place) | ☐ |
| AD-03 | Security-State location | A (reuse `rc5_entities.py`) | ☐ |
| AD-04 | UI-freeze scope | A (backend-only Phase 1) | ☐ |
| AD-05 | Missing audit scripts | A (introspection endpoints) | ☐ |
| AD-06 | P0-D as hard prereq | A (hard prereq) | ☐ |
| AD-07 | Safety-gate data source | C (hybrid FAIL-CLOSED) | ☐ |
| AD-08 | Sensor signing | A (dev cert now, EV cert before Phase 2) | ☐ |

**None of these are executed until each row is explicitly approved.**

## END · architecture decisions delivered · read-only · awaiting owner sign-off
