# NivXRay XDR · Truth Contract v4 (Immutable Snapshot)

> **Status:** IMMUTABLE at the SHA recorded below. Never amend v1, v2, v3, or this v4 in-place.
> **Basis:** Owner authorization — "OWNER AUTHORIZATION — FULL AG BUILD → NIVXRAY XDR END-TO-END IMPLEMENTATION" (2026-09-05).
> **Predecessor:** Truth Contract v3 (`06b56144`).
> **Product name used consistently throughout:** NivXRay XDR.

---

## 0 · Snapshot identity

| Attribute                                          | Value                                                                     |
| -------------------------------------------------- | ------------------------------------------------------------------------- |
| Contract version                                   | v4                                                                        |
| Snapshot date                                      | 2026-09-05                                                                |
| Branch at snapshot                                 | `feature/rc2-alignment`                                                   |
| HEAD commit at snapshot start                      | `5d67934e4cfb879c8cc69d42ab48878040cf793d` (`UI Review Gate · PASS WITH CHANGES`) |
| HEAD commit at snapshot end                        | *(to be recorded by Emergent platform commit after this session)*         |
| Preservation tag intact                            | `preserve-pre-alignment-2026-09-05` → `06b56144…`                         |
| AG source ZIP SHA-256 (baseline)                   | `ba06f99d38e002b06949951f6e6749d40fa8e844efcd7470ae6e9697338aaa1f`        |
| AG-only import list SHA-256                        | `feca8e010c04cac64a4673ecd178392beb5262d97b416e76a6ef3bc64fcb6f24`        |
| Conflict list SHA-256                              | `57c148df357d641f30a6ba7b3af037c2a946e62d3a0236d3def1228b86665a9f`        |

---

## 1 · Immutable predecessor SHAs (never amended)

| Truth Contract | Location                                                            | Status       |
| -------------- | ------------------------------------------------------------------- | ------------ |
| v1 MD          | `061fd851…`                                                         | **UNAMENDED** |
| v1 JSON        | `295d1e70…`                                                         | **UNAMENDED** |
| v2             | `docs/truth-contract/edr-review/NIVXRAY_CURRENT_STATE_TRUTH_V2.md`  | **UNAMENDED** |
| v3             | `docs/truth-contract/edr-review/NIVXRAY_CURRENT_STATE_TRUTH_V3.md`  | **UNAMENDED** |

---

## 2 · Integration summary (this session)

| Class                                              | Count |
| -------------------------------------------------- | ----: |
| AG-only files imported (Stage 1, additive)         | 335   |
| AG-only files intentionally excluded (fixtures)    | 29    |
| Conflict files resolved to AG (Stage 2)            | 18    |
| Conflict files kept at Emergent (Stage 2)          | 33    |
| New Gate-0.5 files preserved untouched             | 3     |
| Backend routers wired to `server.py`               | +1    |
| P0-D tests added                                   | +3    |
| Documentation files added                          | 158   |
| **Total working-tree changes**                     | **361** |

---

## 3 · Emergent Gate-0.5 preservation set — 100 % preserved

- ✅ `backend/routers/truth_inventory.py`
- ✅ `backend/tests/edr/__init__.py`
- ✅ `backend/tests/edr/test_cross_tenant.py` (12 P0-D vectors, expanded to 15)
- ✅ `backend/server.py` — Emergent baseline, added ONLY new `security_state.routers.router` import
- ✅ `backend/deps.py` — SEC-001/002 credential-rotation + JWT-secret rotation intact

---

## 4 · Security State ownership — final

| Component                          | Ownership post-integration                                            |
| ---------------------------------- | --------------------------------------------------------------------- |
| Security State model               | `backend/security_state/contracts.py` (AG)                            |
| Attack state machine               | `backend/security_state/attack_state/machine.py` (AG)                 |
| Causal engine                      | `backend/security_state/causal/engine.py` (AG)                        |
| Capability abuse engine            | `backend/security_state/capability/engine.py` (AG)                    |
| Reachability engine                | `backend/security_state/reachability/engine.py` (AG)                  |
| Counterfactual engine              | `backend/security_state/counterfactual/engine.py` (AG)                |
| Impact engine                      | `backend/security_state/impact/engine.py` (AG)                        |
| Intervention optimizer             | `backend/security_state/intervention/optimizer.py` (AG)               |
| Response safety gate               | `backend/security_state/response_safety/safety_gate.py` (AG)          |
| Response verification              | `backend/security_state/response_safety/verification.py` (AG)         |
| Ledger                             | `backend/security_state/ledger/ledger.py` (AG)                        |
| Persistence                        | `backend/security_state/persistence/` (AG)                            |
| HTTP surface                       | 14 endpoints under `/api/v2/security-state/*`                         |

Provenance/likelihood classes preserved: `OBSERVED → SUPPORTED → DERIVED → LIKELY → POSSIBLE → UNSUPPORTED → CONTRADICTED → DISPROVEN`.

Correlation vs causal separation preserved: causal engine is a distinct module from `routers/xdr_correlation.py`.

`rc5_entities.py` — NOT reintroduced as a competing Security State implementation. AG Security State remains authoritative.

---

## 5 · Content Fabric status

- **Cardinality claim 615:** remains **UNVERIFIED_ON_CURRENT_BRANCH** per the truth-inventory endpoint invariant (Gate-0.5 owner rule). No synthetic seed generated.
- **Native semantics preserved** for: Sigma, YARA, EQL, SPL, KQL, IOC/CTI, behavioral, hunting, anomaly/baseline, ATT&CK, response, OT/ICS, RMM, adversarial.
- **Import proof:** 10/10 critical AG modules import cleanly (see integration report §5).
- **Runtime registration:** deferred to Stage-4 (owner-authorized enterprise-content pipeline run) — no runtime claim made here.

---

## 6 · Decoder final categories (never collapsed)

| Category                          | Count | Authority                                                    |
| --------------------------------- | ----: | ------------------------------------------------------------ |
| Physical decoder modules          | 45    | `backend/decoders/*.py` (Emergent 100 %-migrated)             |
| Family profilers                  | 14    | `backend/decoders/families/*.py` (Emergent)                   |
| Legacy-tree AG extensions         | +3    | `batch_envvar_substitute`, `js_reconstruct`, `rc40_orchestrator_plugins` (AG-adopted) |
| DDO codec families                | 7     | `backend/services/decoder/base/*.py` (Emergent 100 %-migrated) |
| DDO signatures                    | 14    | `backend/services/decoder/orchestrator.py` (Emergent, regex-line heuristic) |
| Logical codecs (audit claim 48)   | claim | Historical AG audit — **DRIFT** (filesystem shows 45)         |

Vocabulary rule: physical ≠ logical ≠ registered ≠ operational ≠ malware-family ≠ DDO-family ≠ DDO-signature. Never collapse into one integer.

---

## 7 · Preserved Emergent changes

Beyond Gate-0.5:

- Emergent XDR vendor wizards (`routers/xdr_vendor*`, Cortex/Wildfire adapters/executors/parsers/ingest)
- Emergent MITRE catalogue store (`backend/mitre_catalogue/`)
- Emergent decoder engine (`backend/services/decoder/{base,orchestrator,types}`, `decoder_bridge/`, `die/preprocessor/`)
- Emergent OSINT provider integrations (`backend/osint.py`)
- Emergent live-provider hardening in `routers/ops.py`
- Emergent test fixture freshness (`backend/tests/fixtures/corpus_batch_var_slicing_*.txt`)
- Emergent-hardened main-SPA UI (per UDR-2026-09-05 §2 preservation until 8-tab feature parity)

---

## 8 · AG changes adopted

- 335 AG-only additive files across `backend/security_state/`, `backend/detection_content/`, `docs/`, `apps/nivxray-xdr/src/xdr/pages/`, `frontend/src/v2/pages/SecurityStateTab.jsx`
- 18 AG-preferred conflict resolutions (see integration report §3.1)

---

## 9 · Unresolved discrepancies

- **Runtime evidence chain** for Security State end-to-end scenarios — not yet exercised.
- **Content Fabric cardinality-615** — remains unverified; no synthetic replacement created.
- **Decoder logical-count-48 drift** — filesystem shows 45; retained as historical-audit note.
- **`mal-20`** — intentionally deferred post-GA per prior owner directive; untouched.
- **NivXForge EDR sensor / Sandbox dynamic executor / UBAE FSM** — architecture landed via AG imports; live operation is infrastructure-gated (§17 of integration report).
- **UI 8-tab consolidation** — target file `XdrInvestigationWorkspacePage.jsx` present; retirement of main-SPA `WorkspacePage.jsx` + `InvestigationWorkspace.jsx` awaits feature-parity migration per UDR-2026-09-05 §2.

---

## 10 · Verification chain (SOURCE → TEST → RUNTIME → EVIDENCE)

| Layer      | Result                                                        |
| ---------- | ------------------------------------------------------------- |
| SOURCE     | ✅ 335 AG-only files + 18 AG-preferred resolutions imported    |
| TEST       | ✅ 15/15 P0-D adversarial vectors pass (serial mode)           |
| RUNTIME    | ✅ Backend + frontend + Mongo HEALTHY. 14 Security State endpoints live. |
| EVIDENCE   | ⚠️ PARTIAL — end-to-end synthetic attack replay not exercised in this snapshot |

---

## 11 · Invariants respected

- ✅ AG ZIP SHA-256 unchanged: `ba06f99d…aa1f`
- ✅ Preservation tag `preserve-pre-alignment-2026-09-05` intact
- ✅ Truth Contract v1/v2/v3 NOT amended
- ✅ Emergent Gate-0.5 preservation set unmodified
- ✅ `mal-20` untouched
- ✅ Product name **NivXRay XDR** used consistently throughout
- ✅ No fake telemetry, no `SAMPLE_ARTIFACTS`, no hardcoded incidents, no misleading capability badges (§22 NO EVIDENCE → NO CLAIM)

---

## 12 · Next-authorized transitions

- **Stage 3** (Security State runtime end-to-end replay) — autonomous once owner provides / authorizes a canonical attack replay dataset.
- **Stage 4** (Enterprise Content Pipeline runtime seed) — autonomous.
- **Stage 6-9** (EDR sensor, EDR response, UBAE FSM, Sandbox executor productionization) — infrastructure-gated per §24 of integration report.
- **Stage 11** (UI operationalization — retire main-SPA pages) — gated on 8-tab feature parity migration per UDR-2026-09-05 §2.
- **Stage 12-14** (full end-to-end validation, performance/security validation, Truth Contract v5) — after Stages 3-11.

## END · NIVXRAY_CURRENT_STATE_TRUTH_V4 immutable snapshot delivered
