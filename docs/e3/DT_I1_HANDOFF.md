# DT-I1 Handoff (append-only milestone log)

- **Baseline:** `feature/e3-edr-engines` @ `cd5b4e1bd5d3e376073d37ec90c09108f79b9895`. The owner verified GitHub is at this SHA.
- **Directive:** `docs/e3/E3_MASTER_DIRECTIVE.md` (commit `a33ea1ad`).
- **Owner UI policy update (replaces §27):** existing Device Trajectory files may be improved, provided that:
  - scope is limited to the DT and its direct components
  - every changed pre-existing file is listed with a reason
  - current behaviour is kept, including the "Absence of detection is not evidence of clean" statement
  - the UI never shows capability the backend can't provide
- **Temporary bundle:** removed. The URL now returns the SPA HTML fallback (200 `text/html`, 67,905 bytes).
- **Screenshots:** NOT received. The visual review (directive §28) is **PENDING**.

---

## Milestone DT-I1A: inventory and status matrix
- **IMPLEMENTED:** `docs/e3/DT_I1A_INVENTORY.md`. No code or behaviour change.
- **TESTED / PROVEN:** n/a (inventory only).
- **Key findings:**
  - **F1** no MITRE → BENIGN.
  - **F2** MITRE regex → MALICIOUS without a detection.
  - **F3** MITRE chips always red.
  - **F4** non-functional Block SHA / Allow-list buttons.
  - **F5** heuristic ancestry edges.
  - **F6** the owner-quoted DT strings are absent from this branch, so the deployed ref needs confirmation.
  - **F7** the TI `clean` vocabulary.
- **FILES CHANGED:** added `docs/e3/DT_I1A_INVENTORY.md` and `docs/e3/DT_I1_HANDOFF.md`.
- **SECURITY / PERFORMANCE IMPACT:** none.
- **NEXT:** DT-I1B view-model contracts.

## Milestone DT-I1B: investigation view model (+ the early DT-I1E TI view contract)
- **IMPLEMENTED:** `backend/edr_investigation/` (`__init__`, `contracts`, `ti`, `builder`). It is store-independent and not wired to any router.
  - **Activity Details:** `ActivityDetail` has exactly the 15 §15 sections, in order. Each section state is one of AVAILABLE / EMPTY / UNKNOWN / UNAVAILABLE / NOT_WIRED.
  - **No detection:** the section is EMPTY with "No detection engine claimed this observation." plus "Absence of detection is not evidence of clean."
  - **MITRE:** a technique is styled as a threat only when a detection engine attributes it; otherwise it is neutral.
  - **Relationships:** `PROVEN_CAUSAL` requires a deterministic linkage (`SOURCE_PROCESS_GUID` / `PROCESS_IID`) plus evidence. A missing parent gives UNKNOWN, with no edge inferred.
  - **TI:** results are kept per provider, with no consensus collapse. NO_DATA and UNKNOWN are never BENIGN, and a reputation claim requires a provider. BENIGN counts only as contradicting *context*.
  - **Response:** response and verification use the existing E1 proof vocabulary. Only VERIFIED is verified; EXECUTED is labelled `SENSOR_CLAIM_ONLY_NOT_VERIFIED`.
  - **Retro history:** append-only. Versions must be contiguous and each must supersede the previous one.
  - **Machine vs. analyst:** the machine assessment is NOT_ASSESSED unless an assessment history exists. The analyst disposition is a separate, auditable vocabulary and never overwrites the machine assessment.
  - **Tenant:** tenant is mandatory, and cross-tenant inputs are rejected. Items are bounded to 50 per section.
- **TESTED:** `tests/edr_investigation`, 12 passed.
  - 11 L1/L2 contract tests.
  - 1 L4 cross-engine test: real E3 SequenceEngine and ML pipeline outputs on synthetic evidence are fed into the view. It checks the TESTING lifecycle is visible, the MITRE attribution, and that the machine assessment stays NOT_ASSESSED.
- **NOT WIRED:**
  - No API route serves the view model; adding one to `server.py` is a shared-architecture change, so it is deferred.
  - No assessment engine exists yet (DT-I1F).
- **FILES CHANGED:** new files only.
- **SECURITY:** tenant-mandatory, cross-tenant rejected, bounded.
- **PERFORMANCE:** O(n) over the supplied inputs, with 50 items per section.
