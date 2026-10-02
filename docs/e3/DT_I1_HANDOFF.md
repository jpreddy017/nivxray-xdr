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

## DT-I1 synthetic preview evidence (scenarios A–F)
- **Source:** local commit `6b61e3af` on `feature/e3-edr-engines`, rendered through the ignored fixture harness `/app/.e3ui-harness`. Every capture shows the "SYNTHETIC FIXTURE PREVIEW — not live data" banner at the top and bottom. The fixtures use RFC 5737 IPs and fictional hashes.
- **Defect found and fixed (`6b61e3af`):** Activity Details values were `#0F172A` on the dark DT panel, which made them invisible. The fix is colour-only; there is no logic change, and the activityView node tests pass.
- **Screenshots:** stored in `/app/.e3ui-harness/shots/dt_{A..F}.jpeg`.
  - A: normal view. MITRE is neutral and the assessment is NOT_ASSESSED.
  - B: unknown registry observation. T1547.001 is UNATTRIBUTED and neutral, and detection is EMPTY.
  - C: behavioral MATCH. Only tf_w, tf_p and tf_r are highlighted, and the detection is attributed to edr_behavior.
  - D: TI outage. abuseipdb shows UNAVAILABLE and virustotal shows RATE_LIMITED, with no conclusion drawn. ML is TESTING with INSUFFICIENT_BASELINE.
  - E: retrospective change. v1 was UNKNOWN; v2 is MALICIOUS through INTEL_CHANGE and supersedes v1. History is append-only.
  - F: response REQUESTED. The proof is NOTHING_HAS_HAPPENED_YET and verified is false.
- **Open findings in pre-existing DT code (not fixed, need owner decision):**
  1. The `TimeRangeBox` day strip is hard-coded to Jun 23–Jul 22, regardless of case dates.
  2. The attack-chain summary counts a behavioral MATCH as "malicious" (C/F: "2 malicious").
  3. Process row labels are truncated.

## Owner milestone review → Step 1 corrective (57218ac3) + DT-I1D causal context (576002a9)
- **Step 1:**
  - The navigator dates now come from the trajectory bounds. If the bounds are missing, the strip shows UNKNOWN; there is no hard-coded fallback.
  - A detection is no longer treated as a malicious verdict. `trajectoryVerdict` returns malicious only when the machine assessment is MALICIOUS; a MATCH shows as DETECTED (amber).
  - Truncated labels expose their full value through a title attribute, a hover tooltip, and an accessible list.
- **DT-I1D:**
  - Added `backend/edr_investigation/causal.py` (the CausalEdge contract) and a frontend mirror in `causalView.mjs`. The two are parity-tested against each other.
  - Added CausalContextPanel to Activity Details.
  - Row indentation and connectors now come from parent identity only.
- **Exposed edge types:** spawned, wrote, executed, modified, connected_to, queried, and co_occurred (CORRELATED only).
- **Not exposed:** resolved_to, user/session launched, service started, and task launched. No trajectory frame telemetry carries these.
- **Previews:** `/app/.e3ui-harness/shots2/dt2_{A..F}.jpeg` (from 57218ac3) and `shots_causal/c_{G..L}.jpeg` (from 576002a9).
- **Tests:**
  - node view-model: 30/30
  - DT component (react-dom/server): 8/8
  - pytest edr_investigation, edr_behavior and edr_ml: 125/125, including the JS/Python parity test.
- **Not present in DT code:** a "Linked XDR Incidents" surface. There was nothing to regress.
