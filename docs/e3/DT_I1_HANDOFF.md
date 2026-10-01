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
