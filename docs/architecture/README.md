# 📜 NivXRay Constitution

> **AUTHORITATIVE. Read every constitution file before proposing or implementing anything. If your task conflicts with any of these documents, STOP and report the conflict — do not invent a new architecture.**

## Constitution Documents (load in this order)

| # | File | Scope |
|---|------|-------|
| 00 | [`00_PRODUCT_VISION.md`](./00_PRODUCT_VISION.md) | What NivXRay is and who it is for |
| 01 | [`01_XLAB_CONSTITUTION.md`](./01_XLAB_CONSTITUTION.md) | X-Lab · the one investigation workspace |
| 02 | [`02_UI_CONSTITUTION.md`](./02_UI_CONSTITUTION.md) | Presentation rules (Lab 2.0 face, locked lens list) |
| 03 | [`03_BACKEND_CONSTITUTION.md`](./03_BACKEND_CONSTITUTION.md) | Single-copy engine rule, shared pipeline |
| 04 | [`04_INVESTIGATION_CONSTITUTION.md`](./04_INVESTIGATION_CONSTITUTION.md) | Universal Investigation Engine and CIO contract |
| 05 | [`05_REPORT_CONSTITUTION.md`](./05_REPORT_CONSTITUTION.md) | 14-section Executive Report + Report Composer |
| 06 | [`06_DEFINITION_OF_DONE.md`](./06_DEFINITION_OF_DONE.md) | What "done" means for every task |

## Working Documents

- [`/app/docs/BACKLOG.md`](../BACKLOG.md) — Persistent implementation backlog. Update after every session; do not generate ad-hoc "Next Action Items."
- [`/app/memory/xlab_parity_audit.md`](../../memory/xlab_parity_audit.md) — Legacy Lab ↔ X-Lab parity matrix.
- [`/app/reference/canonical_investigation/sample_incident/`](../../reference/canonical_investigation/sample_incident/) — **Reference Implementation** (golden investigation). Read this before touching any Adapter or engine.

## Update Discipline

- Constitution files change ONLY via an explicit operator directive.
- The BACKLOG is the ONE place to track work status.
- Never re-propose decisions already frozen in a constitution file.
