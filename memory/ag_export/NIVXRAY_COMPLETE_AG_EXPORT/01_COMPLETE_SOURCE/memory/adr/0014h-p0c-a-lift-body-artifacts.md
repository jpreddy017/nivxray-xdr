# ADR-0014h · P0c-A — Lift `body_artifacts` into `incident.iocs`

**Status**: 🟢 CLOSED (owner-authorised, executed 2026-02-15)
**Predecessors**: P0a + P0b (ADR-0014g), read-only UI-path trace
**Successor**: **STOP** — owner-directed rerun of the actual Prev-Mode UI, then reassessment. — **LOCKED**

## 1 · Root cause (verified via read-only trace)

P0a producer wrote `report_extraction.body_artifacts = [URL]`. `_ice_correlate()` built `canonical["incident"]` from a separate producer path that never lifted P0a's artifacts into `incident.iocs`. Result: `incident.iocs = None` and `counts["iocs"] = 0` despite the URL sitting intact in `report_extraction`. Owner boundary classification: **C** — SSOT correct at one field, consumer reads a different one.

## 2 · Fix (P0c-A · lift-at-producer, per owner choice)

`services/die/investigation_results.py` — 17 LOC inserted immediately after `canonical["incident"] = ice_block.get("incident")`:

```python
# ── P0c-A (ADR-0014h) · Lift P0a body_artifacts into incident.iocs
if (report_extraction.get("source") == "paste_projection"
        and canonical.get("incident") is not None
        and not (canonical["incident"].get("iocs") or [])):
    _paste_body_artifacts = report_extraction.get("body_artifacts") or []
    if _paste_body_artifacts:
        canonical["incident"]["iocs"] = list(_paste_body_artifacts)
```

Two guards, exactly as authorised:
- `source == "paste_projection"` — activates only when P0a projection ran (URL-acquired path leaves `source` unset).
- `not incident.iocs` — never overwrites an existing ICE-populated value.

Result: URL-acquired path is byte-behaviourally unchanged. `_ice_correlate()`, P0b, IDA, DIE, router, registry, IUE, adapters, MITRE, verdict, Workspace UI, `_ACQUIRABLE_CLASSES` are all untouched.

## 3 · Live end-to-end probe on the exact screenshot URL

Before P0c-A → after P0c-A:

| Field | Before | After | Owner's expected |
|---|:---:|:---:|:---:|
| `report_extraction.source` | `"paste_projection"` | `"paste_projection"` | ✓ unchanged |
| `report_extraction.body_artifacts` | `[URL]` | `[URL]` | ✓ unchanged |
| `incident.iocs` | `None` | **`[URL]`** | ✓ fixed |
| `counts["commands"]` | `0` | `0` | ✓ correct (URL has no commands) |
| `counts["mitre"]` | `0` | `0` | ✓ correct (no MITRE evidence) |
| `counts["iocs"]` | **`0`** | **`1`** | ✓ fixed |

Owner's per-case expectations held exactly.

## 4 · Owner-mandated acceptance tests — all 7 green

`tests/canonical/iue/test_p0c_a_lift_body_artifacts_to_incident_iocs.py`:

| # | Test | Purpose |
|---|------|---------|
| 1 | `test_p0c_a_screenshot_url_paste_populates_incident_iocs` | Exact screenshot case now surfaces 1 IOC |
| 2 | `test_p0c_a_counts_iocs_matches_incident_iocs` | `counts["iocs"] == 1` after P0c-A |
| 3 | `test_p0c_a_url_only_expected_shape` | Commands=0, MITRE=0, IOCs=1, artifacts=1 |
| 4 | `test_p0c_a_does_not_overwrite_populated_incident_iocs` | Non-URL paths still valid |
| 5 | `test_p0c_a_guarded_by_paste_projection_source_flag` | Guard string grep-locked |
| 6 | `test_p0c_a_does_not_touch_ice_correlate` | Lift lives OUTSIDE `_ice_correlate` |
| 7 | `test_p0c_a_preserves_report_extraction_semantics` | `report_extraction` unmodified |

## 5 · Regression results

- `canonical/iue/`: **188 passed / 1 pre-existing Sample1-DB failure** (was 181/1) → delta **+7**, zero regression
- M0-tier stack (M0a + M0b + M0b-ext + M0c + M0d + M0d-async + M0e + harness + P0 + P0c-A): **145/145 green**
- P2 Sysmon Slice-1/2/3 + Report determinism + UI-DEF-02 + payload-shape + Sample1-immutability + Workspace-isolation: **unchanged**
- All 4 M0a IUE envelope hashes byte-identical
- SystemWeakness projection unchanged: `[ioc_enrichment.v1, report.narrative.v1]` — `url.acquire.v1` still absent

## 6 · Guardrails held (owner-mandated)

- Only P0c-A (not P0c-B, not P0c-C).
- Only populates `incident.iocs` when currently empty/None.
- Does NOT modify `_ice_correlate()`.
- Does NOT modify P0b beyond what was already shipped.
- No frontend changes.
- No IDA/DIE/router/registry/IUE changes.
- No M0e/M0f work.
- URL-acquired behaviour byte-behaviourally unchanged (source flag not set → P0c-A is no-op on that path).

## 7 · Files changed

| File | Change |
|------|--------|
| `services/die/investigation_results.py` | +17 LOC (P0c-A lift, immediately after `_ice_correlate` call) |
| `tests/canonical/iue/test_p0c_a_lift_body_artifacts_to_incident_iocs.py` | NEW, 7 tests |
| `/app/memory/adr/0014h-p0c-a-lift-body-artifacts.md` | NEW — this ADR |
| `/app/memory/PRD.md` | Amended |

## 8 · Next step (owner-directed)

**Rerun the actual Prev-Mode UI** on the exact 108-byte URL Analyst Paste from the screenshot. Expected UI:

- Commands: **0** (correct — URL has no commands)
- MITRE: **0** (correct)
- IOCs: **1** ← the fix
- Artifact: **1**
- Completeness: > previous 5% (backend counter now non-zero)
- Analyst Brief: populated
- URL-acquired path: unchanged (verified via P0c-A guard)

## 9 · LOCKED (unchanged)

M0e-plumbing · M0f production cutover · M4 IUE `url_only` fix · SystemWeakness URL Acquisition · CRE retirement · `^` XOR decode-fidelity · OCR wiring · Workspace changes · MITRE/verdict changes · Sysmon E22/E11 · Sample1 seeding · registration of any B/C classified stage · provenance producer wiring · `_ACQUIRABLE_CLASSES` extension · `_ida_extract` change · `_ice_correlate` change · IDA / `_VENDORS` / User-Agent / Playwright / ImageAdapter changes.
