# ADR-0014g · P0a + P0b — Analyst-Paste Evidence Projection Repair

**Status**: 🟢 CLOSED (owner-authorised, executed 2026-02-15)
**Predecessors**: read-only pipeline trace (ADR-0014e §11 sibling investigation)
**Successor**: **STOP** — do not authorise M0e/M0f based on this fix. Re-run the exact Analyst Paste screenshot scenario and reassess independently. — **LOCKED**

---

## 1 · Root cause (from prior read-only trace)

The read-only trace across 3 history cases pinpointed the defect to **two lines**:

1. `services/die/investigation_results.py:317-338` — `report_extraction` is populated **only** when `ida_class ∈ _ACQUIRABLE_CLASSES`. For every other classification, it stays `{}` — even though IDA already extracted `raw.artifacts`, `raw.iocs`, `raw.behaviour`, `raw.commands`, `raw.mitre`, `raw.lolbas` at the top level.
2. `services/session/summary_narrative.py:_counts` — only counts `command|powershell|cmd|bash` inputs and `incident.mitre`. **Never sets `counts["iocs"]`.**

Screenshot reproduced exactly: `atomic_url_ioc` paste → `report_extraction={}` → `Commands 0 / IOCs 0 / MITRE 0`.

## 2 · P0a — Paste-path `report_extraction` projection

**Change**: `services/die/investigation_results.py` — added **58 LOC** immediately after the IOC-deduplication block (before "Build the OUTPUT text"):

```python
# ── P0a (ADR-0014g) · Analyst-Paste evidence projection ────────
if not report_extraction:
    _paste_artifacts = list(ida_verdict.get("artifacts") or [])
    _paste_commands  = [_command_to_ssot(_s) for _s in pre.stages]
    # Flatten ioc_by_kind {kind: [values]} into artifact-shaped
    # dicts so `body_artifacts` reflects the total IOC surface.
    _seen_art_keys = {(a.get("type"), a.get("canonical") or a.get("value"))
                      for a in _paste_artifacts}
    for _kind, _vals in (ioc_by_kind or {}).items():
        for _v in _vals:
            if (_kind, _v) in _seen_art_keys:
                continue
            _paste_artifacts.append({"type": _kind, "value": _v,
                                     "canonical": _v,
                                     "source": "preprocessor.ioc"})
            _seen_art_keys.add((_kind, _v))
    report_extraction = {
        "body_artifacts":     _paste_artifacts,
        "mitre_techniques":   list(techniques),
        "cves":               [],
        "threat_actors":      [],
        "malware_families":   [],
        "commands":           _paste_commands,
        "timeline":           [],
        "yara_rules":         [],
        "sigma_rules":        [],
        "hash_context":       {},
        "behaviors":          [],
        "totals": { "artifacts": len(_paste_artifacts),
                    "mitre":     len(techniques),
                    "cves": 0, "actors": 0, "malware": 0,
                    "commands":  len(_paste_commands),
                    "timeline": 0, "yara": 0, "sigma": 0, "behaviors": 0 },
        "source":             "paste_projection",   # provenance flag
    }
```

### Contract match

Owner directive: *"P0a is a projection/adaptation, not merely a dictionary copy."*

The projection matches the exact shape emitted by `_ida_extract` (line 214 of `services/ida/report_extractors.py`) — 12 keys, one `source` provenance flag added so downstream consumers can distinguish paste-projected data from URL-acquired data. Every key present in both paths.

### Guards

- `if not report_extraction:` — activates **only** when the URL-acquired branch left it empty. When the URL was successfully acquired, the branch above already populated `report_extraction` via `_ida_extract`, and P0a is a no-op.
- No re-extraction. All fields sourced from already-computed in-scope variables:
  - `ida_verdict.artifacts` — set by `_ida_classify(src)` at line 307
  - `pre.stages` — set by `_stage("preprocessor", ...)` at line 201
  - `techniques` — built at lines 271-285
  - `ioc_by_kind` — built earlier in the same enclosing block
- No IDA, DIE, router, registry, IUE, MITRE, verdict, URL acquisition, or `_ACQUIRABLE_CLASSES` change.

## 3 · P0b — `_counts["iocs"]` awareness

**Change**: `services/session/summary_narrative.py:523-536` — 12 LOC added inside `_counts()`:

```python
counts["mitre"] = len(inc.get("mitre") or [])
# P0b (ADR-0014g) · surface IOC evidence already present in the
# incident SSOT so paste-derived investigations show a non-zero
# count when IOCs actually exist.
_incident_iocs = inc.get("iocs") or []
if isinstance(_incident_iocs, dict):
    _incident_iocs = sum((v for v in _incident_iocs.values()
                          if isinstance(v, list)), [])
counts["iocs"] = len(_incident_iocs)
return counts
```

Handles both SSOT shapes: `iocs: [...]` (flat list) and `iocs: {kind: [...]}` (dict-of-lists). No change to `commands`/`mitre` semantics.

## 4 · Live probe — matches owner's expected behaviour exactly

Post-P0a+P0b probe on the three trace-case shapes:

| Case              | rext.source        | commands | body_artifacts | mitre_techniques |
|-------------------|--------------------|:--------:|:--------------:|:----------------:|
| atomic_url_ioc    | paste_projection   |    **0** |          **1** |            **0** |
| powershell_paste  | paste_projection   |    **2** |          **4** |            **5** |
| csv_paste         | paste_projection   |    **1** |          **2** |            **0** |

Owner's mandate: *"Non-zero only when evidence actually exists."* Held exactly:
- URL alone → 1 artifact (the URL), 0 commands, 0 MITRE.
- Real command paste → real commands + MITRE surface.
- CSV → artifacts non-zero, MITRE stays 0 (no MITRE evidence in a bare IOC list).

## 5 · Files changed

| File | Nature |
|------|--------|
| `services/die/investigation_results.py` | +58 LOC — P0a projection block |
| `services/session/summary_narrative.py` | +12 LOC — P0b `counts["iocs"]` |
| `tests/canonical/iue/test_p0_paste_evidence_projection.py` | **NEW · 9 tests** |
| `/app/memory/adr/0014g-p0-paste-evidence-projection.md` | **NEW** — this ADR |
| `/app/memory/PRD.md` | Amended |

**Not touched** — IDA, DIE analyzer, recursive decoder, `_ACQUIRABLE_CLASSES`, URL acquisition, `_ida_extract`, router, registry, IUE, MITRE, verdict scoring, Workspace UI, Attack Chain, IKG, Behavioural Timeline, provenance producer, any adapter.

## 6 · Acceptance tests (owner-mandated) — all 9 green

| # | Test | Status |
|---|------|:------:|
| 1 | `test_p0a_report_extraction_populated_for_command_paste` — non-zero commands surface | ✅ |
| 2 | `test_p0a_report_extraction_populated_for_ioc_list_paste` — CSV artifacts surface | ✅ |
| 3 | `test_p0a_report_extraction_populated_for_atomic_url_ioc` — screenshot case | ✅ |
| 4 | `test_p0a_url_acquired_path_still_uses_ida_extract` — URL path not shadowed | ✅ |
| 5 | `test_p0a_does_not_mutate_top_level_ssot_fields` — `raw.*` unchanged | ✅ |
| 6 | `test_p0b_counts_include_iocs` — new `counts["iocs"]` present | ✅ |
| 7 | `test_p0b_counts_iocs_zero_when_no_evidence` — no false positives | ✅ |
| 8 | `test_p0b_counts_iocs_handles_dict_shape` — both SSOT shapes | ✅ |
| 9 | `test_screenshot_defect_no_longer_reproduces` — exact regression witness | ✅ |

## 7 · Regression results

| Suite | Before P0 | After P0 | Delta |
|-------|:---------:|:--------:|:-----:|
| `canonical/iue/` | 172 / 1 pre-existing Sample1 fail | 181 / 1 fail | **+9** |
| M0-tier focused (M0a+M0b+M0b-ext+M0c+M0d+M0d-async+M0e+harness+P0) | 129 / 0 | 138 / 0 | +9 |
| P2 Sysmon Slice-1/2/3 + Report determinism + UI-DEF-02 + payload-shape + Sample1-immutability + Workspace-isolation | 68 / 3 skip | 68 / 3 skip | 0 |

Zero regression. The single canonical/iue/ failure remains the pre-existing Sample1-DB baseline (`nivxray_ci_local` vs `test_database` seed) — unrelated to P0.

## 8 · Guardrails held

- All 4 M0a IUE envelope hashes byte-identical.
- SystemWeakness projection unchanged: `[ioc_enrichment.v1, report.narrative.v1]` — `url.acquire.v1` still absent.
- Legacy URL-acquired path unchanged when acquisition succeeds (P0a's `if not report_extraction:` guard makes it a no-op on that branch).
- No new evidence synthesised — projection consumes only already-computed variables.
- No IDA / DIE / router / registry / IUE / URL / MITRE / verdict / OCR / provenance-producer / adapter code touched.

## 9 · Answers to owner's acceptance-gate questions

- **Existing `raw.*` evidence unchanged?** ✅ Test `test_p0a_does_not_mutate_top_level_ssot_fields` verifies all top-level SSOT keys unchanged.
- **`report_extraction` populated for paste inputs?** ✅ 3 paste-class tests + the screenshot regression witness.
- **Commands/IOCs/MITRE non-zero only when evidence exists?** ✅ Live probe: URL → 0/1/0; command → 2/4/5; CSV → 1/2/0.
- **URL-acquired path byte/behaviourally unchanged?** ✅ `test_p0a_url_acquired_path_still_uses_ida_extract` + `if not report_extraction:` guard.
- **No router/M0/IUE/Workspace changes?** ✅ File-level grep — only 2 files under `services/die/` and `services/session/` touched.
- **Full M0-tier regression green?** ✅ 138/138.

## 10 · What is NOT authorised as follow-up

Per owner directive:

- ❌ Do not authorise M0e/M0f based on this fix.
- ❌ Do not redesign the 2-pipeline architecture (URL-acquired vs paste).
- ❌ Do not extend `_ACQUIRABLE_CLASSES`.
- ❌ Do not change `_ida_extract`.
- ❌ Do not touch IDA classification, DIE analyzer, MITRE mapping, verdict scoring, IUE, router, registry, Workspace.
- ❌ Do not fix the `^` XOR decoder issue (still-open P1).
- ❌ Do not seed Sample1 into `nivxray_ci_local`.

## 11 · Next authorised step

**None.** Owner directive:
> *"After P0 passes, rerun the exact Analyst Paste screenshot scenario and then reassess the remaining M0 migration independently."*

Awaiting owner confirmation of live UI behaviour post-P0 before any further architectural work.
