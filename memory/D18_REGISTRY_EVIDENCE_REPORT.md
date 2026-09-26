# D18 — REGISTRY EVIDENCE

Date: 2026-09-15 · **PREVIEW ONLY — no production deployment, no merge.**

```
cd /app/backend && python -m pytest tests/test_d18_registry_evidence.py -q
cd /app          && python scripts/p0_d18_registry_evidence_live_proof.py
```

## RESULT: **PASS**

| Proof | Result |
|---|---|
| `tests/test_d18_registry_evidence.py` | **54 passed** |
| `scripts/p0_d18_registry_evidence_live_proof.py` (real HTTP, preview) | **PASS** — 41/41 checks |
| Regression (24 files: D2–D18, ingest, pipeline, EDR, rounds) | **598 passed**, 12 failures — all pre-existing, verified identical on a stashed clean tree |

## THE CHAIN, PROVED END TO END

```
raw registry observation (Sysmon 13 / Windows 4657)
  -> canonical registry entity
  -> declared evaluated field (registry.key_path / .target_object / .action)
  -> predicate (DET-PS-001)
  -> matched observed value (the Run key the source actually wrote)
  -> evidence_ref -> resolves to the evidence
  -> detection -> verdict -> incident
```

## CHANGED

| File | Δ | What |
|---|---|---|
| `telemetry/models.py` | +20 | `RegistryEntity` (hive, key_path, value_name, value_data, value_type, action, target_object, new_key_path) on `CanonicalTelemetryEvent` |
| `telemetry/registry_evidence.py` | **NEW**, 280 | Sysmon 12/13/14 and Windows 4657 mapping, per-field provenance, hive resolution, actor/device/identity association |
| `telemetry/sysmon_dsm.py` | +30 | EventType/NewName carried through the parser; registry entity + `additional_fields.registry_mapping` for EIDs 12/13/14 only |
| `telemetry/windows_security_dsm.py` | +40 | **4657 is now a supported EventID**; `registry_value_modified` evidence with the same mapping |
| `library/rules_enterprise.py` | +150 | DET-PS-001 predicate now reads OBSERVED registry fields only; **new DET-PS-005** carries the command-line inference; declarations + canonical fixtures for both |
| `library/declaration_contract.py` | ±25 | DET-PS-001 removed from the debt ledger; `CLOSED_TELEMETRY_GAPS` records how the gap was closed |
| `tests/test_d18_registry_evidence.py` · `scripts/p0_d18_…live_proof.py` | **NEW** | |
| `tests/test_d17_rule_declaration_contract.py` | 2 tests | coverage 20→22, gap-closure assertions |

Declaration coverage: **20/36 → 22/37** (DET-PS-001 declared, DET-PS-005 added and declared).

## THE LINE THIS GATE HOLDS

**A command line that mentions the registry is not registry telemetry.**

`reg add HKCU\…\Run /v x /d y /f` is an observed **process** with an inferred
**intent**. It produces no registry entity, no `registry_mapping`, and it does
not fire the observed-registry rule. It fires **DET-PS-005**, whose
description says it is an inference and whose citation names
`process.command_line`.

Before D18, `DET-PS-001` read `command_line` in the same expression as
`registry.path`, so "the registry was written" and "a process asked for the
registry to be written" produced the same finding with the same confidence.
Coverage is unchanged — both cases still fire a rule — but an investigation
can now tell which claim it is looking at, and the two share a technique
(`T1547.001`) while sharing **no** declared field.

## PER-FIELD PROVENANCE · OBSERVED / DERIVED / NOT_OBSERVED

Every field states which it is, with a source, a basis or a reason:

* `key_path` / `value_name` from Sysmon 13 are **DERIVED** — Sysmon appends
  the value name to `TargetObject`, so the split is computed and the verbatim
  `target_object` is preserved beside it;
* Sysmon carries **no** value type → `NOT_OBSERVED` with the reason, rather
  than parsing a type out of the `Details` string;
* a Sysmon **EventID 12 with no EventType** covers BOTH CreateKey and
  DeleteKey → the operation is `NOT_OBSERVED` and the rule therefore does not
  fire. It is not assumed to be a create;
* an undocumented `4657 OperationType` is recorded raw and left unmapped;
* an unrecognised hive is not assumed;
* an absent actor is **absent** — the reason literally says "not SYSTEM".
  Registry evidence still stands without an actor.

D12 semantics are untouched: Sysmon states `ACTIVITY_TIME` from `UtcTime`,
while Windows 4657 still declares `OBSERVATION_TIME` and refuses to promote
`TimeCreated` into an activity instant. D14 tenant authority and D15 declared
routing are unchanged on the same events.

## BENIGN REGISTRY ACTIVITY STAYS BENIGN

Proved in both pytest and the live run: theme writes, Explorer advanced
settings, uninstall entries, service configuration and a Run key **read**
(EventID 12 with no operation) all produce registry evidence and **no**
persistence detection. Touching the registry is not persistence.

## CROSS-SOURCE AGREEMENT (a free result worth noting)

Sysmon 13 and Windows 4657 describing the same write converge on the same
`registry.target_object`, from independent field layouts
(`TargetObject` vs `ObjectName` + `ObjectValueName`). The same declared rule
fires on both, with the same citation class — which is exactly what a
unified XDR evidence model is supposed to deliver.

**TEST/SYNTHETIC payloads. No real Windows host connected. Nothing deployed,
no protected branch touched.**
