# NivXRay — Real-World Usage Log

_Started 2026-02-28. Purpose: let real SOC cases (not guesses) prioritize v1.6.0._

**Status:** Feature development frozen at v1.6.0 Phase 1a. This log is the sole input for unfreezing.

---

## How this log drives the roadmap

1. Every real investigation gets one entry below.
2. Every `UNKNOWN` verdict must answer: **"What additional evidence would have promoted this to a higher-confidence verdict?"**
3. When a `Missing Evidence` category repeats across ~50–100 cases, it earns a phase (Phase 1b, later, etc.).
4. No new heuristics are added on guesses. Patterns must emerge from this file first.

---

## Missing-Evidence → Phase mapping (living table)

| Missing Evidence          | Target Phase | Notes                                                     |
|---------------------------|--------------|-----------------------------------------------------------|
| Executable name           | Phase 1b     | Vendor CLI recognition + weighted evidence                |
| Digital signature / signer| Phase 1b     | Known-good signer → positive benign evidence              |
| Parent process            | Phase 1b     | Process-tree context weighting                            |
| File hash                 | Phase 1b     | Reputation lookup gate                                    |
| Network telemetry         | Later        | Requires telemetry ingest surface                         |
| Registry context          | Later        | Requires endpoint context surface                         |

_Update the phase column only when repeated evidence supports it._

---

## Vendors in scope for case collection

Cisco XDR · QRadar · Microsoft Defender · Secure Endpoint · Umbrella · IronPort · Sophos

---

## Entry template (copy for each real case)

```
### Case <NNNN> — YYYY-MM-DD — <short-title>

- Vendor / Source:            (e.g., Cisco XDR alert #1234)
- Sample class:               (e.g., ps-encoded, cmd-lolbin, base64-macro, js-obfuscated, msi-installer,
                               wmi-persist, scheduled-task, defender-tamper, ps-download-cradle, dll-sideload)
- Original artifact:          (paste command line / script / shellcode; redact PII)
- NivXRay current output:     (verdict band + confidence + top evidence keys)
- Expected analyst conclusion:(what an experienced SOC analyst would call it)
- Outcome bucket:             Correct | Missing Evidence | Incorrect Reasoning | Incorrect Verdict
- If UNKNOWN — appropriate?:  YES (evidence truly insufficient) | NO (should have decided)
- Missing evidence:           (executable-name | signer | parent-process | hash | net-telemetry | registry | other | none)
- Reusable capability gap?:   YES → log it | NO but Correct → log as regression | NO + env-specific → do not log
- Would-fix priority:         P0 | P1 | P2 | none
- Notes:                      (analyst commentary, only lessons that generalize)
```

---

## Entries

<!-- Paste one Entry block per real case investigated below this line. -->

### Case 0001 — 2026-02-28 — PS_ASCII_XOR_IEX archetype garbled output

- Vendor / Source:            Analyst-supplied training sample (obfuscation demo)
- Sample class:               ps-encoded (integer-array XOR + IEX)
- Original artifact:          `powershell -NoProfile -NonInteractive "((97,68,95,66,83,27,126,89,69,66,...) | ForEach-Object {[Char]($_ -bxor '0x36')} ) -join '' | Invoke-Expression"`
- NivXRay current output:     Verdict `MALICIOUS 100/100`; OUTPUT panel showed garbled `.)+Knuhy1Tsoh<;Typps<Ksnpx=;<...`; IOCs/TI/OSINT empty
- Expected analyst conclusion:Decoded plaintext = `Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green` (benign obfuscation demo)
- Outcome bucket:             `Incorrect Reasoning`
- If UNKNOWN — appropriate?:  n/a (verdict was MALICIOUS, not UNKNOWN)
- Missing evidence:           none — the deterministic decoder DID produce the correct plaintext; a downstream output-selection defect discarded it
- Reusable capability gap?:   YES → correctness bug in existing capability, not a missing capability
- Would-fix priority:         P0 (immediate — correctness defect in existing decoder path)
- Notes:
  - Root cause: the canonical output shown to the analyst came from replaying a non-self-contained recipe instead of using the already-correct deterministic decoder output.
  - Server-side: `wrapper_archetypes.py:4224` emits archetype chain steps with `args: {}`, so the recovered XOR key (0x36) is not persisted onto the `xor` step.
  - Client-side: `selectCanonicalOutput.js` replayed the recipe via `/api/recipe/run`; the replay ran `xor` with default key `0x2A`, producing garbage; the selector then preferred the garbage over the correct `result.output`.
  - Fix (narrow): frontend guard — skip recipe replay when `engine.startsWith("archetype:")`. See `/app/frontend/src/lib/selectCanonicalOutput.js`.
  - Regression tests: `/app/backend/tests/test_ps_ascii_xor_iex_output_selection.py` (3 invariants: handler-correct, engine-name-stable, recipe-replay-not-self-reproducible).
  - Verdict-band separate concern: `MALICIOUS 100/100` on a Hello-World payload is a distinct false-positive driven by YARA-pattern presence alone. Not addressed in this fix — logged as a future capability gap once more evidence accumulates (see Missing-Evidence table).

