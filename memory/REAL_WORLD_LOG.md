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
