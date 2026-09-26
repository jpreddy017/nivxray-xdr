# Canonical Investigation · Reference Implementation

This is the **golden investigation** — a fully worked example that
demonstrates every stage of the X-Lab pipeline against a single
synthetic incident. New engineers should read this before touching
any Adapter or engine.

## Scenario
BITS-transfer PowerShell downloader observed by three vendors
(Cisco XDR · Sysmon · Defender) hitting `evils.com/a.exe` on host
`AZG51-CHECKIN-1`.

## Files

| Path | Meaning |
|------|---------|
| `raw/cisco.json`   | Cisco XDR incident export — Document Adapter input |
| `raw/sysmon.evtx`  | Sysmon EventID 1/3/13 sequence — Log Adapter input |
| `raw/syslog.log`   | Firewall syslog with DNS+HTTP flow — Log Adapter input |
| `raw/defender.json`| Defender XDR alert — Document Adapter input |
| `expected/cio.json`      | Canonical Investigation Object after ingestion |
| `expected/ikg.json`      | Investigation Knowledge Graph nodes + edges |
| `expected/ledger.json`   | Deterministic reasoning steps (Ledger) |
| `expected/story.json`    | Attack Story composed from IKG |
| `expected/executive.json`| Executive Summary derived from CIO |
| `expected/report.json`   | 14-section Report Composer output |

## How this is used

1. **Onboarding** — every engineer reads the raw files and each
   expected file to understand the CIO contract end-to-end.
2. **Regression asset** — CI reprocesses `raw/*` through the current
   pipeline and asserts semantic equivalence with `expected/*`.
3. **Cross-vendor parity** — the three vendor inputs describe the
   SAME incident. The resulting CIOs must be semantically equivalent
   (§5 P2-05b · Canonical Schema Stability Test).
4. **Constitution smoke test** — proves §10 (CIO-only exchange) and
   §11 (adapter plug-in model) hold end-to-end.

## Rules

- Files under `expected/` are updated ONLY when the pipeline is
  intentionally modified. Any diff surfaces as a review checkpoint.
- Adapter authors add a new sibling folder (e.g. `sample_bundle/`,
  `sample_okta/`) rather than mutating this one.
- This directory is READ from the parity CI. Removing it fails CI.
