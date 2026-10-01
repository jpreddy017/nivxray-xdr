# Completion Record · P1-02c · Verdict Engine Polish + Shellcode Parity Hotfix

## Backlog ID
`P1-02c` (Sprints 1-4 + Shellcode-Parity Hotfix)

## Objective
Polish the verdict engine before it becomes the input to the P1-02d
Investigation Truth Model and the full architecture assessment.

## Ships

### Sprint 1 · Graph-Aware Scoring + Temporal Correlation
- `nivxforge/investigation/topology_signals.py`
- `graph_topology_signal()` — longest chain through causal edges
  (`produces / contributes_to / supports / derived_from / escalates_to`).
  Depth ≥ 3 emits synthetic `behaviour` node `execution_chain_correlated`
  (HIGH attack-chain kind). Depth ≥ 5 → conf 0.95. **Requires ≥ 1
  attack-worthy kind in the path** — benign decode ladders no longer
  false-promote.
- `temporal_correlation_signal()` — sliding 60 s window over
  `attrs.timestamp`; ≥ 2 attack-chain-eligible nodes within window →
  `temporal_burst` (HIGH attack-chain kind, conf tiered on span).

### Sprint 2 · Entity Correlation + Negative Evidence
- `nivxforge/investigation/correlation_signals.py`
- `entity_correlation_signal()` — groups nodes by
  `parent_process_id / process_id / image_hash / image_path / user_sid
  / host_id`. ≥ 3 signals on the same entity → `entity_chain_correlated`
  (HIGH attack-chain kind).
- `negative_evidence_signals()` — detects mitigating factors:
  * signed-Microsoft binary
  * internal RFC1918 / loopback / link-local IPs
  * enterprise-allowlist tags (`sccm`, `intune`, `gpo`, `admin-script`, …)
  * benign parent processes (`explorer.exe`, `services.exe`, …)
- New `MITIGATING` EvidenceClass (weight −1). Applied as a single
  aggregate dampener capped at 0.30 when CRITICAL evidence exists,
  0.50 otherwise → **CI-enforced that mitigating evidence NEVER flips
  a Malicious verdict**.

### Sprint 3 · Dynamic Confidence Breakdown + Confidence Timeline
- `VerdictNode.confidence_breakdown` — dict with six keys
  (critical/high/medium/low/context/mitigating) each an int 0-100,
  computed as per-class Noisy-OR.
- `VerdictNode.confidence_timeline` — ordered list of
  `{stage, contributor_label, contributor_kind, class, confidence_pct,
  source}`. Monotonic non-decreasing across positive-class steps;
  mitigating steps may lower confidence.

### Sprint 4 · Verdict Explanation Card
- `frontend/src/nivxforge/lab2/VerdictExplanationCard.jsx` +
  `verdict-explanation-card.css` — single canonical panel: label +
  confidence + escalation-rule tag + reason + six-bar class breakdown +
  positive evidence list + counter-evidence list + confidence timeline
  (compact-mode shows last 4 steps) + supporting-node chips + engine
  identifier. Rendered inside X-Lab Findings sidebar; reused by
  Report Composer and Workspace exec card.
- Six-bar breakdown uses tone-coded left rule (Malicious=red,
  Suspicious=amber, Runtime Dep=yellow, Info=cyan, Unknown=grey) with
  grain overlay — no AI-slop gradients.
- Card projection lives in `labv2.projector.js`:
  `view.verdict.{escalationRule, breakdown, timeline, positive, counter,
  notCounted, supportingNodeIds, engine}`.

### Shellcode-Parity Hotfix (P0 · reported by user)
- **Problem**: X-Lab's Decoded Output Preview was dumping raw GZIP-
  decompressed bytes for encoded-PS → GZIP → IEX → shellcode chains,
  while Workspace correctly renders a "SHELLCODE DECODED · family ·
  arch" banner with C2 IPs and user-agents extracted.
- **Fix**:
  - `fact_substrate.py` — on `result.reached_shellcode` or `is_shellcode`,
    runs `shellcode_analyzer.analyze(raw)` + `_family_recognise(raw)`
    and stashes {`is_shellcode, family, family_mitre, arch, size,
    entropy, c2_ips, c2_urls, c2_domains, user_agents, strings,
    hex_preview, disasm_lines, capstone_available`} under
    `fs.verdict_metadata["shellcode"]`.
  - `builder.py` — injects a synthetic behaviour node
    `shellcode_detected` (mapped as CRITICAL evidence class in
    `evidence_classes.KIND_TO_CLASS`) + decorates the terminal
    `decoded_fragment` node with `attrs.is_shellcode = True` and
    `attrs.shellcode_summary` + surfaces the summary at
    `cio.metadata.shellcode`.
  - `labv2.projector.js` — new `view.shellcode` block; the decode
    ladder's last frame carries `isShellcode + shellcode` to gate the
    banner.
  - `LabV2.jsx` — Decoded Output Preview now renders a proper analyst
    banner (family · arch · size · entropy · C2 IPs · user-agent ·
    hex preview) when `view.shellcode.is_shellcode`; raw bytes are
    suppressed.
- **Live verification** (MSFvenom x86 stager · WinInet + C2
  149.28.81.19): reached_shellcode=True · family="Metasploit
  Meterpreter (reverse_tcp/https · x86 stager)" · arch=x86_64 ·
  size=551 · entropy=1.419 · c2_ips=['149.28.81.19'] · **verdict
  Malicious @ 99%**.

## Test Suite Additions
- `tests/parity/test_verdict_topology_temporal.py` — 11 tests
- `tests/parity/test_verdict_entity_negative.py` — 9 tests
- `tests/parity/test_verdict_breakdown_timeline.py` — 5 tests
- Total parity suite: **67 passed, 13 skipped, 0 failed**.

## Live Regression Board
| Input | Verdict | Confidence | Rule |
|---|---|---|---|
| `hello world` | Informational | 23 % | — |
| `echo hello` | Suspicious | 73 % | — |
| BITS + URL | **Malicious** | 80 % | BITS + network download |
| Encoded PS + IEX + URL | **Malicious** | 100 % | (class · high×5) |
| MSFvenom stager + C2 149.28.81.19 | **Malicious** | 99 % | shellcode_detected (CRITICAL) |

## Constitutional Compliance
- [x] CIO Supremacy — all signals attached to CIO nodes / metadata; no
      vendor objects exchanged
- [x] No new architectural layer — two new sub-modules, zero new
      buses / registries / adapters
- [x] Deterministic — every synthetic signal is a pure function of the
      graph / metadata state
- [x] Backward-compatible — `compute_verdict(graph)` without metadata
      still works
- [x] Confidence monotonicity CI-enforced
- [x] Six permanent gates from P1-02b remain green
- [x] No ADR required (all changes within existing constitution)

## Known Limitations
- MITRE-technique elevation still uses substring matching. Deferred
  to P2-04 (Semantic Investigation Graph).
- Temporal correlation requires event-time attributes on nodes; today's
  inputs rarely carry them. Will be exercised heavily once IDI adapters
  land in P2-05.

## References
- `/app/docs/BACKLOG.md` · P1-02c
- Constitution: §1.1.3, §1.1.16, §1.1.17, §13
- Previous completion: `/app/docs/completions/P1-02b-tiered-verdict-fold.md`

## Next
- **P1-02d** · Investigation Truth Model (single canonical projection
  shape shared by Executive Summary, Story, Verdict, Ledger,
  Notebook, Reports, Exports)
- **Full Architecture Assessment** (Parts 1-20, master + per-part)
