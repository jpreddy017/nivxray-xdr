# Workspace Decode Pipeline Recovery — Evidence Summary

Session anchor: **Phase 3 (Behavioral A/B) + Phase 3.5 (Behavior-linked Dep Graph)** — evidence only, no restoration, no wiring.

## Trees Compared
- Baseline: `/tmp/workspace-v1.5.6/backend/` — git `fff5897` — Jul 28 16:10 UTC (Certified Workspace Baseline · v1.5.6 Behavior)
- Current : `/app/backend/` — HEAD

## Determinism guards applied by the A/B harness
- `analysis_mode: "fast"` forced at every request
- LLM egress stubbed (litellm + emergentintegrations) → temperature noise cannot cause false divergences
- `.env` copied into baseline worktree so both trees share the same JWT / DB / Mongo config
- `get_current_user` overridden to a stub — no live JWT / user seed needed
- Both trees invoked in isolated subprocesses so their `sys.modules` cannot cross-contaminate

## Corpus (v1.0.0 — 10 samples · initial certification corpus)
`S01_ps_b64_utf16le · S02_bash_xxd_b64_rev · S03_cmd_caret_escaped · S04_ps_alias_heavy · S05_nested_b64_gzip · S06_xor_obfuscated · S07_rc4_openssl · S08_unicode_obfuscation · S09_hex_b64_gzip_chain · S10_bash_with_powershell_comment`

## Headline result

**9 / 10 samples DIVERGE between baseline and current.** Only `S06_xor_obfuscated` is identical.

| # | Sample | Baseline | Current | Same? | First divergence |
|---|---|:---:|:---:|:---:|---|
| 1 | `S01_ps_b64_utf16le` | PASS | PASS | ❌ | interpreter tag differs (baseline emitted no interpreter marker; current emits `powershell` via `ps-encodedcommand-recovery`) |
| 2 | `S02_bash_xxd_b64_rev` | PASS | PASS | ❌ | **Bash misrouted to PS normalizer** — current op `powershell-alias-normalize` |
| 3 | `S03_cmd_caret_escaped` | PASS | PASS | ❌ | baseline `strip-carets, extract-b64, utf16le-decode` → current `cmd-runtime-reconstruct, extract-payload, base64-decode, utf16le-or-utf8-decode` |
| 4 | `S04_ps_alias_heavy` | PASS | PASS | ❌ | index 0 op: baseline `ps-string-concat` → current `ps-reconstruct` |
| 5 | `S05_nested_b64_gzip` | PASS | PASS | ❌ | index 2 op: baseline `gzip-decompress` → current `crypto-detect` (gzip step lost) |
| 6 | `S06_xor_obfuscated` | PASS | PASS | ✅ | identical |
| 7 | `S07_rc4_openssl` | PASS | PASS | ❌ | index 0 op: baseline `extract-payload` → current `rot47` |
| 8 | `S08_unicode_obfuscation` | PASS | PASS | ❌ | current inserts extra `extract-payload` op at index 0 |
| 9 | `S09_hex_b64_gzip_chain` | PASS | PASS | ❌ | baseline stops after `hex, base58, xor-brute, ps-normalize...` — current stops after `hex-decode, base64-decode`; gzip stage lost in both, but stage order & interpreter routing diverge |
| 10 | `S10_bash_with_powershell_comment` | PASS | PASS | ❌ | **Regression guard failure** — baseline `ops=[]` (correct passthrough); current fires `powershell-alias-normalize` |

Details for every ❌ row: `phase3_ab_report.md` (per-sample decoder chain + final output snapshots).

## Behavioral blast radius (Phase 3.5)

Ranked by how many divergent samples touch each module. This is the **working set for Phase 4 root-cause analysis** and the **candidate minimal-fork target list for Phase 6**.

| Rank | Module | Samples affected |
|-----:|--------|-----------------:|
| 1 | `operations` | 6 |
| 2 | `magic_decoder` | 5 |
| 3 | `analysis_core` | 3 |
| 4 | `engine.orchestrator` | 2 |
| 5 | `rc22_adapter` | 2 |
| 6 | `decoders.ps_alias_normalizer` | 2 |
| 7 | `nivxforge.investigation.customer_report` | 2 |
| 8 | `nivxforge.investigation.analyst_narrative` | 2 |
| 9 | `nivxforge.investigation.summary_composer` | 2 |
| 10 | `smart_decoder` | 2 |
| 11 | `decoders.cmd_runtime_reconstruct` | 1 |
| 12 | `decoders.ps_reconstruct` | 1 |
| 13 | `decoders.crypto_symmetric` | 1 |
| 14 | `decoders.rot47` | 1 |
| 15 | `decoders.base64` | 1 |

Full per-sample behavior-linked chains: `phase3_5_dep_graph.md`.

## Two headline findings

1. **The `\bpowershell\b` routing flaw is real and evidenced.** `S10_bash_with_powershell_comment` — a plain Bash `echo` with the literal token `powershell` inside a comment — passes through the baseline with zero decoder ops but fires `powershell-alias-normalize` on current HEAD. Same story on `S02_bash_xxd_b64_rev`. This is the regression the owner has been describing.

2. **The core drift is concentrated in ≤ 6 behavioral modules.** `operations`, `magic_decoder`, `analysis_core`, `engine.orchestrator`, `rc22_adapter`, and the `decoders/ps_alias_normalizer.py` + `decoders/cmd_runtime_reconstruct.py` pair account for **every** divergent sample. This is the Phase 6 minimal-fork candidate list. `nivxforge/*` shows up only via investigation-narrative code paths, which are Intelligence-Layer, not Decode-Pipeline; those should NOT be forked into Workspace.

## What this session did NOT do (by contract)

- Did **not** restore or edit any file in `/app/backend/routers/`, `engine/`, `v2/`, `timeline/`, `nivxforge/`
- Did **not** wire `backend/workspace/interpreter_ownership.py` (still dormant)
- Did **not** infer anything from source diffs — every finding above is produced by executing `/api/decode/smart` on both trees

## Artifacts written

```
backend/workspace_recovery/
├── corpus.json                    ← 10-sample certification corpus (v1.0.0)
├── tree_worker.py                 ← isolated per-tree subprocess worker
├── runner.py                      ← Phase 3 orchestrator
├── dep_graph.py                   ← Phase 3.5 orchestrator
├── phase3_ab_report.md            ← human-readable A/B table + stage traces
├── phase3_5_dep_graph.md          ← behavior-linked chains + blast radius
├── EVIDENCE_SUMMARY.md            ← this file
└── artifacts/
    ├── baseline_raw.json          ← raw v1.5.6 responses (all 10 samples)
    ├── current_raw.json           ← raw HEAD responses (all 10 samples)
    ├── phase3_ab_matrix.json      ← normalized per-sample diff
    └── phase3_5_dep_graph.json    ← full graph JSON
```

## Reproducibility

```bash
cd /app/backend
python -m workspace_recovery.runner       # Phase 3
python -m workspace_recovery.dep_graph    # Phase 3.5
```

Both are deterministic. Repeated runs produce byte-identical artifacts.

## Recommended next step (Phase 4 — root cause per divergent sample)

Owner decision required. Suggested cuts (in order):

1. **`operations`** — appears in 6/9 diverging samples. Focus here first: the op-registry ordering + how new ops were added between v1.5.6 and HEAD is the highest-leverage single-file investigation.
2. **`magic_decoder` + `smart_decoder`** — 5+2 samples; likely responsible for the chain-selection differences (S05 gzip step loss, S07 rot47 misfire, S09 chain truncation).
3. **`decoders/ps_alias_normalizer.py` + interpreter-ownership** — responsible for the S02 & S10 Bash-misrouted-to-PowerShell regressions. This is where the dormant `workspace/interpreter_ownership.py` fix will eventually land — but only AFTER (1) and (2) are cleared.
4. **`analysis_core` + `engine/orchestrator` + `rc22_adapter`** — orchestration wrappers; drift here explains the stage-order differences on S01, S03, S08, S09.
5. **`nivxforge/*` investigation-narrative modules** — Intelligence Layer. Per Decode Pipeline Contract, these MUST NOT influence the decoder. If Phase 4 shows they do, that itself is a bug — not a candidate for fork.

**No file will be restored or forked until this evidence is reviewed and Phase 4 root cause is confirmed per divergent sample.**
