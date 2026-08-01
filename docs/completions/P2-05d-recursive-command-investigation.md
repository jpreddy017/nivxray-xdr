# Completion Record · P2-05d Recursive Command Investigation

## Backlog ID
`P2-05d`

## Objective
Extend X-Lab from a single-pass decoder to a recursive investigation engine that queues artifacts, decodes/extracts them, and repeats until an Evidence Graph Fixed Point is reached — with strict recursion policies (Small / Standard / Deep / Unlimited) and guaranteed graceful `PARTIAL` degradation on budget exhaustion (never HTTP 500).

## Implementation
- **Orchestrator**: `/app/backend/nivxforge/investigation/recursive.py`
  - `ArtifactQueue` with deduplication by content hash and configurable cap
  - `RecursionReport` dataclass — `iterations`, `artifacts_processed`, `artifacts_discovered`, `iocs_extracted`, `mitre_techniques`, `hypotheses_validated`, `fixed_point_reached`, `reason_no_new`, `max_depth_reached`, `duration_ms`, `status`, `policy`, `trace[]`
  - `recursively_investigate(cio, seed_content, seed_kind, policy)` — mutates the CIO in place, refreshes verdict + truth on every iteration, terminates on Evidence Graph Fixed Point (all diff conditions True) OR on budget exhaustion (time / artifact count / depth)
  - `_diff_snapshots(cio, prev)` — per-condition equality on `nodes / edges / iocs / mitre / hypotheses / confidence`
  - Snapshot hash via `snapshot_hash(cio)` used for deterministic trace audit
- **Policies**: `RECURSION_POLICIES = { small, standard, deep, unlimited }` — `depth`, `artifacts`, `budget_ms`
- **Day-1 investigators**: base64, command, script, archive (registered in `InvestigatorRegistry`)
- **CIO attachment**: `cio.metadata.recursion_report` populated on every run so every downstream surface (Story, Ledger, UI) can project the report
- **Endpoint wiring**: `POST /api/decode/smart` runs the recursive orchestrator when the input is command/script; on budget exhaustion returns a valid CIO with `recursion_report.status = "partial"` rather than raising

## Tests Added
- Parity: `/app/backend/tests/parity/test_recursive_investigation.py` — 9 tests
  - `test_registry_has_day1_investigators`
  - `test_artifact_queue_dedupes_and_caps`
  - `test_snapshot_hash_stable_over_identical_state`
  - `test_snapshot_changes_when_node_added`
  - `test_recursive_command_extracts_ioc_and_reaches_fixed_point`
  - `test_budget_exhaustion_returns_partial_never_raises`
  - `test_base64_investigator_decodes_and_queues_command`
  - `test_recursion_report_attached_to_cio_metadata`
  - `test_recursion_is_deterministic`

Live verification (2026-02-XX):
```
POST /api/decode/smart with a PowerShell -enc payload →
cio.metadata.recursion_report = {
    "status":              "complete",
    "fixed_point_reached": true,
    "iterations":          4,
    "policy":              "standard"
}
```

## Golden Corpus Updated
No. Existing corpora already exercise the pipeline through the recursive orchestrator. Investigation Quality Benchmark corpus stays as the CI baseline.

## Parity Status
All parity CI green. `tests/parity/test_recursive_investigation.py` (9) + `tests/parity/test_verdict_parity_workspace_vs_xlab.py` (9) → 18 / 18 passing.

## KPI Impact (§13)
| KPI | Before | After | Δ |
|-----|--------|-------|---|
| Adapter detection accuracy | n/a | n/a | — |
| Normalisation correctness | Single-pass | Recursive to fixed-point | + |
| Cross-vendor equivalence  | n/a | n/a | — |
| Replay determinism        | Snapshot-hash stable | Snapshot-hash stable per iteration | = |
| Verdict parity            | Workspace ≡ X-Lab (single pass) | Workspace ≡ X-Lab (recursive) | = |
| E2E investigation latency P95 | ~1.5 s | ~2.0 s (with recursion loop) | +500 ms budgeted |
| Deep-command investigation success rate | Terminated at first layer | Terminates at fixed point OR PARTIAL — never crashes | + |
| Golden-corpus coverage    | Unchanged | Unchanged | = |

## Constitutional Compliance
- [x] Preserves the CIO contract (§10) — the orchestrator only mutates the existing CIO
- [x] Adds no new architectural layer (§11) — lives inside `nivxforge/investigation/`
- [x] Consumes/emits only CIO or named CIO derivatives (RecursionReport is a named CIO metadata block)
- [x] Remains deterministic — snapshot-hash-audited, dedup queue, seeded ops only
- [x] Passes the four PR gates
- [x] No ADR required — extends existing investigation engine

## Integration Audit Attached
An end-to-end integration audit (`/app/docs/audits/2026-02_XLAB_INTEGRATION_AUDIT.md`) was performed concurrently with this ticket, verifying that all 17 already-shipped X-Lab features are actually wired to the live `/nivxforge/x-lab` route (backend populated → API returns → React component mounted → UI renders → screenshot proof). Recursion Report itself is classified **Implemented but NOT integrated** because it currently has no dedicated UI panel — data lives in `cio.metadata.recursion_report` and only indirectly manifests through the richer graph/ledger.

## Known Limitations
1. **UI panel for the RecursionReport**: not yet built. Data is available on `cio.metadata.recursion_report` and the CIO-driven graph already reflects the recursion outcome. Dedicated analyst-facing panel (showing iterations / fixed-point / max depth / duration) is tracked as follow-up under the unified Investigation Graph work.
2. **Investigator plug-in registry**: currently ships base64 / command / script / archive. Additional artifact kinds (registry, url-follow, hash-lookup) will be added as CIO evidence requires.

## Bugs Discovered and Fixed alongside this ticket
- **BUG-01**: `powershell-encoded` operation in `/app/backend/operations.py:599` was hard-coded to `raw.decode("utf-16-le", errors="ignore")`. When fed a non-canonical `-enc` payload (ASCII bytes base64'd instead of UTF-16LE bytes), the operation produced CJK-ideograph mojibake in `decode_chain[].preview`, which cascaded into `summary.analyst` "Recovered payload reads:" and made the Story/Output/Executive lenses appear broken even though verdict/OSINT/MITRE were correct. Fix: replaced with `_ps_encoded_smart_decode_bytes()` that tries strict UTF-16LE → strict UTF-8 → UTF-16LE-replace fallback with printability validation. Verified against both canonical UTF-16LE and ASCII-base64 payloads.

## References
- Backlog line: `/app/docs/BACKLOG.md` · Task P2-05d
- Constitution sections referenced: §10 (CIO), §11 (no new layers), §13 (KPIs)
- Audit: `/app/docs/audits/2026-02_XLAB_INTEGRATION_AUDIT.md`
