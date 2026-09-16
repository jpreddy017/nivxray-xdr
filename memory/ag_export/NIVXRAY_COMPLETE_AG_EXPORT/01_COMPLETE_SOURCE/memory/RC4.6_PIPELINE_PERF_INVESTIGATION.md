# RC4.6 Follow-up Engineering Task — Pipeline Performance Investigation

**Status:** PLANNING ONLY — no implementation authorized yet
**Priority:** P1 (post-RC4.6 semantic engine work)
**Owner:** TBD
**Estimated effort:** 2-4 days investigation + 1-3 days implementation depending on findings

---

## Background

During the RC4.5.6 infrastructure investigation (Feb 21, 2026), we measured a ~5-second **fixed pipeline overhead** on BOTH Preview and Production — meaning even a trivial input like `"hello world"` that produces zero decoder candidates still takes ~5 seconds to return.

Evidence:
- `"hello world"` on Preview: 5.1s
- `"hello world"` on Production: 5.8s
- Same code, both environments — this is a decoder/pipeline inefficiency, not an infrastructure delta.

This is independent of the Prod-CPU issue that RC4.5.6 mitigated. If we can drive this 5-second baseline to ~200ms, ALL decodes get faster, and complex payloads that today take 4-5s would drop to sub-second on Preview and to a few seconds on Prod.

---

## Investigation goals

1. **Identify the 5-second overhead source.**
   - Which decoder(s) in the orchestrator queue burn wall-clock on payloads that never match?
   - Is there a shared "exhaust all candidates" pass that could short-circuit early?
   - Are any regex compilations happening per-request instead of module-level?
2. **Instrument the pipeline** with optional per-stage timing exposed on the API response.
3. **Identify safe caching opportunities** without changing decode behaviour.
4. **Report evidence-based improvement recommendations.**

---

## Proposed approach — 3 phases

### Phase 1 — Diagnostic instrumentation (0.5 - 1 day)

Add optional per-stage timing to the `/api/decode/smart` response, behind a debug flag.

**Design:**
- New request parameter: `debug_timing: bool = False` (default off — zero response bloat for normal calls)
- When enabled, add `timing` field to response:
```json
{
  "timing": {
    "decode_ms": 1801,
    "extract_iocs_ms": 0,
    "mitre_map_ms": 36,
    "shellcode_iocs_ms": 48,
    "verdict_card_ms": 4,
    "recipe_step_timings": [
      {"op": "extract-payload", "ms": 1},
      {"op": "base64-decode", "ms": 3},
      {"op": "powershell-alias-normalize", "ms": 2},
      {"op": "xor-brute", "ms": 1791},
      {"op": "crypto-detect", "ms": 4},
      {"op": "family-meterpreter", "ms": 0}
    ]
  }
}
```
- This lets us profile Prod without SSH access and pinpoint the exact slow stage per payload.

**Files touched:** `routers/ops.py` only (~30 lines added, all behind the flag)

**Risk:** VERY LOW — the flag defaults to off, so normal responses are byte-for-byte identical.

### Phase 2 — 5-second baseline overhead investigation (1-2 days)

Use Phase 1 instrumentation to answer:
- On `"hello world"`, what specifically takes 5 seconds?
- Is there a candidate loop that always runs even when nothing matches?
- Are regex patterns compiled per-call?

**Hypotheses to test:**
1. **Wrapper archetype detection** scanning all 4,500 lines of `wrapper_archetypes.py` on every input — a linear scan of a huge match table would explain the fixed cost.
2. **`operations.mitre_map()` on empty/trivial input** — the ReDoS hotfix improved worst-case but the 125 patterns still run.
3. **Regex re-compilation** — `re.compile(...)` inside function bodies instead of module-level.
4. **Custom-recipe matching** — the `find_matching_recipes(db, body.input)` call at `routers/ops.py:414` runs a Mongo query on every decode; batch these or add a fast-path.

Deliverable: An evidence-backed table of "stage X costs Y ms on trivial input, could be reduced to Z ms by W."

### Phase 3 — Safe performance improvements (1-3 days)

Based on Phase 2 findings, implement the highest-ROI wins that **do not change decode behaviour**.

**Candidates (in priority order, all deterministic):**

1. **Module-level regex constants** — hoist `re.compile()` calls out of function bodies. Zero behaviour change.
2. **LRU cache on `/api/decode/smart`** — SHA-256 of input → cached result (5-minute TTL). Idempotent decoder = safe to cache.
3. **Short-circuit trivial inputs** — if input is <20 chars and has no decoder-friendly characters, skip the exhaustive candidate scan. Return `terminal: "trivial"` immediately.
4. **Batch Mongo lookups** — combine `find_matching_recipes` + case history + IOC history into a single aggregation.
5. **Lazy MITRE mapping** — skip `mitre_map()` when input length < 50 chars (no attack chain fits in 50 chars).

**Acceptance criteria:**
- All 134 RC4.x Quality Gate tests must remain GREEN.
- Full-regression run (all 136 test files) must show identical verdict / confidence / iocs on the ToInvestigate case and 10 other known-good corpus samples (bit-for-bit output equality — this is deterministic).
- Trivial payload wall-time drops from ~5s to <500ms.
- Heavy payload wall-time drops from ~5s to <3s on Preview (proportional Prod improvement contingent on Emergent Support resolution).

**Non-goals (out of scope for this task):**
- Rewriting XOR-brute in Cython/Rust (separate performance ticket, RC4.7 candidate).
- Changing decoder ordering or scoring (would change verdict outputs — forbidden).
- Adding new decoders (RC4.6 semantic engine work is separate).
- Removing any current capability.

---

## Blockers / dependencies

- **None to start Phase 1** — self-contained.
- Phase 2 depends on Phase 1 shipping.
- Phase 3 depends on Phase 2 findings.

---

## Related documents

- `/app/memory/RC4.5.6_DEPLOYMENT_NOTE.md` — the 15s→45s ceiling mitigation
- `/app/memory/RC4.5.6_INFRA_REPORT_FOR_EMERGENT.md` — the Emergent Support ticket
- `/app/memory/RC4.5_ARCHITECTURE_AUDIT.md` — the full architecture audit (section 15 flagged "no result caching" as a performance debt item)
