# ADR-0012 — Progressive Partial Recovery (Analyse What The Decoder Recovered)

- **Status:** **Accepted · slice-1 implemented** (2026-02-28).
- **Deciders:** Operator (product owner) · Emergent (proposer)
- **Threshold met:** Operator-supplied production case (2026-02-28,
  regsvr32 `-EncodedCommand` blob truncated mid-UTF-16LE) — pipeline
  produced `Undetermined` despite the decoder having a clean
  `regsvr32 /u /s /i:http` prefix in `partial_recovery.prefix_text`.
- **Supersedes / adjusts:** the 2026-07-25 SOC-user lock in
  `v2/semantic/ps_recovery.py:_annotate_confidence_and_partial`
  ("`partial_recovery` … is NEVER used by the AST / behavior extractor
  and NEVER promoted to `recovered_script`"). This ADR narrows that
  lock: `partial_recovery` remains **not promoted to
  `recovered_script`**, but IS made available to the analysis engine
  as a **separately-labeled evidence source**.

## 1 · Problem (evidence-based)

Observable, verified in code:

1. `/app/backend/v2/semantic/ps_recovery.py:406-470` already computes
   `partial_recovery = { prefix_text, prefix_encoding, prefix_bytes,
   corrupted_bytes, corruption_offset }` on every `decode_error`.
2. `/app/backend/routers/ops.py:507-594` short-circuits on
   `_rep.status == "decode_error"` with hard-coded empties:
   `output=""`, `iocs={ips:[], urls:[], …}`, `mitre=[]`, `lolbas=[]`,
   `tradecraft=[]`, `verdict_display="Undetermined"`.
3. Therefore the recovered prefix (e.g. `regsvr32 /u /s /i:http`)
   never reaches `command_analyzer.extract_iocs` /
   `command_analyzer.map_mitre` / LOLBin detection — which already
   contain a `regsvr32 → T1218.010` rule.

Root cause: the pipeline conflates **"Decode Success"** with
**"Analysis Eligibility"**. They are separable.

## 2 · Decision

Split the two concepts:

```
Decode  ──── success ────► Full Analysis (unchanged)
   │
   └── decode_error
              │
              └── partial_recovery.prefix_text is not empty?
                          ├── YES → Progressive Analysis
                          │            (§2.2 · always partial-labeled)
                          └── NO  → Undetermined (unchanged)
```

### 2.1 Decoder invariants (unchanged)

- Decoder MUST NOT fabricate bytes.
- Decoder MUST NOT stitch reconstruction into `recovered_script`.
- `partial_recovery` remains best-effort and byte-verified.
- ADR-0007 verdict-severity floor is unchanged.

### 2.2 Progressive Analysis contract

When `decode_error` and `partial_recovery.prefix_text` is non-empty AND
readable (≥6 printable-ASCII chars, contains ≥1 alpha), the endpoint:

1. Runs `command_analyzer.extract_iocs(prefix_text)`.
2. Runs `command_analyzer.map_mitre(prefix_text)`.
3. Runs LOLBin detection on tokens of `prefix_text`.
4. Emits a **"Partial Decode"** verdict label (distinct from
   Undetermined, distinct from Suspicious/Malicious) with:
   - `confidence_band` copied from the decoder report (never
     upgraded).
   - `severity_cap = "Suspicious"` — never Malicious from a truncated
     stream alone (behavioral evidence is definitionally incomplete).
5. Every resulting IOC/MITRE/LOLBin evidence item carries:
   - `provenance: "partial_recovery"`
   - `truncation_note: <corruption_offset>, encoding=<enc>`
6. Adds a `cause` classification to the response:
   `truncated | corrupted | wrong_encoding | nested_encoding | unsupported`.

### 2.3 Cause classification (deterministic, no LLM)

Derived from decoder report signals — no guessing:

| Cause             | Trigger                                                                 |
|-------------------|-------------------------------------------------------------------------|
| `truncated`       | `partial_recovery.prefix_text` non-empty AND `first_invalid_offset` > 0 |
| `corrupted`       | `GZIP_HEADER_VALID_BODY_BAD` or `GZIP_SYNTHETIC_HEADER` reason present  |
| `wrong_encoding`  | Bytes decode under UTF-8/ASCII cleanly but NOT UTF-16LE (or inverse)    |
| `nested_encoding` | Multiple decoder layers succeeded and last-layer failed                 |
| `unsupported`     | `BASE64_DECODE_FAIL` and prefix_text is empty                           |

Only ONE cause is emitted (first-match wins in the table order above).

### 2.4 Governance-mandatory labels

The API response — and any downstream CIM Evidence emitted — MUST
carry:

- `verdict_display = "Partial Decode"` (never "Malicious", never
  "Suspicious" masquerading as clean)
- `partial_recovery.confidence_note` (from decoder, unchanged)
- `provenance = "partial_recovery"` on every derived evidence item
- `cause` (one of §2.3)

Without these labels, the analysis MUST NOT run. This is a
correctness-over-recall gate.

## 3 · Scope

**In scope (slice-1, this ADR):**
- Rewire `routers/ops.py:507-594` decode_error branch to invoke
  §2.2 pipeline when `partial_recovery.prefix_text` is present.
- Add `cause` classification.
- Add "Partial Decode" verdict label + ADR-0007-compatible severity
  cap.
- Add pytest: `test_adr0012_progressive_partial_recovery.py` with the
  operator's regsvr32 case + 2 negative controls (empty prefix →
  Undetermined; complete decode → unchanged behavior).

**Out of scope (explicit non-goals for slice-1):**
- ❌ Reversing the "NEVER promoted to `recovered_script`" lock (kept).
- ❌ Reconstructing bytes past the corruption point.
- ❌ Rerouting through the CIM composer (waits on ADR-0011).
- ❌ Applying to non-PowerShell decode paths (slice-2 candidate).
- ❌ UI presentation changes (Track B).

## 4 · Exit criteria

Slice-1 lands green when:

1. `tests/test_adr0012_progressive_partial_recovery.py` all-pass.
2. Full pytest suite: net-zero-new failures vs baseline
   (`test_adr0007_*.py`, `test_adr0008_*.py`, `test_adr0009_*.py`
   remain green).
3. Operator's regsvr32 payload, when POSTed to `/api/decode/smart`,
   returns:
   - `verdict_display == "Partial Decode"`
   - IOCs include the recovered URL prefix (`http` / `192.168.48.129`
     iff present in prefix)
   - MITRE includes T1218.010
   - LOLBin includes `regsvr32`
   - `cause == "truncated"`
4. Complete-decode Corpus v1 cases: unchanged verdict labels
   (regression guard).

## 5 · Non-decisions (deliberately parked)

- ADR-0011 engine unification remains **Proposed · planning-only**.
  Slice-1 of ADR-0012 does NOT flow through the CIM composer yet;
  it lives in the endpoint layer. When ADR-0011 lands, the
  progressive-analysis outputs will be moved into
  `nivxforge/cim/compose.py` as `evidence.class = structural` with
  `provenance = partial_recovery`.
- Extending progressive recovery to other decoder families (gzip
  body corruption, wrong-encoding blobs) is deferred to slice-2.

## 6 · Risks & mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Progressive analysis emits a Malicious verdict from a partial URL | High if uncapped | High | §2.2 hard cap: severity ≤ Suspicious; verdict label is "Partial Decode" (distinct from Malicious) |
| Analyst mistakes the recovered prefix for the full command | Med | Med | Every response carries `partial_recovery.confidence_note` + `cause` + `truncation_note` on every evidence item |
| A future decoder change makes `partial_recovery.prefix_text` unreliable | Low | Med | pytest pins the field's contract; any change to `_annotate_confidence_and_partial` runs against the ADR-0012 pytest gate |
| Slice-1 forks the reasoning layer that ADR-0011 wants to unify | Low | Low | §5 explicitly plans the migration; the endpoint-layer wiring in slice-1 is 20-30 lines and trivially removable |

## 7 · Registry impact

`CAPABILITY_REGISTRY.md` gains:

| Capability | ADR | Status | Evidence | Corpus | Regression | Component |
|---|---|---|---|---|---|---|
| Progressive Partial Recovery (PowerShell decode_error) | ADR-0012 | **Accepted · slice-1** (2026-02-28) | operator regsvr32 case | v1 + 3 new fixtures | `tests/test_adr0012_progressive_partial_recovery.py` | `routers/ops.py` decode_error branch |
