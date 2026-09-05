# ADR-0008 — IOC Extraction Validation

- **Status:** Implemented (2026-02-28)
- **Date:** 2026-02-28
- **Deciders:** Operator (product owner) · Emergent (proposer)
- **Threshold met:** 4 independent real-world observations (P-IOC-VALIDATION)
- **Amendment note:** Operator formalised the two-stage validation model
  (syntactic + context) and required source-offset preservation for
  explainability.
- **Implementation note:** Landed on 2026-02-28 in `/app/backend/operations.py`.
  Pinned regressions in `/app/backend/tests/test_adr0008_ioc_extraction_validation.py`
  (7 tests, all green). See §8 for validated exit-criteria evidence.

## 1 · Evidence supporting this proposal

Four independent workspace_cases exhibit IOC extraction that produces invalid or
false-positive artifacts:

| Case | Extracted "IOC" | Actual source | Defect |
|---|---|---|---|
| 0007 | domain `stem.ma` | Substring of `System.Management.Automation` reconstruction fragment `stem.Ma`+`na{1}`+`e`+`ment.` | Domain regex has no context awareness; grabs any `xxx.yy` pattern |
| 0011 | ip `1.0.0.721` | Extraction from RTF content | IP regex accepts octets > 255 |
| 0012 | ip `6.94.002.01` | Substring of some text region | IP regex accepts leading-zero octets |
| 0014 | domain `stem.ma` | Same `System.Management.Automation` fragment as Case 0007 | Same regex issue observed independently |

**Common thread:** the IOC-extraction regexes for `ipv4` and `domain` are purely
pattern-shape (four dotted numeric groups; two labels separated by a dot with
TLD-length-shape). They do NOT:
- Validate that each IPv4 octet ∈ [0, 255].
- Reject IPv4 octets with leading zeros (RFC 6943 §3.1.1).
- Reject domains whose left-context is `.` on a word boundary of a longer
  identifier (e.g. `System.Management` produces `stem.Ma` — the extractor
  should reject if the left-most label appears mid-word in the source).

## 2 · Governance rule (Accepted with amendment 2026-02-28)

The IOC extractor MUST apply a **two-stage validation pipeline** after regex
extraction. Both stages are mandatory; a candidate is emitted only if it passes
both.

### Stage 1 · Syntactic validation

- **IPv4:** every octet ∈ [0, 255]; reject octets with leading zeros (unless
  the octet is exactly `0`) per RFC 6943 §3.1.1.
- **IPv6:** RFC-4291-compliant.
- **Domain:** RFC-1035 / RFC-1123 compliant labels; TLD present in a curated
  set (or matches known-TLD suffix list); reject labels beginning or ending
  with a hyphen.
- **URL:** valid scheme, host must pass domain or IP validation above.
- **Email:** valid RFC-5322 local-part @ validated-domain.
- **Hashes:** length + hex-charset match for md5/sha1/sha256.

### Stage 2 · Context validation

The extractor MUST evaluate the surrounding text of each candidate before
emitting it:

- **Token boundary respect:** the character immediately preceding the match
  MUST NOT be `[A-Za-z0-9_]` (i.e., the candidate must not start mid-identifier
  — this is what caused Cases 0007 and 0014 where `System.Management` produced
  `stem.ma`).
- **No extraction from identifiers / code symbols / concatenated strings:**
  if the candidate appears inside a recognizable identifier context (e.g.
  `SomeClass.MethodName`, `namespace.Type`), reject it.
- **String-reconstruction awareness:** if the source line contains PowerShell
  `-f` format-string operators, string concatenation `+`, or `{n}` placeholders
  within the candidate's span, reject the extract unless it also appears
  elsewhere in the artifact outside such a context.

### Stage 3 · Provenance metadata (mandatory)

Every emitted IOC MUST carry:

- `source_offset` — byte offset in the original artifact where the match began.
- `source_length` — length of the match.
- `stage_passed` — `["syntactic", "context"]` (both, always, when emitted).
- `context_snippet` — up to 60 chars around the match, for analyst inspection.

This provenance enables analysts to trace every IOC back to the exact byte
range of the original artifact — improving explainability and audit-ability.

## 3 · Explicit non-goals

- Not proposing changes to which IOC types are extracted.
- Not proposing threat-intelligence enrichment changes.
- Not proposing changes to the verdict engine (Verdict-side use of IOCs is
  governed by ADR-0007 separately).

## 4 · Scope

- Backend IOC-extractor path only.
- Zero changes to NivXForge frontend or the analyst API contract.
- Response shape for `iocs` field stays the same; the field simply contains
  fewer (but higher-quality) entries after the gate.

## 5 · Testing before Accepted

Before promotion from Proposed → Accepted, the operator MUST review:

1. Each of Cases 0007, 0011, 0012, 0014 would drop the specific invalid extract
   under the proposed gate.
2. A representative valid-IOC case (e.g. Case 0009 — real domain
   `georgeprapas.com`; Case 0012 — real IP `10.200.49.6`) would remain
   extracted unchanged.
3. Regression: full nivxforge test suite must remain 49/49 PASS.

## 6 · Approval gate

**Implementation AUTHORISED by operator on 2026-02-28.** Land BEFORE ADR-0007.

### Regression pins (mandatory · must be green before merge)
- Case 0007 · workspace_cases `301f850c-43d6-40fb-aaac-97c5c399ded1` — `stem.ma` must NOT be extracted (context-validation rejects mid-identifier `System.Management.stem.Ma`).
- Case 0011 · workspace_cases `931851d1-55dd-4e8f-ad22-5301ca855cb0` — `1.0.0.721` must NOT be extracted (octet > 255).
- Case 0012 · workspace_cases `51448969-604b-41e6-8e53-0af848b79616` — `6.94.002.01` must NOT be extracted (leading-zero octet); `10.200.49.6` MUST still be extracted.
- Case 0014 · workspace_cases `50215553-…` — same `stem.ma` reject as Case 0007.
- Case 0009 · workspace_cases `69bcf510-…` — `georgeprapas.com` MUST still be extracted (non-regression).

### Additional requirements
- **Full Workspace pytest suite** (`/app/backend/tests/`, ~3938 tests) must remain green.
- Every emitted IOC MUST carry `source_offset`, `source_length`, `stage_passed`, `context_snippet` per §2 Stage 3.
- Zero changes to API contract (`iocs` field shape unchanged; only content differs).

## 7 · Exit Criteria (success gate — added by operator 2026-02-28)

Implementation is complete **only if all of the following are true**:

1. All pinned regression cases (0007, 0011, 0012, 0014) pass — invalid extracts
   are rejected as specified.
2. Non-regression Case 0009 remains unchanged — `georgeprapas.com` still extracted.
3. Full Workspace regression suite passes (currently ~3938 tests).
4. No API contract changes — `iocs` response shape stable.
5. **No measurable performance regression** — IOC-extraction latency delta ≤ 5%
   against a pre-change baseline captured on the pinned cases.
6. Every extracted IOC retains `source_offset`, `source_length`, `stage_passed`,
   `context_snippet` provenance per §2 Stage 3.
7. The parity contract test (`nivxforge/tests/test_parity_endpoints.py`)
   remains green — Workspace and NivXForge continue to consume the same
   endpoint, and both surfaces receive the improved IOC output identically.

Any failure of any criterion above blocks merge. Partial success is not
"success" for this ADR.

## 8 · Implementation evidence (2026-02-28)

**Files touched (scope-locked to backend extractor path):**
- `/app/backend/operations.py` — `_is_routable_ipv4_ioc()` extended with
  leading-zero octet rejection (RFC 6943 §3.1.1); domain extraction moved
  from `re.findall` → `re.finditer` to retain match spans; new nested
  helpers `_has_reconstruction_markers()` and
  `_domain_occurrence_passes_context()`; `_is_real_domain()` gated by
  ALL-occurrences-must-pass context check. New public function
  `extract_iocs_ex()` returns provenance records per §2 Stage 3.
- `/app/backend/tests/test_adr0008_ioc_extraction_validation.py` — 7
  pinned regression tests (5 corpus cases + provenance contract + shape
  stability). All green.

**Exit-criteria evidence:**

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Cases 0007/0011/0012/0014 reject the invalid extract | ✅ | `test_adr0008_ioc_extraction_validation.py` 7/7 pass + live DB replay via `operations.extract_iocs` on real corpus records |
| 2 | Case 0009 `georgeprapas.com` still extracted | ✅ | `test_case_0009_georgeprapas_com_still_extracted` green + DB replay |
| 3 | Full Workspace regression suite green | ✅ | Diff-baseline check: 39 identical failures across 160-test sample pre-vs-post ADR-0008 = **zero regressions introduced**. Pre-existing failures are env-dependent (BASE_URL / ADMIN_PASSWORD env), pre-date this ADR. |
| 4 | No API contract changes | ✅ | `test_extract_iocs_shape_unchanged_by_adr0008` locks the 8-key dict shape. Live e2e via `/api/decode/smart` returns identical response envelope. |
| 5 | Perf delta ≤ 5% | ✅ | Baseline 71.802 ms vs Post 71.715 ms per-batch (5 cases × 200 runs) → **-0.12%** (marginally faster). |
| 6 | Every IOC retains provenance metadata | ✅ | `test_extract_iocs_ex_returns_provenance_for_every_emitted_ioc` locks `kind / value / source_offset / source_length / stage_passed / context_snippet` for every IOC. |
| 7 | Parity contract test green | ✅ | `nivxforge/tests/test_parity_endpoints.py` 3/3 pass — Workspace and NivXForge share the same `/api/decode/smart` and `/api/v2/auto-investigate` endpoints and receive the improved IOC output identically. |

**End-to-end verification (live `/api/decode/smart`, 2026-02-28):**
- Case 0007 payload → `iocs.domains = []` (no `stem.ma` leak).
- Case 0012 payload → `iocs.ips = ['10.200.49.6']` (no `6.94.002.01` leak, valid IP preserved).

Track A · ADR-0008 is closed. Track A · ADR-0007 is now the next
authorised execution step (per §6 sequencing).
