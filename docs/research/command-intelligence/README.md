# Automatic Command Intelligence — implementation and validation

Date: 2026-10-12. Release status: **NO-GO for production; isolated review candidate**.

Repository: `jpreddy017/nivxray-xdr`.
Branch: `engineering/xdr-command-auto-intelligence`.
Base: RC2 `d9b3cd6c99580df407c5147c49b9b5753338bef7`.
PRs 7–10 and existing branches were inspected before choosing this base. PR #10
and its source branch are not changed or merged. No product migration, manual
deployment, production data, DNS, secrets or security HOLD changes.

## Reproduced root causes

The actual path was `/xdr/intelligence/command` → `XdrCommandIntelPage.jsx` →
shared authenticated Axios client → `POST /api/analyze/command` →
`command_analyzer.analyze_command`. This is a legacy semantic analyser, not the
Universal Decoder engine entry point. The UI trimmed evidence, requested manual
span selection, and rendered the response as JSON.

Observed on unchanged RC2:

| Synthetic sample | Before | Automatic mode after |
|---|---|---|
| PowerShell `-enc` with UTF-16LE `Write-Output "hello"` | Correctly recovered in legacy analyser | Recovered; extraction, Base64 and UTF-16LE are separate evidence layers |
| `VjNKcGRHVXRUM1YwY0hWMElDSm9aV3hzYnlJPQ==` | `NOT_REQUIRED`; no canonical artifact | `Write-Output "hello"` via Base64 → UTF-8 → Base64 → UTF-8 |
| Two literal `FromBase64String` calls with different commands | `AMBIGUOUS`, `needs_choice=true`; neither decoded | Both recovered automatically; ambiguity retained, no single canonical promotion |
| `('Write-' + ('Out' + 'put'))` | Not used as a claimed baseline failure | Static literal `'Write-Output'`; nested expression folding |
| Base64 containing gzip of a script | Older paths include unbounded inflate | Bounded Base64 → gzip → UTF-8 with an explicit limit/integrity result |

The legacy analyser gates on 0.80 confidence, asks for a choice when two spans
are within 0.05, ignores nested payloads shorter than 32 characters, and has a
three-pass nested-span limit. The Universal Decoder already contained CMD/PS
reconstruction, Plane-A codecs and a signature-driven DDO, but its `decode()`
entry was not a complete general codec exploration path. There is no evidence
here that every production failure has the same cause: the user's original
failing input and a production trace were not supplied.

## Source research and reference comparisons

Primary sources reviewed:

- [CyberChef Magic library](https://github.com/gchq/CyberChef/blob/master/src/core/lib/Magic.mjs)
- [CyberChef Magic operation](https://github.com/gchq/CyberChef/blob/master/src/core/operations/Magic.mjs)
- [MinusOne](https://github.com/airbus-cert/minusone), source checkout
  `48d85ed29a293359c5a990569de70561dd2c312c`, especially PowerShell string,
  cast, encoding rules and their tests.
- [PowerPeeler](https://github.com/zhengbili/PowerPeeler) and its
  [research paper](https://arxiv.org/abs/2406.04027): dynamic instruction-level
  recovery is outside the no-execution contract. It was not run.

Magic selects operations using input patterns and entropy ranges. It runs
matching operations recursively, checks output criteria, retains recipes,
prunes unhelpful branches, and ranks using language statistics, UTF-8 validity,
file identification, useful-operation flags, recipe length and entropy.
Intensive mode adds brute-force branches. Those heuristics are useful for
exploration, but do not establish which command executed or prove benignness.

NivXRay uses bounded, signature-supported alternatives, strict byte codecs,
explicit command framing and reproducible hashes. Ranking is a documented
heuristic, not a probability or verdict. No external runtime is added to the
product, and no upstream source is copied into production modules.

| Capability | CyberChef Magic | This candidate |
|---|---|---|
| Recursive detection and recipes | Broad operation registry | Narrow bounded registry in Universal Decoder |
| Ranking | Statistical language/entropy/file heuristics | Framing, readable text, command tokens, unresolved penalties, stable tie ordering |
| Embedded command payloads | General data transforms | Explicit PS EncodedCommand/FromBase64String and cautious literal candidates |
| PowerShell expressions | General transformations | Literal-only concatenation, nested parentheses, char codes, whole-expression format/join |
| Arbitrary PowerShell dataflow | Not a full PS evaluator | Deliberately unresolved; MinusOne is broader |
| Compression | Many formats | gzip/zlib only in this mode; streaming size/ratio limits |
| Encryption | Key-based operations and optional brute force | No encryption recovery claim; unknown/key-dependent material stays unresolved |
| Canonical security evidence | Not this tool's purpose | Parent hashes, exact layers, partial/ambiguous promotion guard |

Executed reference comparisons:

1. **CyberChef npm 11.5.0**, tarball SHA-1
   `38a00e80c64195d6bccd65b02d4df90075ff7052`. Its full Node export failed
   on upstream dependency/module loading (`crypto-api` extensions and missing
   `terser`). A research-only harness ran the **unchanged actual Magic detection,
   recursive exploration and ranking**, with six upstream codec classes:
   From Base64, From Hex, Gunzip, Zlib Inflate, Decode text, URL Decode.
   Only the recipe dispatch adapter was replaced to avoid importing unrelated
   operations. Depth 5, no intensive mode. **This is a restricted-registry
   comparison, not a full CyberChef parity benchmark.** Recorded results are in
   `cyberchef-11.5.0-restricted-results.json`.
2. **pyminusone 0.4.1** ran six harmless literal-expression fixtures.
   Five supported cases recover equivalent strings in both engines (quote style
   differs); variable interpolation resolves in MinusOne and remains unresolved
   in NivXRay. Results are in `minusone-0.4.1-results.json`. The inspected source
   checkout is newer than this executed wheel; their versions are distinguished.

The restricted Magic run recovers standalone and nested Base64 and hex. Its
gzip result includes the plaintext but ranks the recognized compressed file
above it. In this restricted non-intensive configuration it leaves the UTF-16
and whole PowerShell-wrapper fixtures unchanged. Do not generalize those last
two observations to every Magic configuration. NivXRay recovers those supported
fixtures using explicit byte encodings and command framing.

The research-only `magic_reference.mjs` adapter is included for reproduction.
Extract npm `cyberchef@11.5.0` outside the application, install its dependencies
with scripts disabled, then set `CYBERCHEF_ROOT` to that extraction and run the
adapter with Node 24. The application never imports or installs CyberChef.

Run the recorded comparisons locally:

```sh
PYTHONPATH=backend python docs/research/command-intelligence/compare_references.py
```

## Implementation and reuse

- Existing `UniversalDecoderEngine` gains `analyze_automatic`; legacy `decode`
  and callers keep their behavior. Candidate traversal lives under the same
  `services/decoder` owner, not a separate product.
- Existing Base64/compression modules gain strict candidate decoding and bounded
  inflate functions. Existing encoding registry, PS char/concatenation/format/join
  folds, CMD wrapper/caret handling, IOC rules and provenance types are reused.
- Existing `/api/analyze/command` accepts opt-in `automatic:true`; legacy requests
  retain their contract. Authentication is the same `get_current_user` dependency.
- A spawned worker provides actual termination on timeout, plus concurrency
  rejection. A timed-out thread alone would not stop decoding.
- The existing page sends exact input and displays status, candidates, a layer
  timeline, intermediate text/binary evidence, recipes, observations, IOCs,
  limits and unresolved reasons. It rejects incompatible old-backend responses
  visibly rather than silently falling back.
- Browser cancellation/generation checks complement the existing secure Axios
  transport. Tenant changes clear input/results; stale responses cannot reappear.
- ATT&CK results stay empty and marked HELD. No observations are written.

Recipe replay is available as `services.decoder.automatic.replay_recipe`.
It validates source/output hashes and operation arguments against supported
transitions. Recipes and ranking are deterministic; provenance timestamps
record the analysis time and are intentionally not byte-identical between runs.

## Resource and evidence guarantees

| Control | Limit |
|---|---|
| Original input | 16 KiB UTF-8 |
| Per decoded artifact | 128 KiB |
| Cumulative generated bytes | 1 MiB |
| Candidate nodes / returned candidates | 64 / 12 |
| Depth | 12 transformations |
| Cooperative search / killable worker | 2 seconds / 4 seconds |
| Concurrent workers | 2 per API process; excess receives 503 |
| Decompression | 128× expansion, 1 KiB floor, 128 KiB absolute cap |

No scripts, interpreters, embedded commands or external endpoints are executed
by the decoder. Binary evidence is explicitly represented as Base64, not passed
off as a decoded script. Truncated compression is partial; CRC failure does not
promote output. Trailing/concatenated compression streams are unresolved.
A hash-shaped hexadecimal string stays a speculative candidate. UTF-16 without
BOM/zero-byte structure is not promoted on printability alone. Multiple plausible
payloads remain separate. A recovered embedded payload does not establish that
its surrounding dynamic wrapper was resolved.

The API is stateless pasted-input analysis. It does not fetch tenant evidence,
store artifacts or change tenant authorization. Existing JWT lookup is the only
DB interaction in this route. This is not a new tenant-isolation certification.

## Validation

- **279 backend tests passed:** 46 new decoder tests, 7 new authenticated API/worker
  tests, existing command/honesty/DDO tests, and RC1-P1/RC2 scope/RBAC regressions.
  Pytest uses the repository configuration with its documented `-n 0` serial
  override. No assertions weakened; no lint/test suppression.
- **113 focused backend tests also passed in a clean virtual environment** using
  the dedicated CI requirements, including the application-pinned FastAPI/Pydantic
  versions. One upstream dependency deprecation warning remains.
- **122 frontend tests passed:** 117 baseline plus 5 new page/contract tests.
- **XDR production build and EDR-scope build passed.** 13 existing shared
  security/transport tests passed independently. These are console boundaries,
  not EDR sensor/agent acceptance.
- PR #10's existing ownership manifest was checked against this checkout without
  moving/changing its branch, scripts or configurations. Mapped source paths exist.
- **Local Chromium integration passed:** actual page → existing Axios client →
  real FastAPI route/JWT validation → spawned decoder → rendered output. Covers
  exact whitespace, expandable recipe, mobile width, tenant-change cancellation,
  503 messaging and 401 credential clearing.
- The browser fixture supplies an isolated synthetic auth-record store and a
  simple shell with the real theme. It does **not** certify the complete console,
  live Mongo, deployed route guards or Administrator/MSSP staging sessions.
- Real local desktop/mobile screenshots are adjacent to this report. They are
  fixture screenshots, not production or protected-preview acceptance.
- A dedicated read-only GitHub workflow is included. Hosted CI status is reported
  separately in the PR; this document does not assume it has passed.

## Known limitations and production blockers

1. Independent security/code review and approved deployed frontend/backend
   acceptance remain mandatory; RC2 and EDR HOLDs remain unchanged.
2. Deploy backend support before this frontend. An older backend may ignore the
   new request field, but the UI rejects the missing response schema explicitly.
   Rollback is reverting this isolated change; there is no schema/data migration.
3. Dynamic variables, environment-dependent CMD expansion, arbitrary PS loops,
   member invocation, string interpolation, broad JavaScript/VBScript semantics,
   XOR/cryptographic recovery, raw Deflate without trustworthy framing, ZIP/LZMA
   and full AST/dataflow recovery are not implemented by this automatic mode.
4. IOC extraction is inherited lexical detection, not reputation or execution
   proof. Behavioral explanations describe observed tokens with evidence IDs.
   No external OSINT calls occur.
5. Existing legacy decoding endpoints still contain their prior unbounded codec
   paths. This change hardens the new automatic path; it does not claim to fix
   all shared decoder resource risks or replace legacy release gates.
6. Worker memory/CPU under multi-process deployment needs staging load validation.
   Per-process concurrency is bounded; global rate limits remain an infrastructure
   concern. No new infrastructure or production settings were changed.
7. Full CyberChef operation parity was not tested and is not claimed. The registry
   restriction and upstream distribution issue are recorded above.
8. The exact original production failure sample is still needed to confirm its
   complete recovery; synthetic reproductions establish the reported defects.

**Stop before merge/deploy.** Review this candidate against RC2; do not merge PR
#10 or other security/release candidates as a side effect.
