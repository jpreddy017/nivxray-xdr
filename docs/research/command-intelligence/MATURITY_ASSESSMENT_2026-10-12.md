# Command Intelligence static maturity upgrade

Starting commit: `e75f163e6c7640c34a07985024369ce086f035ea`.
Branch: `engineering/xdr-command-static-maturity`.
Separate stacked draft PR targets PR #11's engineering branch; PR #11 remains HOLD/draft. The final GitHub SHA and hosted CI result are recorded in that PR after publication.

**Release: NO-GO. Engineering maturity self-assessment: 78/100.** The requested 80 target is not declared achieved. This rubric is local planning evidence, not an industry benchmark, third-party certification or production approval. The prior estimated 65 had no common rubric; it cannot be compared numerically as if measured.

## Reuse and implementation

Reuse: Universal Decoder's candidate queue, byte codecs, gzip/zlib bounded inflate, source/hash layers, ranking, exact original preservation, recipe replay, canonical guard, IOC extraction and authenticated API; CI-09 resource protections; existing V2 PowerShell tokenizer; existing UI timeline, candidates, recipes and warnings. Existing RC5/V2/AST-lite evaluators were inspected rather than replaced. Their wider permissive materialization is not automatically authorized as canonical evidence.

New production files:

- `backend/services/decoder/powershell_constants.py`: restricted typed constant-expression AST using the existing tokenizer with complete token-coverage checks. Supports string-only concatenation, bounded integer arithmetic/bitwise operators, char/byte arrays, joins, index-only string formatting, straight-line known variables and pure finite ForEach-Object maps. Strict Base64 plus explicit UTF8/Unicode/BigEndianUnicode/ASCII GetString chains are supported. Original assignments remain in place; no branch/environment/scope is guessed.
- `backend/services/decoder/cmd_constants.py`: one explicit `/v:on` literal SET→ECHO delayed-expansion template. Percent expansion, unsafe values and unsupported command grammar remain unresolved.
- `backend/services/decoder/command_behaviors.py`: typed syntax observations for retrieval, expression evaluation, process launch, scheduled-task creation, autorun writes, process dumping, monitoring changes and injection-related API chains. Strings, variables and comments are masked with the existing lossless tokenizer. Compound findings cite supporting spans; none proves execution, malicious intent or credential access.

Integration: `automatic.py` adds replayable constant-AST and CMD transitions, post-order operator descriptions, expression offsets/replacement hashes and scope-aware ranking. A complete whole-input candidate can outrank an unresolved embedded shortcut; multiple independent embedded payloads remain ambiguous. CMD context does not suppress PowerShell reconstruction after an explicit EncodedCommand boundary. Plain supported literals are not rewritten cosmetically.

`XdrCommandIntelPage.jsx` displays behavior kind, observed/correlated syntax basis and exact character offsets using the existing evidence panel. Existing `/command-intelligence/1` fields and success contracts remain; behavior metadata is additive. ATT&CK remains empty/HELD. Backend and frontend code do not evaluate scripts, invoke shells, fetch extracted URLs or call an AI model.

Test/measurement changes: `test_command_maturity.py`, `fixtures/command_maturity/corpus.py`, `maturity_benchmark.py`, CommandIntelligence UI test, actual loopback browser harness and the dedicated non-deploying workflow. Research decisions are in `MATURITY_RESEARCH_2026-10-12.md`; no third-party source was copied and no runtime dependency added.

## Same-corpus measurement

The 43 harmless fixtures contain literal output oracles and encodings generated from known text. The same final corpus/evaluator ran against an isolated baseline checkout and this candidate. Previously available reference fixtures were reviewed; no previously supplied complex sample with an authoritative expected output was substituted with invented content.

| Measure | Baseline | Candidate |
| --- | --- | --- |
| Full recovery + exact canonical payload | 9/22 | **22/22** |
| Correct partial artifact with no canonical promotion | 2/2 | **2/2** |
| Unsupported/malformed/encrypted/unsafe cases refuse promotion | 12/12 | **12/12** |
| Plain/benign cases preserve non-promotion | 7/7 | **7/7** |
| Overall recovery/promotion-policy checks | 30/43 | **43/43** |
| Targeted typed behavior checks | 0/7 | **7/7** |
| Reproducible candidate recipes | 43/43 | **43/43** |
| Incorrect canonical promotion observed in this corpus | 0 | **0** |

The behavior baseline lacked the new typed rule contract and included risky token hits inside displayed text; 0/7 does not mean it had no behavioral functionality. The new checks cover six positive findings and one quoted-text negative case. They are small synthetic coverage, not a malware corpus accuracy rate. Refusal correctness means no canonical promotion; some unsupported samples still produce clearly marked partial alternatives.

Recorded direct-analysis latency (single process, imports included, not a service load test): baseline median 0.102 ms / p95 0.403 ms / maximum 15.376 ms; candidate median 0.301 ms / p95 0.718 ms / maximum 110.985 ms. Peak process RSS: baseline 16,256 KiB; candidate 26,220 KiB. Cold imports dominate the maxima. Raw `MATURITY_BEFORE.json` and `MATURITY_AFTER.json` are authoritative; host/load variation prevents extrapolation to deployment latency or worker memory.

Additional generated holdout-style oracles: 20 fixed random seeds × XOR/add/subtract = **60 exact reconstruction/replay comparisons**, represented by 20 parametrized tests. Independent string generation and known encoding arithmetic supply the expected values. No PowerShell or CMD execution is used to derive them. Supported-semantics coverage remains narrower than a native grammar differential benchmark.

Before/after examples:

| Input | Baseline | Candidate |
| --- | --- | --- |
| `Write-Output (-join [char[]](104,101,108,108,111))` | UNRECOVERED | `Write-Output 'hello'`, canonical |
| `$a='he'; $b='llo'; Write-Output ($a+$b)` | UNRECOVERED | `$a='he'; $b='llo'; Write-Output 'hello'`, assignments retained |
| `Write-Output (-join (111,98,107,107,104 \| ForEach-Object {[char]($_ -bxor 7)}))` | UNRECOVERED | `Write-Output 'hello'`, canonical |
| `cmd /c powershell -enc <known UTF-16LE fixture>` | Correct child, partial wrapper path ranked first | Complete CMD peel → EncodedCommand → Base64 → UTF-16LE candidate ranked first |
| `Write-Output 'IEX DownloadString VirtualAlloc schtasks'` | Risky token annotations in quoted data | Output syntax only; no risk chain |

## Verification and security

- Clean pinned dedicated gate: **262 passed** (176 baseline focused/archive/security tests + 86 new maturity tests). All 30 CI-09 tests pass, including optional codec bombs, malformed streams, detection limits, cumulative budgets, shared admission, worker timeout/descendant cleanup and lifespan isolation.
- New symbolic guards: 16 KiB source, 2,048 tokens, 1,024 AST nodes, depth 16, 512 items, 32 statements, 16,384 evaluation steps and 128 KiB output. Joins, concatenation, format replacement, literal rendering and program output check expansion before allocation. Unknown tokens, unterminated/escaped-quote grammar, automatic/scoped variables, coercion, side-effecting map bodies, unknown keys, control flow and out-of-range integers are refused.
- Fresh CI-09 harmless probe: legacy oversized input 413, automatic 422, gzip bomb refusal, worker timeout 504 and no delayed completion marker. No legacy resource-protection file was changed.
- Broader backend run: **492 passed, 3 failed**, followed by the two additional automatic-variable guard tests in the final clean gate. Same three RC22 failures reproduced at e75f163e before coding: UTF-16 legacy trace ID, char-array marker and IOC bundle. They are not repaired, waived or hidden by this track.
- Frontend **123 passed**. XDR and EDR-scoped isolated builds pass. A first XDR build encountered an output-directory ENOTEMPTY condition; rerunning to a separate scratch output succeeded. No build/security setting was weakened.
- Workspace **25 Node + 14 Jest passed**; broader backend includes Workspace convergence/certification, canonical plumbing and adapter tests. PR #10 changes were not copied or modified.
- Actual local page→Axios→JWT-validated FastAPI→spawned worker→DOM: **18 harmless cases passed**, including six added maturity cases. Every layer/input/output/recipe/hash/IOC/limitation is checked against the real API response; new behavior labels and offsets render. Mobile width, inert evidence text, tenant cancellation, busy and unauthorized responses pass.
- Ownership manifest check and `git diff --check` pass. This is local synthetic auth acceptance, not deployed Mongo/MSSP or production authorization certification.

## Evidence-backed planning rubric

| Dimension / weight | Supported score | Evidence and deductions |
| --- | --- | --- |
| Encoding/compression / 10 | 10 | Same six generated multilayer/encoding cases plus existing codec regressions; no broad format-parity claim |
| PowerShell static semantics / 15 | 12 | Character arrays, variables, formatting, strict encoding calls; no native grammar differential validation, interpolation/functions/branches |
| Custom decoder recognition / 10 | 8 | Pure bounded XOR/arithmetic maps and 60 generated checks; arbitrary loops, rotating keys and advanced arithmetic remain unsupported |
| Evidence/provenance / 15 | 15 | Exact original, 43 replay checks, canonical/refusal checks, hashes and source spans; confidence remains recovery-only |
| Behavioral interpretation / 10 | 8 | Seven targeted positives/negative checks and quoted/comment regressions; no deep cross-statement dataflow or contextual intent proof |
| Resource security / 15 | 13 | CI-09 30 tests + symbolic adversarial guards; host-wide process/memory sizing and new-code external review still pending |
| Local integration/UX / 10 | 9 | 18 actual browser/API cases and 123 frontend checks; fixture shell is not deployed full console |
| Broad regression health / 5 | 3 | 492 pass, three reproduced baseline failures unresolved |
| Deployed acceptance / 10 | 0 | Authorized isolated staging unavailable; previous access 403 |
| **Total / 100** | **78** | Conservative manual engineering rubric, not an independently validated maturity benchmark |

This rubric explains the assessment but is not a promise of objective industry standing. Do not round 78 up to 80. The 43-case correctness result is objective; a general maturity score remains a documented judgment. Resolve the known regression gate and obtain authorized deployment/runtime acceptance rather than adding speculative features to inflate points.

## Remaining gates and limitations

Authorized isolated staging acceptance remains BLOCKED; PR #11 and production stay HOLD. Validate the full console Analyse action, tenant/MSSP/Mongo contracts, Base64→UTF-16LE→GZIP chain, target-host CPU/RSS/process multiplication and supported optional tooling. Require owner approval for release. No merge/deployment, production database/configuration, secrets, DNS, RC2, EDR candidate or PR #10 modification occurred.

The constant grammar intentionally excludes interpolated strings, methods beyond the tiny encoding whitelist, mixed quote formatting, culture-sensitive conversion, regex replacement, mutable arrays/indexing, arbitrary for/while loops, rotating XOR keys, external variables, script-host execution and crypto without keys. Binary/encrypted/unsupported material remains partial or unresolved. Capability observations do not establish maliciousness, successful execution, injection or credential theft. No new ATT&CK authorization is granted.
