# Staging contract failure investigation — 2026-10-12

Release: **NO-GO**. Reviewed baseline: `d3327a8d93a4bbb8a4a553588edfd09e2fafeb10` (draft PR #13). Isolated repair branch: `engineering/xdr-command-contract-investigation`. PRs #11–#13, PR #10, RC2 and EDR candidates are untouched. No production POST, deployment, merge, database/configuration/DNS/credential change or HOLD removal occurred.

## Root cause and deployed revision mapping

| Surface | Established evidence | Remaining uncertainty |
| --- | --- | --- |
| Preview `dpl_72i1GFUuNFiV75T9BWBDiDnufzYB` | Fresh read-only deployment metadata: project `nivxray-xdr`, READY, branch `engineering/xdr-command-review-gates`, Git SHA `d3327a8d93a4bbb8a4a553588edfd09e2fafeb10` | Backend SHA is independent of this frontend deployment |
| Observed backend `https://nivxray.nivxforge.com/api/analyze/command` | Owner-observed HTTP 200 legacy-style report; fresh public GET `/api/openapi.json` advertises `CommandAnalyzeIn` with only `input` and `force_decode_span`, no `automatic` property | Exact backend Git SHA and infrastructure route/process cannot be established from generic API version `1.0.0-rc`; no claim that it is a specific historical commit |
| Reviewed backend | `backend/schemas.py:72–78` defines `automatic: bool = False`; `backend/routers/ops.py:556–575` dispatches `automatic=true` to isolated automatic worker and preserves legacy mode otherwise | This source contract is not the advertised live contract |
| Preview API origin | Saved owner deployment metadata specifies `bash scripts/vercel-build.sh`; that script line32 defaults `XDR_PROD_API_ORIGIN` to the observed live origin and lines60–65 overrides `REACT_APP_NIVXRAY_API_URL` for the build | No private environment values or protected bundle were read. The owner-observed request destination matches the script default; a default alone does not prove an actual environment value |

This is a **confirmed contract incompatibility / frontend-backend version alignment gate failure**, not a frontend validation bug. An old model using Pydantic's normal extra-field handling can ignore the new automatic flag; the missing advertised property plus the observed legacy response supports that explanation, but the original authenticated wire request and deployed process source have not been captured here. A reviewed backend also legitimately returns the legacy shape when automatic is omitted, so response shape alone does not identify a backend commit.

Fresh metadata retrieval succeeded; the earlier Vercel control-plane403 is no longer the primary diagnosis for this deployment. This task's cloud browser still encountered Vercel's ordinary login wall. No login troubleshooting, session copying, bypass link or protection changes were attempted. The owner's observed failure and fresh public API schema are sufficient to diagnose the contract gate; they are not a successful deployed acceptance run.

## Exact frontend contract / path

`apps/nivxray-xdr/src/xdr/pages/commandIntelligenceContract.js:1–19` sends `{input, automatic:true}` preserving exact evidence. It requires schema `command-intelligence/1`, exact echoed original, string decode status/reason, canonical evidence object, final recoverable `{format:'text'|'base64',value:string}`, array candidates/methods/warnings/behaviors/IOCs/unresolved portions and valid candidate layers/recipes. A legacy object is rejected even at HTTP200 or when a zero-step candidate contains text.

`XdrCommandIntelPage.jsx:80–99` clears old results, sends the request through existing authenticated/tenant-bound Axios, accepts only validated responses and fences late responses by request generation/tenant. `apps/nivxray-xdr/src/lib/api.js:15–16` appends `/api` to the build-time public origin. `vite.config.js:31–32` maps `REACT_APP_NIVXRAY_API_URL` then `REACT_APP_BACKEND_URL`. The production-oriented script overrides that normal mapping. No origin/build/production configuration was changed in this repair.

## Separate legacy correctness findings and isolated minimal repair

Input: `powershell -NoProfile -Command "Write-Output 'NivXRay-Test-123'"`.

1. **Incorrect FAILED status.** Baseline `_find_payload_spans` identifies a high-confidence inline script; `attempted = bool(to_decode)` treated its existence as a decoding attempt. An identity Magic candidate has no transformations, hence final output is deliberately empty; that does not mean the original script failed to decode. Fixed status logic at `backend/command_analyzer.py:1361–1376`: plain inline bodies with no successful transforms/unresolved constructs are NOT_REQUIRED, with no fabricated canonical recovery.
2. **Substring stealth false positive.** Baseline `classify_behaviors` searched switches anywhere in command text, matching both `-noprofile` and `-nop` and even quoted script arguments. Repair at lines720–737 matches complete launcher option/value tokens before the payload flag. NoProfile/NonInteractive/NoExit alone do not produce stealth findings. Actual Hidden window and Bypass/Unrestricted execution-policy options remain observable, explicitly without establishing malicious intent. Existing behavior list shape/tag compatibility retained.
3. **Additional HIGH legacy evidence defect.** `powershell -c "Write-Output hello"` produced `RECOVERED` and canonical garbage from permissive whole-script Base64 decoding. Lines755–784 now reuse the existing bounded automatic detector: when a recognized inline script requires no supported transformation, retain a zero-step inline candidate and bypass speculative whole-script binary recipes. Embedded payload extraction, encoded-command paths and recognized obfuscation retain existing legacy paths. No decoder feature was rebuilt. Existing partial-construction fixtures initially exposed an overly broad guard; it was narrowed using the existing detector, with all original tests retained and passing.

The automatic service at the reviewed baseline already handles the reported harmless input correctly: schema `command-intelligence/1`, engine `1.1.1-auto`, NOT_REQUIRED, final_recoverable equal to exact original, no candidates/methods/behaviors/IOCs and no canonical promotion. Blank legacy final_output for a zero-step identity candidate is deliberate evidence policy; copying that candidate into canonical evidence would be an incorrect fix.

## Reproductions and security

New `backend/tests/test_command_staging_contract.py` uses the actual frontend request builder/validator, real FastAPI route, existing JWT dependency with synthetic users, and isolated workers. It covers the exact harmless input, legacy200 rejection, plaintext/garbage recovery, malformed EncodedCommand, benign switches/quoted arguments, and explicit configuration positives. Original RC22, semantic honesty and resource tests are unchanged. New frontend unit regression uses an explicitly minimal observed-shape reproduction, not a claim to retain the complete original live JSON. Local browser injects that incompatible200 and asserts visible error, no accepted result, exactly one request and no fallback.

Before targeted repair: **12 failed / 3 passed** on the same15 new regression cases. After: **15/15 passed**, plus two launcher-boundary holdouts (17 new regressions total). The reviewed automatic path passes before and after; the repaired defects are in shared legacy analysis. CI-equivalent local command gate: **370 passed**. Frontend: **124 passed**, XDR build passed. Local browser: **23 successful API/evidence cases**, plus injected legacy200 rejection, tenant-cancellation, busy503, invalid-token401, inert-text/mobile checks. All30 CI-09 protections remain covered, including bounded decompression, detection/recipe limits, kill-and-reap timeout, admission/concurrency and malformed streams. Worker/resource/auth/tenant modules are unchanged; the reused detector executes within the existing legacy worker boundary and its hard deadline/memory/input/output budgets. No submitted PS/CMD scripts were executed or extracted URLs fetched.

Broader shared XDR/Workspace/tenant/canonical/decoder regressions: **591 passed** on the final tree. Final hosted CI link is recorded in the isolated draft PR. Counts overlap; do not sum suites as unique coverage.

## Minimal operational resolution and acceptance decision

Provision or select an **owner-authorized isolated backend at the reviewed repair commit**, verify its source/deployment revision, automatic request field and real automatic response, and build the isolated frontend against that backend's public origin. Check the production-oriented build script's explicit API override: setting only the usual frontend API variable does not control this script's chosen origin. Preview-only configuration/backend deployment requires owner approval and is not performed here. Preserve production origin and all existing release gates.

Then run full authenticated console Analyse with harmless plaintext, Base64→UTF-16LE→GZIP/nested payloads, every layer/recipe/hash/IOC/limitation, actual RBAC/tenant/MSSP boundaries, cancellation/concurrency and CPU/RSS/process telemetry. No frontend compatibility bypass, legacy-envelope fabrication or production deployment is proposed.

**Staging contract gate: FAIL (observed). Authorized version-aligned deployed acceptance: BLOCKED / not passed. Local engineering repair gate: PASS within tested scope. Release: NO-GO.** Previous81/100 is a manual engineering planning score, not production certification; this investigation provides no new deployed-acceptance points or release approval. Backend Git SHA, actual reverse-proxy topology, full authenticated request capture and isolated runtime telemetry remain explicit dependencies.

Sanitized source evidence: `STAGING_CONTRACT_EVIDENCE_2026-10-12.json` contains only the public schema excerpt, document hash, generic API version and verified frontend metadata; no credentials or private configuration values.
