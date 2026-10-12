# Independent review and release-gate repairs

Reviewed immutable PR #12 commit: `b8fb550915287106615a12c6b96bdfdd3c481ec0`.
Security baseline PR #11: `e75f163e6c7640c34a07985024369ce086f035ea`.
Repairs: isolated `engineering/xdr-command-review-gates`, stacked draft targeting PR #12's branch. Neither existing PR was modified, merged or approved. Final published SHA and hosted CI link are recorded in the repair PR.

**Original PR #12 review: FAIL. Isolated repair review: PASS within the tested static-decoding scope. Release: NO-GO.**

A separate read-only reviewer inspected source, independently ran existing security/maturity tests and supplied previously unseen counterexamples. The implementer repaired a separate tree; the reviewer found additional variants during re-review, then verified their closure. No submitted PowerShell/CMD was executed, no live customer endpoint tested and no GitHub approval submitted. This is independent engineering verification, not a third-party penetration-test certificate.

## Concrete findings

| ID / severity | Location | Baseline reproduction | Repair / verification |
| --- | --- | --- | --- |
| RG-01 / HIGH | `powershell_constants.py`, command statement/argument parsing | `Write-Output 2+2` wrongly becomes canonical `Write-Output 4`. Grouped arguments also swallowed trailing tokens: `Write-Output (1)+2`; Write-Host pipelines were interpreted as value-producing maps. | Compute only inside the balanced command argument group or one simple value. Refuse additional argument/operator/pipeline grammar. Argument data is preserved. |
| RG-02 / HIGH | `powershell_constants.py`, Pratt precedence/evaluation | `Write-Output ('[{0}]' -f 'x' + 'y')` promoted `[xy]` rather than `[x]y`; comma/arithmetic grouping and format associativity were incorrect. | Align comma, formatting, arithmetic, binary join and bitwise precedence with Microsoft documentation; operators left-associate. Nested array/coercion cases that the typed model cannot represent are refused. |
| RG-03 / HIGH | `powershell_constants.py`, lexical variable coverage | `$x='a';Write-Output ${x` silently repairs missing `}` and promotes a constant. | Validate complete raw variable spans; malformed/scoped/unsupported variable syntax refuses promotion. Valid `${x}` retains coverage. |
| RG-04 / HIGH, baseline-existing | `automatic.py`, `static_folds` and transition fallback | `Write-Output 'a'+'b'` folds in argument mode. `bash -c 'echo hi'+'x'` changes Bash command content. A new AST refusal alone left this fallback reachable. | Restrict historical fold context and emit its recipe only when the typed whole-program pass independently proves identical output. Valid historical literal recipes remain reproducible. Whitelisted Base64 argument normalization restores the existing nested literal recipe as partial evidence. |
| RG-05 / HIGH | `powershell_constants.py`, raw string validation | `$x=1+2;$y="c""` promotes an earlier fold although the final doubled quotes leave the string unterminated. | Validate complete SQ/DQ literal grammar rather than last-character matching. Valid triple-quote endings remain accepted. Malformed untouched tails prevent canonical promotion. |
| RG-06 / MEDIUM | `command_behaviors.py`, syntax masks and command boundaries | Displayed Set-MpPreference/reg/comsvcs/API names become invocation findings; original `cmd /d /c echo ...` and executable-path variants produce false injection chains. | Anchor command findings, mask unquoted display arguments except balanced expression groups, keep post-group bare arguments masked, and recognize explicit CMD executables/paths/flags conservatively. Real parenthesized API expressions retain observations and exact spans. |

The initial 43-case maturity corpus did not expose these language-boundary errors. Its 100% result never established general semantic correctness. New adversarial cases are retained rather than hidden behind the old benchmark.

Primary semantic references: [PowerShell parsing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parsing), [operator precedence](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operator_precedence). The implementer opened these sources directly; the independent reviewer used them independently. No incompatible third-party code was copied.

## Three RC22 failure dispositions

1. **UTF-16 trace ID — obsolete expectation, stronger contract test.** The current PS preamble performs real Base64 and strict UTF-16LE recovery, represented by `ps-encodedcommand-recovery` and `recovery_winner=utf16le_strict`. The old test expected the bypassed generic plugin ID `utf16-decode`. The test now checks the exact recovered script in the recovery trace, strict winner, ordered attempts and actual invocation/recovered lengths, retaining output URL/IOC and successful terminal assertions. Downstream legacy wrapper peeling still returns its established URL output. No duplicate/fictitious UTF-16 trace was added. Generic registry and UTF-16BE tests remain.
2. **Character array — real delimiter defect plus obsolete oracle.** The legacy regex ignored its separator, and a generic JavaScript concatenation candidate could preempt PowerShell reconstruction. The PS-specific complete typed expression handles supported array/join precedence; legacy literal separator folding now honors the separator and refuses a trailing operator extension. JS concatenation-only detection does not claim explicit PS constructs. The original sample `... -join '' + '_MARK_'` is retained with the exact native-semantics separator oracle `P_MARK_o_MARK_w_MARK_e_MARK_r_MARK_S_MARK_h_MARK_e_MARK_l_MARK_l`. An added parenthesized join-then-concatenate sample requires exact `PowerShell_MARK_`. The obsolete substring expectation was replaced with stricter exact assertions, not weakened.
3. **IOC extraction — genuine typed schema defect.** `_extract_all` appended `_entity_classifications: list[dict]` to the same map passed to `PluginResult.iocs: Dict[str,List[str]]`. One classified IPv4 made Pydantic reject all indicators. Classification diagnostics remain available from the raw helper, but are separated before constructing the typed IOC result. URL/IP/email/hash checks now pass; no model schema, auth or tenant contract is widened.

Cross-product impact: these fixes touch shared legacy decoder helpers and therefore receive Workspace/decoder/RC22 tests. Automatic mode uses its own established IOC extraction; it keeps existing API/evidence fields. No EDR agent, response authority, Workspace UI, product ownership or canonical integration schema is edited. Automatic recipe/provenance version is bumped to **1.1.1-auto** so repaired grammar is distinguishable from PR #12's 1.1.0-auto. The HTTP schema remains `command-intelligence/1`.

## Verification

- Before: independent PR #12 run **116 passed** (86 maturity + 30 CI-09), despite the counterexamples. Parent reproduction of RC22: **3 failed, 129 passed** with maturity/security included.
- Repair re-review: independent combined run **168 passed**, followed by final **38 review-gate tests passed** and fresh CMD/grouped-argument/malformed-string positive and negative probes. Reviewer closes every concrete finding above within the supported tested scope.
- Clean pinned CI-equivalent gate: **355 passed**, including RC22, review gates, all maturity and all 30 CI-09 resource tests. New CMD path cases are included.
- Broader backend run: **571 passed, zero failures**; three additional CMD-prefix/path cases subsequently pass in the clean gate. Covers XDR scope/RBAC/tenant authority, Workspace convergence/certification, canonical plumbing, bridge/adapter, archive, PS reconstruction and entity classifier. Do not combine overlapping counts.
- Frontend **123 passed**; Workspace **25 Node + 14 Jest passed**; isolated XDR and EDR builds passed.
- Actual local page→Axios→JWT-validated API→spawned worker→DOM: **23 harmless cases passed**. Five new holdouts check argument mode, grouping, format precedence, malformed brace and CMD display syntax. Every intermediate, recipe, hash, IOC, limitation, behavior label/offset, mobile width, inert text, tenant cancellation, 401 and busy response is checked against the API.
- CI-09 harmless probe remains PASS: legacy oversized413, automatic422, bounded gzip refusal, timeout504 with no delayed completion. No resource-profile/worker/auth file changed.
- Same 43-case benchmark: **43/43 policy checks, 7/7 typed behavioral checks, 43/43 recipe checks** retained. It remains synthetic subset coverage, not a general malware accuracy rate. `REVIEW_GATES_BENCHMARK.json` records the run.
- `REVIEW_GATES_BEFORE.json`/`AFTER.json` retain exact direct reproductions. `REVIEW_GATES_SECURITY.json` records the resource probe. Diff and read-only ownership checks pass; hosted result/commit tree equality are recorded in the repair PR.

Representative broader command: `PYTHONPATH=backend python -m pytest -n 0` over `test_command_review_gates`, `test_command_maturity`, `test_command_resource_limits`, `test_command_automatic`, `test_command_automatic_api`, `test_command_analyzer`, `test_ci_r1_r3_decoder_honesty`, `test_xdr_rc1_p1_scope_authority`, `test_xdr_rc1_integration`, `test_rbac_selected_customer`, `test_d14_tenant_authority`, `decoder_harness/test_ddo_dispatch_matrix`, `test_decoder_bridge`, `test_decoder_pass`, `test_workspace_certification`, `test_canonicalizer_decoder_plumbing`, `test_rc22_decoder_pack`, `test_rc22_workspace_adapter`, `test_die_cycle_b_archives`, `test_ps_reconstruct_p03`, `test_entity_classifier` (under `backend/tests`, `.py` suffix).

## Exact staging dependency

Fresh permitted read-only checks:

- Project inventory lists engineering `nivxray-xdr`, project `prj_wItvwa3g09dQxMqv2WNzdrCO3QDe`, account/team `team_GpHdVK9BbLH0warYc4OXARGa`.
- `GET /v9/projects/{idOrName}` with those exact IDs returns **403 forbidden**: “Not authorized: Trying to access resource under scope jpreddy017.” Provider requests access-bearing authentication for that scope. Request ID `bom1:sfo1::pgngg-1791799030449-bd1262c724d4`.
- `GET /v7/deployments` scoped to the same project/team and `target=preview` also returns **403**. Request ID `bom1:sfo1::rcjxq-1791799030005-c7bd9f23f4e3`.
- Team listing returns no team memberships; Git deployment context also returns an empty teams list. This describes the current connector's observable access, not proof about the owner's account membership. Inventory visibility is insufficient to establish project/deployment access.
- Vercel CLI fallback is unavailable; no installed CLI with an independently authorized identity was found. No secrets/credentials were searched, printed, requested or changed. No unchanged retries, alternate-scope guesses, share/bypass tokens or protection changes were attempted.

This is a **control-plane authorization block**, not evidence that the Analyze API or UI itself returned403. No authorized isolated staging frontend/backend URL and session has been established. Therefore deployment configuration, preview commit, configured API origin, backend SHA, Mongo/MSSP tenant isolation and runtime resource telemetry remain **UNVERIFIED/BLOCKED**.

Local source wiring is compatible: Vite maps the configured public `REACT_APP_NIVXRAY_API_URL`/backend origin to the Axios `/api` base, and the existing static-host rewrite serves the console. The local API responds with schema `command-intelligence/1` and repaired engine `1.1.1-auto`; the page accepts that response. This does not establish deployed environment values or version alignment.

Owner dependency: establish approved read access for the connected identity to this exact project/team (or provide an existing authorized isolated staging surface through approved access), identify the frontend/backend commit pair, supply authorized test tenants/principals through approved session mechanisms and permit read-only CPU/RSS/worker telemetry. The connector error does not establish which membership, integration scope or provider policy must change; a legitimate owner/provider administrator must resolve it. Engineering cannot repair this403 by changing application authentication or production configuration. Do not send secret values through chat.

## Existing rubric reassessment

| Published dimension | Previous / weight | Repaired / weight | Evidence |
| --- | --- | --- | --- |
| Encoding/compression | 10/10 | 10/10 | Existing modes and CI-09 codec regressions retained |
| PS static semantics | 12/15 | 12/15 | Reviewed argument/precedence/lexical defects fixed; still restricted grammar, not native differential validation |
| Custom decoder recognition | 8/10 | 8/10 | Bounded maps retained; arbitrary loops/rotating keys unsupported |
| Evidence/provenance | 15/15 | 15/15 | Concrete canonical bugs closed and 38 review gates added; hashes/recipes/partial guards verified within scope |
| Behavior | 8/10 | 8/10 | Display/context false positives fixed; no deep intent/dataflow proof |
| Resource security | 13/15 | 14/15 | Independent new-code review completed, all30 CI-09 tests pass; target-host sizing still pending |
| Local integration/UX | 9/10 | 9/10 | 23 actual local browser cases; full deployed console unverified |
| Broad regression health | 3/5 | 5/5 | All three RC22 failures dispositioned, strict oracles and broad suite green |
| Deployed acceptance | 0/10 | 0/10 | Exact authorization block unresolved |
| **Engineering planning total** | **78/100** | **81/100** | Same manual published rubric; not an independently certified industry benchmark |

The previously published78 was a provisional self-assessment: independent review subsequently found HIGH defects, so that number never authorized release. **81 is supported only for the repaired, independently reviewed engineering tree and this rubric**, not the unchanged PR #12 head. Do not describe either PR as production-approved.

Release stays **NO-GO** until authorized isolated staging validates actual full-console Analyse, Base64→UTF-16LE→GZIP, tenant/MSSP/database/role journeys, frontend/backend rollout compatibility, CPU/RSS/process multiplication, concurrency/cancellation and owner release approval. All MITRE/security HOLDs remain. No merge, deployment, production configuration/database, DNS, secret, PR #10, RC2 or EDR candidate change occurred.
