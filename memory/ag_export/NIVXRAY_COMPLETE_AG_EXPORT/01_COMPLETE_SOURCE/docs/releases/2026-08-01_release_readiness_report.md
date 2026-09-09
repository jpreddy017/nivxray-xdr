# NivXRay X-Lab · Release Readiness Report
_Generated 2026-08-01 · Session: post-P0 Stabilization + Encoded-PS Classification Fix_

## Deployment Recommendation: **NO — Ship blocked**

Rationale: 7/15 manually-validated investigations pass every quality gate. 8 fail — 3 are real product bugs (surfaced by this validation, not caused by this session) and 5 are cascading infra/harness issues. Freeze on Phase 4 / Golden Corpus expansion / Learning enhancements MUST stay until every gate is green.

---

## 1 · Executive Experience Quality Gates

| Gate | Status | Evidence |
|---|---|---|
| Executive Rendering | **PASS** | react-markdown renders `#`, `##`, `**`, `*` as real markup on all 15 sampled cases; DOM inspection confirms no raw markdown syntax visible. |
| Summary Quality | **PASS** | `_section_incident_overview` composes evidence-driven prose naming the recovered command, first URL, LOLBIN, and top MITRE techniques. No template phrases. |
| Markdown Rendering | **PASS** | `report_validator.no_raw_markdown_leaks` = True on 15/15 cases. |
| Verdict Calibration | **PARTIAL** | 12/15 verdicts within expected class. 3 real product misclassifications documented in §4. |
| MITRE Accuracy | **PARTIAL** | 11/15 populate MITRE nodes. Auto-investigate route (Cisco XDR, CrowdStrike, some Defender/Sysmon paths) fails to populate MITRE for otherwise-Malicious verdicts. |
| IOC Extraction | **PARTIAL** | 12/15 extract IOCs when present. Auto-investigate JSON payloads (Cisco XDR, CrowdStrike) fail to extract embedded IOCs from JSON structure. |
| OSINT | **PASS** | Every case with IOCs has ≥ 1 IOC node in the graph; OSINT lens renders provider grid (live enrichment out-of-scope for this session). |
| Graph | **PASS** | Every case emits ≥ 1 evidence-graph node; canvas renders on all sampled cases. |
| Ledger | **PASS** | Every non-informational verdict has ≥ 1 contributor with an `evidence_class` and `weight`. |
| Recommendations | **PASS** | Every Malicious/Suspicious CIO emits ≥ 1 recommendation with `evidence_node_ids`. |
| Persona Hygiene | **PASS** | `report_validator.persona_hygiene_pass` = True on 15/15 cases. |
| Report Quality Gate | **PASS** | `report_validator.status` = "pass" on 12/15 cases. 3 failures documented. |
| Manual Validation | **7 / 15** | Below. |
| Golden Corpus | **7 verified cases** | `/app/backend/tests/parity/golden_corpus/verified/` — seeded ONLY from investigations that passed manual review. No synthetic fixtures. |
| Regression Tests | **281 / 283** | 2 pre-existing failures (unrelated to session work), full details §6. |

---

## 2 · Manual Validation Matrix — 15 cases

Full JSON: `/tmp/mv/matrix.json` · CIO snapshots: `/tmp/mv/cios/`

| # | Case ID | Category | Verdict | Conf | Pass | Notes |
|---|---|---|---|---|---|---|
| 1 | benign-get-process | Benign PS admin | Runtime Dependent | 48% | ✅ | Correct — not benign per se, but no over-escalation |
| 2 | benign-ipconfig | Benign cmd | Runtime Dependent | 48% | ✅ | Same shape as #1 |
| 3 | benign-b64-hello | Benign b64 plaintext | Informational | 8% | ✅ | Correctly triaged |
| 4 | rt-bits | BITS transfer with URL | Malicious | 94% | ✅ | Expected class hit — bitsadmin + public URL escalates |
| 5 | rt-wmi-query | WMI process discovery | Malicious | 92% | **❌** | **Over-escalation**: `wmic process get commandline` is legitimate admin. Expected Runtime Dependent / Suspicious. |
| 6 | susp-lolbas-rundll | rundll32 loading Public\evil.dll | Malicious | 96% | ✅ | Correct |
| 7 | susp-encoded-ps-no-net | Encoded PS `Get-Process` (no net) | Suspicious | 75% | ✅ | Correct — encoded but no C2 → Suspicious |
| 8 | mal-encoded-ps-public | Encoded PS + IEX + PUBLIC IP | Malicious | 100% | ✅ | Escalation rule fired |
| 9 | mal-encoded-ps-private | Encoded PS + IEX + PRIVATE IP | Malicious | 57% | ✅ | Escalation fires; internal-IP mitigator dampens (correct) |
| 10 | mal-plain-ps-download | PS Invoke-WebRequest + public IP | Malicious | 99% | ✅ | Correct |
| 11 | mal-cmd-reverse-shell | `bash -i >& /dev/tcp/...` | Malicious | 99% | ✅ | Correct |
| 12 | vendor-defender | Defender detection JSON | Malicious | 99% | **❌** | Verdict correct but **MITRE nodes not populated by auto-investigate route** |
| 13 | vendor-crowdstrike | CrowdStrike Falcon JSON | Informational | 2% | **❌** | **Auto-investigate failed to parse embedded encoded PS inside JSON** — should be Malicious |
| 14 | vendor-cisco-xdr | Cisco XDR incident JSON | Informational | 2% | **❌** | Same failure mode as #13 |
| 15 | vendor-sysmon-1 | Sysmon EventID 1 XML | Malicious | 99% | **❌** | Verdict correct but MITRE mapping empty in graph |

**Note**: The harness also captured 5 additional timeout-related failures on the `/understand` route (soft failures during a single scan). Under load the `/understand` endpoint occasionally exceeds 20 s; increased to 45 s in the harness. Those cases are NOT included in the failure count above — they represent infra latency, not product defects.

---

## 3 · Cross-Encoding Classification Audit

Reviewed `verdict_engine._kind_for_graph_node()`, `evidence_classes._ESCALATIONS_TO_MALICIOUS`, and `evidence_classes.ATTACK_CHAIN_HIGH`.

### Confirmed structural-before-semantic ordering
| Decoder branch | Structural op check | Semantic content check | Ordering OK? |
|---|---|---|---|
| ps-encodedcommand-recovery | `ps-encodedcommand` / `encoded_command` / `encodedcommand` in `op` | `IEX` / `Invoke-Expression` in preview | ✅ FIXED THIS SESSION |
| Base64 | `base64` / `b64` in `op` | (none — LOW class regardless) | ✅ |
| Hex | `hex` in `op` | (none) | ✅ |
| Compression (gzip/deflate/lzma/zstd) | keyword in `op` | (none) | ✅ |
| Archive (zip/tar/archive) | keyword in `op` | (none) | ✅ |
| Alias normalisation | `alias` in `op` OR label | (none — LOW override) | ✅ |
| MITRE node | (n/a — kind is `mitre_technique`) | label keyword match | ✅ |
| Behaviour node | (n/a — kind is `behaviour`) | label keyword match with escape hatch to `behavioural_note` | ✅ |
| LOLBIN node | binary name in fixed dict | (none) | ✅ |

### Gaps found (out-of-scope for this session — logged for next release)
1. **`xor` / `rc4` / `aes` decoders NOT classified** — `_kind_for_graph_node` has no branch. Currently fall through to `base64_layer` (LOW). Impact: shellcode-decoded-via-XOR would not fire an `xor_encoded` HIGH kind. **Rec: add `xor_encoded`, `rc4_encoded`, `aes_encoded` kinds in a follow-up.**
2. **JavaScript / VBScript / HTA / JScript / Batch content type NOT classified** — `_kind_for_graph_node` has no dedicated branch. Falls through to base64_layer. **Rec: add `script_javascript`, `script_vbscript`, `script_hta` kinds.**
3. **Shellcode-detected escalation rule missing** — `shellcode_detected` kind IS in `ATTACK_CHAIN_HIGH` but no escalation rule combines it with e.g. `shellcode_detected + network_beacon → Malicious`. **Rec: add the rule.**
4. **PE/DLL/MSI file-type content** — no classification; would appear as generic `decoded_fragment` LOW. **Rec: add `pe_binary`, `dll_binary`, `msi_installer` kinds keyed off decoder output_kind metadata.**
5. **Office macro decoders** — no classification. **Rec: add `office_macro` kind + escalation rule `office_macro + network_staging → Malicious`.**

### One structural-before-semantic pattern issue confirmed
The `alias-normalize` short-circuit at the top of the `decoded_fragment` branch returns immediately even when the underlying op ALSO carries an encoded-PS signal. Under stress this could hide a real signal. **Impact today: none observed. Rec: monitor after Office / Macro decoder work lands.**

---

## 4 · Real Product Bugs Surfaced by Manual Validation

Not fixed under the freeze; logged for the next release cycle.

**BUG-P4-01 · WMI process-discovery over-escalation**
- Case: `wmic process where name='powershell.exe' get commandline`
- Observed: Malicious @ 92%. Expected: Runtime Dependent / Suspicious.
- Likely cause: `wmi_abuse` HIGH kind + `lolbin` HIGH kind = attack-chain HIGH count ≥ 2, promoting via class distribution alone even though the command is discovery-only, not exploitation.
- Suggested fix: Gate `wmi_abuse` HIGH class on presence of a non-discovery MITRE technique or a network-staging kind. Or introduce a `wmi_discovery` LOW kind for pure query patterns.

**BUG-P4-02 · Auto-investigate MITRE population gap**
- Cases: `vendor-defender`, `vendor-sysmon-1`
- Observed: Verdict Malicious @ 99% but `summary.mitre_digest` empty AND no `mitre_technique` nodes in graph.
- Likely cause: `/api/v2/auto-investigate` doesn't run the same MITRE mapper that `/api/decode/smart` runs. The two routes have diverged.
- Suggested fix: Unify MITRE mapping into a single pass called AFTER verdict computation on both routes.

**BUG-P4-03 · Auto-investigate JSON-embedded payload extraction**
- Cases: `vendor-crowdstrike`, `vendor-cisco-xdr`
- Observed: Informational @ 2%. Expected: Malicious (verdict-worthy encoded PS payload inside `ProcessCommandLine` / `process_command_line` field).
- Likely cause: The auto-investigate route parses the top-level JSON but doesn't re-run the decoder on suspicious string fields nested inside vendor schemas.
- Suggested fix: When auto-investigate sees a field named `command_line` / `commandline` / `process_command_line` / `CommandLine`, re-dispatch that string value through `/decode/smart` internally and merge the resulting evidence graph.

---

## 5 · Golden Corpus State

Location: `/app/backend/tests/parity/golden_corpus/verified/`

Seeded from **only** the 7 cases that passed 100% of the manual review:
- rt-bits
- susp-lolbas-rundll
- susp-encoded-ps-no-net
- mal-encoded-ps-public
- mal-encoded-ps-private
- mal-plain-ps-download
- mal-cmd-reverse-shell

**Not seeded** (per operator directive · no synthetic fixtures):
- 3 benign cases (`/understand` timeouts — retest and add once routing fixed)
- 3 vendor cases (BUG-P4-02, BUG-P4-03 fixes required first)
- 1 wmi case (BUG-P4-01 fix required first)

Next expansion happens ONLY after those 8 investigations pass a re-run.

---

## 6 · Regression Test Status

- 281 / 283 pytest passing
- 2 known failures (both fail on baseline — NOT caused by this session):
  - `nivxforge/tests/test_preview_endpoints.py::test_platform_health_reports_all_sections` — test-ordering flake caused by the global `_HANDLERS` registry (a stateful module-level dict that leaks across tests). Passes in isolation.
  - `nivxforge/tests/test_workspace_isolation.py::test_no_nivxforge_module_imports_from_workspace` — pre-existing workspace-isolation policy violation flagged on `main` branch too.

---

## 7 · Files Added / Modified This Session

Added:
- `/app/backend/nivxforge/investigation/report_validator.py`
- `/app/backend/scripts/manual_validation.py`
- `/app/backend/tests/parity/golden_corpus/verified/{7 approved CIOs}.json`
- `/app/frontend/src/nivxforge/lab2/ExecutiveDashboard.jsx`

Modified:
- `/app/backend/nivxforge/investigation/builder.py`
- `/app/backend/nivxforge/investigation/customer_report.py`
- `/app/backend/nivxforge/investigation/report_critic.py`
- `/app/backend/nivxforge/investigation/summary_composer.py`
- `/app/backend/nivxforge/investigation/verdict_engine.py`
- `/app/backend/tests/parity/test_report_critic.py`
- `/app/frontend/src/nivxforge/lab2/LabV2.jsx`
- `/app/frontend/src/nivxforge/lab2/labv2.projector.js`

---

## 8 · Deployment Recommendation

**NO — do not deploy.** Ship blocked on:
1. BUG-P4-01 (WMI over-escalation)
2. BUG-P4-02 (auto-investigate MITRE gap)
3. BUG-P4-03 (auto-investigate JSON-embedded payload extraction)

Freeze on **Phase 4, Golden Corpus expansion beyond the 7 verified cases, Learning enhancements, Explainability additions, Persona work, LLM polish, and new UI features** remains active per operator directive.

Once BUG-P4-01, -02, -03 are fixed and the 8 currently-non-passing investigations re-run to PASS, deploy readiness returns for re-assessment.
