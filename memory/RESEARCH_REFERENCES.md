# NivXRay Research References – Learning Corpus (Feb 2026)

Curated primary-source research the NivXRay offline LLM, regex engines, and
deterministic archetypes are trained against. Every rule/archetype/prompt
tuning below is traceable back to one (or more) of these sources.

---

## SOURCE A — Deep Instinct: **"Excel(ent) Obfuscation: Regex Gone Rogue"**
- URL: https://www.deepinstinct.com/blog/excellent-obfuscation-regex-gone-rogue
- Author: Ido Kringel, Deep Instinct Threat Lab (May 2025)
- IOC hashes (SHA-256):
  - `dedbe856891dd633ce3dd66ecc120ef4f1ae0a61a37dbb4cc6a59f7eae7019d9`  (sample1_re_new.xlsm)
  - `2c99e702609d549440952ef72f2386a74e0da1462df65ab4206f44c94e8dbc72`  (sample1.xlsm)
  - `5af1bd3d95e6307d95e9973aa4a084ae210f9038cbea2235d14b02d97abd4f2b`  (sample1_mp.xlsm)

### Key techniques (mapped to NivXRay detectors)
| Technique                                                 | Detector added                    |
|-----------------------------------------------------------|-----------------------------------|
| REGEXEXTRACT(cell, pattern) hides `WScript.Shell`, PS str | `EXCEL_REGEX_OBFUSC` archetype    |
| REGEXREPLACE / REGEXTEST helper functions                 | `EXCEL_REGEX_OBFUSC` (aliases)    |
| Junk-text-blob in cell A1 with hidden strings             | Heuristic + LLM narrative note    |
| VBA `getval0`/`getval1`/`getval2` naming convention       | Regex tag                         |
| PowerShell reconstructed at runtime via regex match       | LLM prompt awareness              |

### MITRE mapping
- T1027 (Obfuscated Files or Information)
- T1204.002 (User Execution: Malicious File)
- T1059.001 (PowerShell) — downstream child
- T1140 (Deobfuscate/Decode Files or Information)

---

## SOURCE B — Bohannon & Holmes: **"Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science" (Black Hat US 2017)**
- URL: https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And Evasion-Using-Science.pdf
- Authors: Daniel Bohannon (@danielhbohannon), Lee Holmes (@Lee_Holmes)
- Companion tools: `Invoke-Obfuscation`, `Invoke-CradleCrafter`, `Revoke-Obfuscation`

### Key techniques (Launch + Cradle + Token layers)
| Bohannon technique                                                | Detector added                    |
|-------------------------------------------------------------------|-----------------------------------|
| CMD env-var split: `set p1=power&& set p2=shell && %p1%%p2%`      | `CMD_ENVVAR_SPLIT_POWERSHELL`     |
| CMD stdin exec: `echo <PS> \| powershell -`                       | `CMD_STDIN_POWERSHELL`            |
| CMD env-var cmdline pass-through: `powershell IEX $env:cmd`       | `PS_ENVVAR_IEX`                   |
| CMD substring env expansion `%ProgramData:~0,1%%ProgramData:~9,2%`| covered by `BATCH_VAR_SLICE`      |
| Clipboard cradle `[Clipboard]::GetText()` + IEX                   | `PS_CLIPBOARD_IEX`                |
| WMI parent-arg lookup `Get-WmiObject Win32_Process -Filter …`     | `PS_WMI_PARENT_ARG_EXFIL`         |
| Tick-obfuscation: `` `D`o`w`n`l`o`a`d`S`t`r`i`n`g ``              | `PS_TICK_OBFUSC`                  |
| Wildcard cmdlet resolve: `& (GCM *w-O*)`                          | `PS_GET_COMMAND_WILDCARD`         |
| Method-name as string/variable: `.("Down"+"loadString").Invoke()` | `PS_STRING_CONCAT` (existing)     |
| String reversal: `$rev[-1..-$rev.Length] -Join ''`                | `PS_REVERSE_STRING` (existing)    |
| `[Array]::Reverse($chararray)` + `-Join ''`                       | `PS_ARRAY_REVERSE_JOIN`           |
| `[RegEx]::Matches($x,'.','RightToLeft')` reversal                 | `PS_REGEX_REVERSE`                |
| Split delimiter obfuscation: `$c.Split("~~") -Join ''`            | `PS_SPLIT_JOIN_DELIM`             |
| Junk-char replace: `.Replace("~~","")` / `-Replace "~~",""`       | `PS_REPLACE_JUNK`                 |
| Format-op cmdlet: `& ("{1}{0}" -f 'X','IE')`                      | `PS_FORMAT_OPERATOR` (existing)   |
| ScriptBlock create: `[Scriptblock]::Create("...")`                | `PS_SCRIPTBLOCK_CREATE`           |
| PS 1.0 `$ExecutionContext.InvokeCommand.InvokeScript(...)`        | `PS_EXECCONTEXT_INVOKESCRIPT`     |
| `$PShoMe[21]+$psHOMe[34]+'X'` char-index IEX                      | `PS_PSHOME_INDEX_IEX`             |

### MITRE mapping
- T1059.001, T1059.003 (Command & Scripting Interpreter)
- T1027 / T1027.010 (Obfuscated Files / Command Obfuscation)
- T1140 (Deobfuscate/Decode)
- T1562 (Defense evasion where AMSI/log tamper co-occurs)

---

## SOURCE C — dr4k0nia: **"String Obfuscation The Malware Way"**
- URL: https://dr4k0nia.github.io/posts/String-Obfuscation-The-Malware-Way/
- Author: dr4k0nia (@dr4k0nia), Dec 15 2022
- Companion tool: `MurkyStrings` — https://github.com/dr4k0nia/MurkyStrings

### Key techniques
| Technique                                                        | Detector added                       |
|------------------------------------------------------------------|--------------------------------------|
| Homoglyph insertion (Cyrillic а/е/і/о/с) removed by `.Replace()` | `DOTNET_HOMOGLYPH_REPLACE`           |
| Random System-namespace name insertion removed by `.Remove(i,l)` | `DOTNET_STRING_REMOVE`               |
| Combined homoglyph + Remove (multi-pass)                         | Both detectors chain via smart-mode  |
| CIL pattern: `Ldstr` + `Ldnull` + `Callvirt String::Replace`     | LLM narrative — flag reflectively    |

### MITRE mapping
- T1027   (Obfuscated Files or Information)
- T1027.009 (Embedded Payloads)
- T1140  (Deobfuscate/Decode Files or Information)

---

## Training-corpus impact
- New JSONL rows in `/app/backend/training/corpus/samples.jsonl` teach the
  offline LLM to recognise the plain-text signatures + expected decoded output.
- New archetypes in `/app/backend/wrapper_archetypes.py` provide **0%
  hallucination** deterministic decoders that fire BEFORE the LLM.
- `/app/backend/training/system_prompt.py` now names all 3 sources explicitly
  so the LLM's narrative layer cites them when the corresponding shape fires.
- Pytest coverage at `/app/backend/tests/test_research_refs_feb2026.py` locks
  every new archetype behind a regression test.
