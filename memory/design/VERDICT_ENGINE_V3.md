# NivXRay · Verdict Engine v3 — Architecture

> **Status**: shipped 2026-02-23 · flag-gated `VERDICT_ENGINE_V3`
> **Determinism**: 100 % — same frame → same score → same band, forever.
> **Explainability**: every score comes with a `breakdown[]` naming the exact
> signal, weight, reason, and evidence reference that produced it.

## Design goals

1. **Never classify by binary name.** `powershell.exe`, `cmd.exe`,
   `rundll32.exe`, `msiexec.exe`, `regsvr32.exe`, `wscript.exe`, `cscript.exe`,
   `certutil.exe`, `bitsadmin.exe`, `wbadmin.exe`, etc. are always neutral
   until proven suspicious by behaviour.
2. **Deterministic.** No LLM. No probabilistic model. No cloud call. Pure
   Python + config.
3. **Threat Intelligence is enrichment only.** VirusTotal / AbuseIPDB / OTX
   never *decide* the verdict — they can only *tag* events for analyst
   click-through.
4. **Behaviour-first.** Signals derived from the RC5 pipeline (MITRE tags,
   rule matches, parent/child chains, command-line semantics, registry / file /
   network side-effects, LOLBAS, entropy, signing status …).
5. **Auditable.** Every verdict emits a `breakdown[]` so any analyst can
   reconstruct why the score is what it is. All weights + bands live in one
   config file.
6. **Extensible.** New signals are added by dropping a detector function into
   `signals.py` and a weight into `weights.py` — no engine rewrite.

## Score model

```
score(event, ctx) = clamp(0..100,
    Σ signal.weight  for signal in signals_fired(event, ctx)
  − Σ decay.weight   for decay  in decay_fired(event, ctx)
)

with per-family caps to prevent any one family from dominating:
    caps = { persistence: 30, evasion: 25, credential: 30,
             impact: 40, execution: 20, network: 25, artefact: 15 }
    contribution(family) = min(caps[family], Σ family weights)
```

## Bands (default — configurable)

| Score  | Band                        | UI colour     |
|-------:|-----------------------------|---------------|
|   0–15 | `benign`                    | gray           |
|  16–35 | `informational`             | slate          |
|  36–55 | `low`                       | amber-low      |
|  56–70 | `suspicious`                | amber          |
|  71–85 | `malicious`                 | red            |
| 86–100 | `critical`                  | dark red      |

## Signal catalogue (v3.0)

Every signal is deterministic. `family` drives the anti-inflation cap.
`requires_corroboration=True` means the signal alone caps the final score at
70 unless a second unrelated signal fires.

| family      | key                          | weight | rationale |
|-------------|------------------------------|-------:|-----------|
| execution   | `MITRE_CRITICAL`             |   +25 | Techniques the community treats as end-of-chain (T1486, T1490, T1489, T1620, T1003, T1055). |
| execution   | `MITRE_HIGH_RISK`            |   +12 | LOLBAS abuse / obfuscation / persistence families (T1218, T1027, T1547, T1562). |
| execution   | `MITRE_OTHER`                |    +4 | Everything else — provides colour, never dominates. |
| execution   | `RULE_HIT`                   |   +10 | Detection rule fired; corroborates the MITRE tag. |
| execution   | `MITRE_CORRELATED`           |    +8 | ≥ 3 distinct techniques in the same chain. |
| execution   | `MULTI_STAGE`                |    +8 | Chain depth ≥ 3 with LOLBAS at multiple depths. |
| execution   | `LOLBAS_ABUSE`               |    +8 | Signed system binary invoked with unusual verbs. Names alone do not qualify. |
| execution   | `SUSPICIOUS_PARENT`          |   +18 | Office / Outlook / browser / explorer spawns a shell/scripting host. |
| execution   | `SERVICE_CREATED_PROC`       |   +12 | `services.exe` spawns something that isn't on the expected list. |
| persistence | `REGISTRY_PERSISTENCE`       |   +15 | Run / RunOnce / Winlogon / StartupApproved keys. |
| persistence | `SCHEDULED_TASK_CREATE`      |   +12 | schtasks / Register-ScheduledTask. |
| persistence | `WMI_PERSISTENCE`            |   +18 | `__EventFilter` / `CommandLineEventConsumer`. |
| credential  | `CREDENTIAL_DUMPING`         |   +25 | LSASS handle acquire, comsvcs `MiniDump`, procdump, T1003 hit. |
| credential  | `LSASS_ACCESS`               |   +18 | Any process opens LSASS with dump-capable rights. |
| evasion     | `PROCESS_INJECTION`          |   +18 | T1055 / `CreateRemoteThread` / `NtWriteVirtualMemory`. |
| evasion     | `AMSI_BYPASS`                |   +18 | `AmsiUtils` reflection, `System.Reflection` + `AmsiEnable`. |
| evasion     | `DEFENDER_TAMPERING`         |   +18 | `Set-MpPreference -Disable*`, `sc stop Windefend`, MpCmdRun disable. |
| evasion     | `ENCODED_POWERSHELL`         |   +10 | `-EncodedCommand`, `-e ` with base64 blob ≥ 40 chars. |
| evasion     | `OBFUSCATION`                |    +8 | High cmdline entropy, char-substitution, backtick sprinkle. |
| impact      | `BACKUP_DESTRUCTION`         |   +25 | `wbadmin delete catalog`, `wbadmin delete backup`. |
| impact      | `SHADOW_COPY_DELETE`         |   +20 | `vssadmin delete shadows`, `wmic shadowcopy delete`. |
| impact      | `RANSOM_NOTE_CREATION`       |   +25 | New file matching ransom-note pattern (`README*.txt`, `HOW_TO_DECRYPT*`). |
| impact      | `MASS_FILE_ENCRYPTION`       |   +30 | ≥ 25 file writes in ≤ 60 s with entropy jump ≥ 0.7. |
| network     | `NETWORK_BEACONING`          |   +15 | ≥ 4 outbound connects to same host at regular ±20 % intervals. |
| network     | `EXTERNAL_C2`                |   +18 | Connect to IP/domain flagged by RC5 IOC pack (deterministic list). |
| network     | `DOWNLOAD_CRADLE`            |   +15 | `IWR` / `WebClient.DownloadString` / `curl -o` followed by execute. |
| artefact    | `NEWLY_DROPPED_EXECUTABLE`   |    +8 | File written and executed within 60 s. |
| artefact    | `UNSIGNED_EXECUTABLE`        |    +4 | Sig verify failed and binary path outside `%SystemRoot%`. |
| artefact    | `HIGH_ENTROPY_PAYLOAD`       |    +6 | Written file entropy ≥ 7.5 bits/byte. |
| artefact    | `CHAIN_COMPLEXITY`           |    +6 | ≥ 5 distinct entities in the execution chain. |

### Decay signals (subtract from score)

| key                        | weight | rationale |
|----------------------------|-------:|-----------|
| `SIGNED_MICROSOFT_BINARY`  |   −4  | Verified MS signer + valid chain. |
| `EXPECTED_PARENT_CHILD`    |   −4  | `services.exe → svchost.exe`, `wininit.exe → services.exe`, etc. (deterministic table). |
| `NO_MITRE_TAGS`            |   −4  | The RC5 decoder found nothing behavioural. |
| `SINGLE_EVENT_NO_CORROB`   | cap ≤ 70 | If only one signal fired *and* it required corroboration, final score is capped at 70. |

## Config-driven

Everything above lives in `weights.py` as a plain dict. Sites can override:

```python
WEIGHTS.update({"BACKUP_DESTRUCTION": 35})            # tighten Impact
BANDS["malicious"] = (75, 89)                          # tighter malicious floor
FAMILY_CAPS["network"] = 30                            # let networking cluster more
```

## FP protection

- **Corroboration rule** — high-value signals (`MITRE_CRITICAL`, `LSASS_ACCESS`,
  `PROCESS_INJECTION`, `AMSI_BYPASS`, `MASS_FILE_ENCRYPTION`,
  `BACKUP_DESTRUCTION`) contribute their full weight only when at least one
  *unrelated* signal in a different family also fires. Alone they cap the
  final score at 70 (band = `suspicious`) so a single false positive can
  never mint a `malicious` verdict.
- **Family caps** — no family may contribute more than its cap, preventing a
  chain of related-but-redundant persistence signals from inflating a score.
- **De-duplication** — the same MITRE technique fired N times on the same
  entity counts *once*.
- **Decay** — signed system binaries with expected parents subtract points.

## Integration & migration

`v2/routers/trajectory.py` and `v2/routers/report.py` continue to emit the
v2 `verdict` field. When flag `VERDICT_ENGINE_V3` is observable, every frame
gets an **additional** `verdict_v3` block with `score`, `band`, `breakdown`.
Downstream consumers (Device Trajectory UI, IRG canvas, Process Ancestry,
Report / STIX / Evidence bundle) can adopt v3 at their own pace; the v2 shape
is preserved unchanged for backwards compatibility.

## Testing

Unit tests cover:

1. **BENIGN baseline** — `notepad.exe` with no MITRE / no rule → score 0.
2. **Named-binary neutrality** — `powershell.exe -Version` with no MITRE →
   score 0. Never fires just because of the name.
3. **Corroboration cap** — a lone `LSASS_ACCESS` capped at 70.
4. **Ransomware chain** — Office → PS → LOLBAS `wbadmin delete` → vss delete
   → mass write → ransom note fires ≥ 6 signals → score ≥ 86 (critical).
5. **Decay** — `services.exe → svchost.exe` (signed, expected parent, no
   MITRE) subtracts 8 → score 0, band `benign`.
6. **Family cap** — 4 persistence signals still sum to ≤ 30.
7. **Determinism** — same input → same output over 1000 iterations.

## Chaos ransomware — worked example

Real chain from the Talos writeup, applied to v3 signals (no signature
matching; **behaviour only**):

```
outlook.exe                           → SUSPICIOUS_PARENT   +18
  └─ powershell.exe -EncodedCommand …    ENCODED_POWERSHELL +10
                                         MITRE_HIGH_RISK    +12  (T1027)
      └─ chaos_loader.exe            → NEWLY_DROPPED_EXEC   +8
                                       UNSIGNED_EXECUTABLE  +4
          ├─ wbadmin delete catalog  → BACKUP_DESTRUCTION   +25 (MITRE_CRITICAL +25)
          ├─ vssadmin delete shadows → SHADOW_COPY_DELETE   +20
          ├─ mass file writes .chaos → MASS_FILE_ENCRYPTION +30
          └─ HOW_TO_DECRYPT.txt      → RANSOM_NOTE_CREATION +25
```
Raw sum = 177 · Family caps applied (Impact 40 · Execution 20 · Artefact 12
· Evasion 22) → clamped total ≈ **94 → `critical`**.

The verdict is reached **without ever looking at the binary name**. Even if
`chaos_loader.exe` were renamed `svchost.exe`, the score would land in the
same band because the behavioural evidence is identical.
