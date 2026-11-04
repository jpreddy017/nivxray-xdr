# Real Investigation Proof · Phase-B / Post-P2 Test Cases

**Frozen 12-case corpus (Phase A) is untouched.** This document captures test
inputs the owner has designated as *future* validation targets — cases that
NivXRay is expected to handle correctly **only after** the Cruise-Missile
principle (ADR-0023 §3a) is fully realised, i.e. once behavioural
telemetry has been ingested and correlation across process / file / network
/ registry / user-session evidence is available.

These cases must **not** be added to the frozen corpus without owner
authorisation and a fresh Phase-A re-run. They live here as pre-registered
Phase-B expectations only.

---

## Case pb-01 · PowerShell deployment with legitimate-looking context

**Registered:** 2026-08-12 · owner
**Class:** Ambiguous — "suspicious behaviour ≠ malicious verdict"
**Corpus location:** Phase-B (post-P2) only

### Input A (deployment launcher)

```
-ExecutionPolicy Bypass -NoProfile -File "C:\WINDOWS\IMECache\5c9d6d08-8a34-4439-ba8e-1ef8b3988af3_1\install.ps1" -CustomInstallCommand ""
```

### Input B (deployment application script)

```
-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -Command & { & 'C:\WINDOWS\IMECache\5c9d6d08-8a34-4439-ba8e-1ef8b3988af3_1\Deploy-Application.ps1' -Version 1.26832.0 -InstallProgress Hide -ShowInstallPrompt No -AppName Claude_x64_MSIX -DeploymentType Install -DeployMode Interactive -DeferType Silent -DeferTimesValue 0 -AppsClose None -RestartPrompt No -CDSeconds 600 -RemoveShortcut No -DesktopShortcut None -LoggedOut No; Exit $LastExitCode }
```

### Pre-registered expected conclusion (verbatim from owner)

> Suspicious execution characteristics observed, but the available command-line
> evidence alone is insufficient to establish malicious intent. Additional
> process, signer, parent, file, network and deployment-context evidence is
> required.

### Signals NivXRay must surface from command line alone (Phase-A capability)

- T1562.001 · Impair Defenses: Disable or Modify Tools (ExecutionPolicy Bypass)
- T1564.003 · Hide Artifacts: Hidden Window (`-WindowStyle Hidden`)
- Deployment-context strings: `IMECache`, `install.ps1`, `Deploy-Application.ps1`,
  `-AppName Claude_x64_MSIX`, `-DeploymentType Install`

### Signals the verdict layer must NOT collapse into (Phase-A safety gate)

- Do not label `Malicious` from command-line alone
- Do not manufacture a parent-child claim (WINWORD, Outlook, IntuneManagementExtension,
  etc.) that the input does not evidence
- Do not stop at "PowerShell + Bypass = Malicious"

### Phase-B (post-P2) capability under test

Once behavioural evidence ingestion (ADR-0023) is live, NivXRay is expected to
extend the investigation along the Cruise-Missile evidence chain:

- **WHO** launched the PowerShell process? (parent image + PPID · session · user)
- **WHAT** launched *that* process? (grandparent chain)
- **WHAT** script executed? (path + signer + hash of `Deploy-Application.ps1`)
- **WHAT** files did it create? (Sysmon 11 file-create events)
- **WHAT** processes did it spawn? (Sysmon 1 child processes)
- **WHAT** registry keys changed? (Sysmon 12/13 registry events)
- **DID** it communicate externally? (Sysmon 3 network / Sysmon 22 DNS)
- **WHO** signed the executable / script? (Authenticode)
- **IS** this behaviour normal for the observed deployment platform?
- **WHAT** ATT&CK evidence emerges from the full chain?

Only after those questions are answered may the verdict move away from
"Suspicious · additional evidence required".

### Success criterion (Phase-B)

Given the same two command-line inputs plus a **legitimate deployment
telemetry bundle** (IntuneManagementExtension parent · signed script · no
suspicious child processes · no external network), NivXRay must:

- Preserve the T1562.001 + T1564.003 evidence
- Retrieve the parent-signer + deployment-context evidence from the
  telemetry bundle
- Emit a verdict in the range **Benign** / **Suspicious (contextual)** — NOT
  `Malicious`
- Emit an analyst narrative that explicitly says why the suspicious
  behaviour resolves as expected enterprise deployment given the
  correlated evidence

Given the same command-line inputs plus a **hostile telemetry bundle**
(unsigned script · unusual parent · child processes contacting external
IPs · registry persistence writes), the same NivXRay pipeline must escalate
to `Malicious` with the specific chain elements cited as evidence.

This is the "suspicious behaviour ≠ malicious verdict" test that separates a
serious investigation platform from an indicator detector. It is the
canonical Phase-B falsification case.

---

*End of Phase-B / Post-P2 test-case register. Additions require owner
sign-off recorded as a new pb-NN entry.*
