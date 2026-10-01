# B5 | EID 5 BLOCKED | SYSMON SOURCE XML PROVENANCE INVESTIGATION

Read-only workspace investigation. **Nothing was executed on the endpoint.**
No deploy, no Sysmon change, no service restart, no EID 5 enablement, no
historical termination reconstruction.

Trigger: the corrected enablement script HALTED at G2 twice on
DESKTOP-A9HGFJJ (`config XML not found`), which is the fail-closed
behaviour working as designed. Sysmon 15.22 still names
`C:\NivX\sysmon\nivx-w1-sysmon.xml` as its configuration file, but that
file is gone from disk.

---

## 1 | ORIGIN OF THE FILE — FOUND, AND IT IS THE ONLY WRITER

`/app/memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md` section **1.3 "Write the
configuration - exactly the event ids the DSM accepts"** contains the
here-string that created the file:

```
@'
<Sysmon schemaversion="4.90">
...
'@ | Set-Content -Encoding UTF8 C:\NivX\sysmon\nivx-w1-sysmon.xml
```

Exhaustive search of the workspace for anything else that writes, copies,
generates or packages that file:

| searched | result |
|---|---|
| `Set-Content`/`Copy-Item` targeting `nivx-w1-sysmon.xml` | only `memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md` §1.3 |
| `agents/nivxforge-windows/Install-NivXForgeSensor.ps1` | **zero** Sysmon references — the sensor installer never deploys a Sysmon config |
| `agents/nivxforge-windows/build/build_windows_installer.ps1` | no Sysmon config payload |
| `scripts/`, `backend/`, provisioning/deployment code | no generator, no template, no packaged copy |
| other repo `.xml` Sysmon configs | none exist |

So the file was **hand-written once on the laptop from a document**, never
from a build artefact. There is no second authoritative copy in this
workspace, which is exactly why its disappearance is unrecoverable from
here.

## 2 | CAN THE CANDIDATE BE TIED TO THE LIVE ConfigHash? — NO

Live `ConfigHash` (Sysmon's SHA-256 of the configuration **file bytes**):

```
0BAE60B361373E09C3B834EE68CA52B9412D9A9239036F25DE5A2EBC39C9A7AC
```

The §1.3 here-string was reconstructed and hashed under every plausible
Windows write encoding. `Set-Content -Encoding UTF8` on PowerShell 5.1
writes UTF-8 **with BOM**, CRLF line endings and one trailing terminator,
so that is the primary candidate:

| candidate | SHA-256 | bytes |
|---|---|---|
| BOM + CRLF + trailing CRLF (PS 5.1 default) | `6dd4204650352c72dc9c075ae0780425dbc8016c99954b3abecc78c85c4c5052` | 1845 |
| BOM + CRLF, no trailing | `17604a4718602c1e102d614e5d170dc06316f9d3bf7c54872dd96980bc68e284` | 1843 |
| no BOM + CRLF + trailing | `497132c55a0c31a18799fb03dc6c112e6aa25227c1822162b66a4d74fbb58b44` | 1842 |
| no BOM + LF + trailing | `9efe1f4e129b69af21d5895baa99a67785013f0790f893f3143f499218ed6ddd` | 1810 |

A wider sweep of **96 variants** (comments kept/stripped, trailing
whitespace normalised, `HashAlgorithms` order `SHA256,MD5` vs
`MD5,SHA256`, `CheckRevocation` True/False/absent, CRLF/LF, BOM/no-BOM,
trailing terminator/none) produced **no match** to `0BAE60B3…`.

**Conclusion: `ORIGINAL_SYSMON_XML_NOT_RECOVERED`.** The documented XML is
the provenance of *intent*, not the byte-identical artefact Sysmon hashed.
The on-disk file had drifted from the document (re-indentation, edited
comments, or a later hand edit). Nothing in this workspace records the
file's own SHA-256 — §1.3 asked for it to be sent back, and it was never
captured here.

## 3 | SEMANTIC RECOVERY — COMPLETE AND CORROBORATED

Every event class in the live `Sysmon64.exe -c` dump matches the
documented intent, 19 / 19, with no disagreement:

| event class | documented | live `-c` | agree |
|---|---|---|---|
| ProcessCreate | exclude | exclude | yes |
| NetworkConnect | exclude | exclude | yes |
| FileCreate | exclude | exclude | yes |
| RegistryEvent | exclude | exclude | yes |
| DnsQuery | exclude | exclude | yes |
| **ProcessTerminate** | **include** | **include** | **yes** |
| DriverLoad | include | include | yes |
| ImageLoad | include | include | yes |
| CreateRemoteThread | include | include | yes |
| RawAccessRead | include | include | yes |
| ProcessAccess | include | include | yes |
| FileCreateTime | include | include | yes |
| FileCreateStreamHash | include | include | yes |
| PipeEvent | include | include | yes |
| WmiEvent | include | include | yes |
| FileDelete | include | include | yes |
| ClipboardChange | include | include | yes |
| ProcessTampering | include | include | yes |
| FileDeleteDetected | include | include | yes |
| HashAlgorithms | `SHA256,MD5` | `MD5,SHA256` (set-equal, Sysmon prints its own order) | yes |

Exact relevant section, as documented:

```xml
    <!-- LOG NOTHING for every unsupported event id: an empty
         onmatch="include" rule matches nothing. -->
    <ProcessTerminate onmatch="include"/>         <!-- 5  -->
```

`onmatch="include"` with **no child rules matches nothing**, so EID 5 is
not generated. That is the confirmed root cause, now established from the
running configuration and not only from the document.

One caveat stated rather than assumed: the owner's `-c` output shows only
top-level classes. In *this* configuration every element is empty, so
there is nothing nested to lose — but that is an inference from the
document, not from the dump. A full verbatim `-c` transcript would settle
it. (`NativeCommandError` at the start is PowerShell treating Sysmon's
stderr banner as an error record; Sysmon ran and printed its whole
configuration. Nothing was applied.)

## 4 | EXACT ROLLBACK — **CANNOT** BE GUARANTEED BY FILE TODAY

The previous script's safety model was "restore the original XML byte for
byte". That original does not exist, so the model is void and the script
must not be re-run as written.

What *does* still exist, and is authoritative:

* the **ACTIVE rule blob** in
  `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\Rules`,
  fingerprinted in the accepted PRE baseline as
  `6eecc58c62d90305b3e989adbffa92060cf22e315a04a7da28683b72aa0cba8f`.

That fingerprint is the decisive lever, because **the rule blob is
compiled from the rules, not from the file text**: comments, indentation,
attribute order and encoding do not survive compilation. So a
semantically identical XML should compile to the *same* blob and produce
the *same* fingerprint — which converts "did we reconstruct the config
correctly?" from an opinion into a cryptographic test.

It is a test that requires one apply, and that is a real change. It is
therefore proposed, not performed.

## 5 | FAIL-CLOSED RECOVERY / TRANSITION DESIGN (proposal only)

### Option A — two-phase, reconstruction proven BEFORE the EID 5 change (recommended)

**Phase R1 — reconstruction fidelity proof. ProcessTerminate stays
`include`. No EID 5 change.**

1. Export the live rule blob (`reg export …\SysmonDrv\Parameters`) and
   re-read the active fingerprint; require it to equal `6eecc58c…`,
   else HALT.
2. Write `C:\NivX\sysmon\nivx-w1-sysmon.RESTORED-PRE.xml` from §1.3
   **verbatim and reviewed by the owner first**, with ProcessTerminate
   still `include`.
3. Apply it, require exit code 0, then re-read the active fingerprint.
   * **equals `6eecc58c…`** -> PROVEN: the reconstruction compiles to the
     exact accepted PRE rule state. From that moment a byte-exact file
     rollback exists again and the EID 5 change becomes safe.
   * **differs** -> HALT and report. Do not touch EID 5. The rule state
     has moved and the only remaining route back is a registry import
     (see the residual risk below), which needs owner sign-off.

**Phase R2 — the one-line EID 5 change**, using the already-approved gate
set (G1 elevation, G3 accepted-fingerprint gate now pointed at the R1
fingerprint, G4 verified backup, G5 single-line structural proof, G6
apply-exit gate, G7 fingerprint-moved gate, G8 live-state gate, then the
5 marked processes and the ProcessGuid pairing proof). Rollback is the R1
file, whose fidelity was proven cryptographically in R1.

**Residual risk, stated plainly:** Phase R1 performs an apply. If the
fingerprint does not come back as `6eecc58c…`, restoring the exact PRE
blob would mean importing the exported `.reg` — and Sysmon reads its
rules at service start / config apply, so a registry import most likely
needs a **service restart** to take effect. Service restarts are
currently forbidden, so that path is **unproven**. The honest position:
R1 has a small but non-zero chance of leaving the endpoint in a
semantically-equivalent-but-not-fingerprint-identical state until a
restart is authorised.

### Option B — zero-apply hold

Leave EID 5 disabled and look for the original XML outside this
workspace first: the laptop's own backup/Recycle Bin/File History,
OneDrive version history, `%TEMP%`, any USB or second machine used during
W1, or the original chat transcript where the file hash was reported. If
the file (or its recorded SHA-256 `0BAE60B3…`) is found, exact rollback is
restored with **zero** endpoint change and Option A's residual risk
disappears. Cost: process lifetime stays honestly
`PROCESS_LIFETIME_UNKNOWN` for longer.

### Option C — registry-import rollback only (not recommended)

Treat the exported `.reg` as the rollback and skip the reconstruction
proof. Rejected: its effectiveness depends on a service restart that is
out of scope, so the rollback would be asserted rather than proven — the
exact failure mode this programme exists to avoid.

### Not on the table

Silently synthesising a "close enough" replacement config and applying
it. A config that cannot be tied to the accepted PRE state is a new
baseline wearing the old one's name, and it would quietly invalidate the
PRE/POST comparison B5 exists to produce.

## 6 | REQUESTED RETURN FIELDS

| field | value |
|---|---|
| `ORIGINAL_SYSMON_XML_PROVENANCE` | `memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md` §1.3 here-string, hand-written to disk once; no installer, build or provisioning artefact exists |
| `CANDIDATE_XML_SHA256` | `6dd4204650352c72dc9c075ae0780425dbc8016c99954b3abecc78c85c4c5052` (PS 5.1 default write); 95 further variants enumerated |
| `TIED_TO_LIVE_CONFIGHASH` | **NO** — live `0BAE60B3…` matched none of 96 byte-level reconstructions |
| `PROCESSTERMINATE_SECTION` | `<ProcessTerminate onmatch="include"/>` with no child rules — matches nothing, so EID 5 is not generated |
| `SEMANTIC_EQUIVALENCE` | 19/19 event classes and the hash-algorithm set agree with the live dump |
| `EXACT_ROLLBACK_GUARANTEED` | **NO** by file today. Recoverable via Option A Phase R1, where `6eecc58c…` equality proves the reconstruction compiles to the accepted PRE rule state |
| `RECOVERY_STATUS` | `ORIGINAL_SYSMON_XML_NOT_RECOVERED` |
| `ENDPOINT_CHANGED` | NO |
| `DEPLOYED` | NO |
| `EID5_STATUS` | still disabled; enablement blocked pending owner choice of Option A or B |
