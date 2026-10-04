# W1 · PHASE 2.3 COMPATIBILITY HOTFIX — Windows PowerShell 5.1 parser defect

**Owner result accepted: Phase 2.3 = FAIL. Root cause confirmed and
reproduced here. It was our defect, in the committed artifact.**

The transfer was clean — the laptop's SHA256 matched the canonical LF artifact
byte-for-byte. The fault is that a BOM-less `.ps1` is decoded by Windows
PowerShell 5.1 with the **machine ANSI code page**, so the 5 non-ASCII bytes
in the file (em dashes and a middle dot, all inside comments and two `throw`
strings) became mojibake and broke quoting.

---

## 1 · ROOT CAUSE, REPRODUCED

A PowerShell 7.4.6 runtime was installed in this pod and the failure was
reproduced deterministically by decoding the **exact failed artifact** with
Windows-1252 before parsing it
(`scripts/windows/Test-ForwarderParse.ps1`):

```
DecodedAs     : windows-1252      DecodedAs     : utf-8
NonAsciiBytes : 5                 NonAsciiBytes : 5
ParserErrors  : 13                ParserErrors  : 0
line 84: Unexpected token 'telemetry' in expression or statement.
line 83: Missing closing '}' in statement block or type definition.
line 198: Unexpected token '" + "' in expression or statement.
```

Line 84 and line 198 are **exactly** the two failures the owner reported. The
21/21 contract test could not have caught this: it validated the server-side
envelope contract, never the script's own parse — a limitation that was
disclosed and has now cost a cycle, so it is closed below.

---

## 2 · THE FIX (narrow, no security property weakened)

`scripts/windows/NivXRay-SysmonForwarder.ps1`

1. **pure ASCII, 0 non-ASCII bytes.** Em dashes and the middle dot became
   ASCII `-`. The file now parses **identically under every code page** —
   verified as utf-8, windows-1252, iso-8859-1 and windows-1251 — so the fix
   does not depend on adding a BOM or on the laptop's locale.

Four further 5.1-hostile constructs were found while auditing and corrected
in the same pass, because each would have failed *later*, with a credential
in play:

2. `Add-Member BatchSize 200 -Force` (positional) → explicit
   `-NotePropertyName` / `-NotePropertyValue`. Positional binding to
   `Add-Member`'s NoteProperty parameter set is not dependable across hosts.
3. **`Set-StrictMode -Version Latest` + optional properties.** Reading
   `$cfg.$f`, `$receipt.accepted`, `$o.status` or `$state.LastRecordId`
   *throws* under StrictMode when the field is absent — i.e. the config-error
   and server-refusal paths would have crashed instead of reporting. All
   optional reads now go through a new `Get-Prop` helper.
4. **The ingest route wraps its receipt in `data`.** The script read
   `$receipt.accepted` at the top level, so the receipt would have been
   misread and — worse — the refusal loop would have seen nothing. It now
   unwraps `data` when present. This was a genuine Phase 4 bug found before
   Phase 4.
5. `Tls12 -bor 12288` (TLS 1.3) is now assigned inside a try/catch that falls
   back to TLS 1.2, since assigning an OS-unsupported protocol value throws.
   The floor is still TLS 1.2 and no certificate validation is bypassed.
6. `Write-Log` → `Write-ForwarderLog` (PSScriptAnalyzer flags `Write-Log` as
   shadowing a cmdlet name present on some hosts).
7. `EventData` is now read via `SelectSingleNode`/`ChildNodes` instead of
   dotted XML property access, which also throws under StrictMode on a record
   that carries no `EventData`.

**Unchanged, and asserted by the gate:** HTTPS-only guard, TLS floor, no
certificate-validation callback, the key-file ACL refusal, key never logged,
tenant authority, `declared_source: microsoft-sysmon`, the 7 supported event
ids, verbatim EventData, `_nivx*` refusal, `source_event_id` format,
bookmark-advances-only-after-the-server-accounted semantics, `refused.jsonl`
and `gap.jsonl`.

---

## 3 · THE GATE THAT WOULD HAVE CAUGHT IT

`backend/tests/test_w1_forwarder_source_gate.py` — **16 passed**:

* every `scripts/windows/*.ps1` is **pure ASCII**, LF, no BOM;
* the forwarder **parses** when decoded as utf-8 / windows-1252 /
  iso-8859-1 / windows-1251 (real PowerShell parser, via
  `Test-ForwarderParse.ps1`);
* **PSScriptAnalyzer `PSUseCompatibleSyntax` targeting 5.1 and 7.0 reports NO
  FINDINGS** for all three scripts;
* the security properties above are still present in the source, and no
  `Write-ForwarderLog`/`throw` line can carry the key;
* the 5.1 pitfalls are absent (`Add-Member -NotePropertyName` present, no
  StrictMode-unsafe property reads, `data` unwrapping present).

### And the replica gap is closed

`scripts/windows/Test-ForwarderEnvelope.ps1` loads `ConvertTo-RawEvent`,
`ConvertTo-Envelope` and `Get-Prop` **out of the real artifact via the
PowerShell AST** and builds envelopes from synthetic Windows EventLog XML.
`p0_w1_forwarder_contract_check.py` now **posts those PowerShell-generated
envelopes** to the live route instead of a Python replica, and additionally
proves:

* a source field named `_nivx_collector_id` — an attempt to impersonate NivX
  transport provenance — is **dropped, not renamed**;
* EventData is carried verbatim (29 fields on the EID 1 record).

**Contract test: 24/24 PASS** (was 21/21; the 3 new checks are the
PowerShell-generated-envelope assertions).

---

## 4 · HONEST LIMIT

This pod has **PowerShell 7.4.6 on Linux ARM64. It is NOT Windows PowerShell
5.1.** What is proven here is: syntax parses, PSScriptAnalyzer finds no
5.1 syntax incompatibility, the file is code-page-proof, and the artifact's
own envelope code satisfies the live route. **Runtime compatibility on
Windows PowerShell 5.1.19041.6456 is proven only by your `-DryRun` on the
laptop.** I am not claiming it from a Linux parse.

---

## 5 · CORRECTED ARTIFACT

```
path              scripts/windows/NivXRay-SysmonForwarder.ps1
bytes             15659
lines             400
encoding          ASCII (0 non-ASCII bytes), no BOM, LF (0 CR bytes)
SHA256 (LF)       c969d5e0092dc5178ad522ec102979313c7864a3ff9264fd809724a1e0eacc5b
SHA256 (CRLF)     9c54a79eea2134585bdec35b81a2fdadc62b9a966777ec685218b44dd7dbdc54
SHA256 (CRLF+BOM) 1bbd213dd5c2886deafdcb2280b58c8eeadddcdbc9daddf1daef7ad00664fd6a
superseded        586c4f12737feb0a636a7ed0ebef94f788cb1b205586c4f23b72c7ed03c63413 (FAILED 5.1 parse)
```

Diff scope: `scripts/windows/NivXRay-SysmonForwarder.ps1` (+the two new
PowerShell test scripts, the source gate, and the contract check's
PowerShell-generated-envelope wiring). No collector, `forwarder.json`,
`ingest.key` or tenant configuration was created. `_COLLECTED_PRODUCTS`
remains `{"linux"}`.

**STOP — corrected artifact handed off. W1 remains NOT CLOSED.**
