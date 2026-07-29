# ADR-0007 — Verdict-Evidence Gating

- **Status:** Accepted (2026-02-28, with amendment · implementation not yet authorised)
- **Date:** 2026-02-28
- **Deciders:** Operator (product owner) · Emergent (proposer)
- **Threshold met:** 4 independent real-world observations (P-VERDICT-STRUCTURAL)
- **Amendment note:** Operator broadened the rule from "decoded content" to
  "evidence-backed behavioral or semantic indicators" to future-proof it for
  artifact types where "content" is not the useful abstraction (e.g. shellcode,
  memory dumps, binary payloads).

## 1 · Evidence supporting this proposal

Four independent workspace_cases exhibit the same defect: the verdict is driven
by the *encoding structure* of the input, not by the decoded content. All four
are logged in `REAL_WORLD_LOG.md` with the full 9-category review.

| Case | Artifact | Decoded content | Verdict | Defect |
|---|---|---|---|---|
| 0005 | Base32 → Base64 → Base64 blob | "SOC Challenge: If you can read this, you decoded it correctly." | Suspicious 80 | Verdict driven by "long base64 blob" structural rule |
| 0006 | `aGVsbG8gd29ybGQ=` | "hello world" | Suspicious 45 (summary) / Partial Decode (card) | Verdict on 11-char benign ASCII |
| 0013 | b64-UTF-16 encoded PS | "start-process notepad" | Malicious 70 (summary) / Partial Decode (card) | Encoded-form → Malicious ignoring benign decoded body |
| 0017 | `powershell -e ABC` | "ABC" | Malicious 70 | `powershell -e` LOLBIN + T1027.010 → verdict without any malicious signal in decoded content |

**Common thread:** encoding-form indicators (base32/base64 length ≥ threshold,
`-e`/`-encodedcommand`, LOLBIN presence) fire verdict scores without a gate that
asks "does the *decoded content* support this severity?"

## 2 · Governance rule (Accepted with amendment 2026-02-28)

A Verdict of `Suspicious` or higher MUST be supported by at least one
**evidence-backed behavioral or semantic indicator**. Encoding or obfuscation
alone cannot produce Suspicious/Malicious.

### 2.1 Acceptable behavioral / semantic indicators (any one satisfies the gate)

- Decoded URLs, IPs, or domains present in the decoded body
- API imports or Win32 API resolution (e.g. `InternetOpen`, `VirtualAlloc`)
- Shellcode characteristics (MSFvenom prologue, WinINet strings, syscall
  stubs)
- Registry tampering (writes to Run/RunOnce, service keys, security policy)
- PowerShell execution behavior (`Invoke-Expression`, download-cradle,
  `Start-BitsTransfer`, DownloadString)
- LOLBin abuse (concrete chained invocation, not mere presence of the binary
  name)
- AMSI / ScriptBlockLogging / Defender bypass (`Enable-*Logging`
  reconstruction, `[Ref].Assembly.GetType(...)` reflection into AMSI,
  ETW patching)
- Encoded payload only if the decoded payload itself demonstrates any of
  the above suspicious behaviors

### 2.2 Structural indicators (contribute to confidence, cannot solely determine verdict)

- Base64 / Base32 form detected
- High entropy / low printable ratio
- UTF-16LE PowerShell EncodedCommand form
- YARA structural signatures (form-based, not behavior-based)
- Command-line length or nesting depth
- LOLBIN presence *by name only* (e.g. `powershell.exe` in a path without
  suspicious invocation context)

### 2.3 Rule (formal)

Tag each indicator with an `evidence_class`:
- `behavioral` — matches §2.1 categories (drives verdict).
- `structural` — matches §2.2 categories (contributes to confidence only).

Then:
- Verdict ≥ `Suspicious` requires ≥ 1 `behavioral` indicator.
- Verdict = `Malicious` requires ≥ 1 `behavioral` indicator with `kind=positive`.
- Otherwise the verdict caps at `Informational` or `Partial Decode` and the
  structural signals surface in explanation only.

## 3 · Explicit non-goals

- Not proposing to change existing structural indicators — they remain valid
  *inputs* to the verdict; they just cannot solely drive it.
- Not proposing changes to the decoder pipeline.
- Not proposing new indicator types.

## 4 · Scope

- Backend verdict-composition path only.
- Requires updating verdict-scoring logic AND the summary-block composer to
  respect the gate.
- Zero changes to NivXForge frontend or the analyst API contract (the response
  shape stays the same; only the verdict label/confidence changes for cases
  that were structurally-driven).

## 5 · Testing before Accepted

Before promotion from Proposed → Accepted, the operator MUST review:

1. Each of Cases 0005, 0006, 0013, 0017 would produce a lower/appropriate
   verdict under the proposed gate.
2. A representative "true positive" case (e.g. Case 0009 — BITS + URL +
   Malicious 90) would remain unchanged, because it has content-source
   indicators (URL in decoded output).
3. Regression: full nivxforge test suite must remain 49/49 PASS.

## 6 · Approval gate

Do NOT implement until this ADR is marked **Accepted** by the operator and a
Phase-1a scope is defined.
