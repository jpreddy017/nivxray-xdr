# ADR-0007 — Verdict-Evidence Gating

- **Status:** Proposed
- **Date:** 2026-02-28
- **Deciders:** Operator (product owner) · Emergent (proposer)
- **Threshold met:** 4 independent real-world observations (P-VERDICT-STRUCTURAL)

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

## 2 · Proposed governance rule

A Verdict of `Suspicious` or higher MUST be supported by at least one indicator
whose evidence source is the **decoded content** (or observable metadata about
that content — extracted IOCs, API imports, embedded strings), not the
**encoding form** alone.

Formally, tag each indicator with an `evidence_class`:
- `structural` — derived from the encoding form (base64-blob-length, LOLBIN
  presence, encoding-command flag, encoding-recipe-peel).
- `content` — derived from decoded content (URL/IP/domain in output,
  process-injection pattern, shellcode signature, defender-tamper string,
  registry write, etc.).

Then:
- Verdict ≥ Suspicious requires ≥ 1 `content` indicator.
- Verdict = Malicious requires ≥ 1 `content` indicator with `kind=positive`.
- Otherwise the verdict caps at `Informational` or `Partial Decode`.

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
