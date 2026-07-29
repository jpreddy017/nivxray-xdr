# ADR 0004 — MITRE Attribution Accuracy for PowerShell XOR

- **Status:** Proposed  (draft — awaiting review)
- **Date:** 2026-02-28
- **Author(s):** e1 (evidence review)
- **Supersedes:** —
- **Superseded by:** —

_This ADR is an **attribution accuracy enhancement**, not a decoder
expansion, not a new analytical capability, and not a new engine. It
narrows a mislabelling in the existing MITRE mapping so analysts can
trust the ATT&CK tag they see._

---

## 1 · Problem Statement

The MITRE technique `T1027.013 · Encrypted/Encoded File · RC4` is
currently being applied to inputs that are **not** RC4 encryption at
all. Specifically, PowerShell integer-array + inline-XOR one-liners
(Case 0001 archetype) trip the generic XOR-cipher signature in
`crypto-detect` and are labelled T1027.013. The result is:

- Analysts see "RC4 shellcode" attribution on scripts that are
  neither RC4 nor shellcode.
- Downstream expectations set by the label (binary blob, stream
  cipher, likely shellcode payload) do not match the actual input
  (PowerShell script, character-array XOR, likely CLI text payload).
- The `reached_shellcode` metric appears misleadingly low (0.5%)
  because the label was mis-applied in 85% of cases.

This is a **Charter Rule 3 violation** — the conclusion (T1027.013)
is not backed by evidence in the specific inputs it is applied to.

## 2 · Supporting Evidence

Source: `/app/memory/DIAGNOSTIC_RC4_SHELLCODE_2026-02-28.md`.

- **220 rows** currently labelled `MITRE:T1027.013`.
- **187 rows (85%)** contain `powershell-xor-inline-key` in their
  chain — PowerShell string-XOR, not RC4 stream-cipher-on-binary.
- **13 rows (5.9%)** use `rc4-inline-decrypt` — the actual RC4 path.
- **1 row (0.5%)** progresses to `family-meterpreter` — a genuine
  shellcode terminal.
- Sample non-RC4 payload heads (from the diagnostic report):
  ```
  powershell -NonInter "((97,68,95,66,83,27,126,89,69,66,...
  powershell -nop -w hidden "((88,84,73,49,57,120,102,99,49,60,...
  ((\n    125, 88, 67, 94, 79, 7, 98, 69, 89, 94, 10, 13, 122, ...
  ```
- The **T1027.013 population is dominated by a mislabelled family.**
  Correct attributions for the mislabelled cases are:
  - `T1027.010 · Command Obfuscation`  (primary)
  - `T1140 · Deobfuscate/Decode Files or Information`  (secondary,
    when applicable)

Missing-Evidence tally row this ADR decrements: to be added on
acceptance — "MITRE attribution accuracy on obfuscation techniques"
(counts of mislabelled attributions).

## 3 · Proposed Change

Introduce a **deterministic input-shape discriminator** at the point
where `crypto-detect` currently emits T1027.013. The discriminator
distinguishes:

- **Shape A · PowerShell string-XOR** — presence of `powershell` /
  `pwsh` command head + integer-array literal + `-bxor` + `[char]` /
  `[Char]` conversion + IEX-style pipeline. Attribute as
  `T1027.010` and, when a `-bxor` key is recovered, additionally
  `T1140`. **Do NOT emit T1027.013.**
- **Shape B · True RC4** — invocation of the `rc4-inline-decrypt`
  decoder OR input to a chain that treats bytes as a binary stream
  through an RC4 key-scheduling / PRGA construction. Attribute as
  `T1027.013`.
- **Shape C · Ambiguous** — none of the invariants for A or B
  satisfied. Emit no RC4 or shellcode-specific attribution; leave
  attribution to downstream engines.

Concrete first-cut implementation:

- Lives entirely under `/app/backend/nivxforge/` (new module, e.g.
  `nivxforge/attribution/mitre_shape.py`).
- Called by NivXForge downstream orchestration (not by Workspace).
  In Phase 0 the router remains dormant, so this discriminator is
  library code only until a follow-up ADR reverses Decision A1.
- **No modification to `crypto-detect` in Workspace.** The Workspace
  behavior remains identical for as long as the NivXForge router is
  dormant. When the router is eventually mounted (separate ADR), the
  Workspace `crypto-detect` output can be re-labelled downstream
  without altering the Workspace op itself.

**Explicit non-goals:**

- ❌ Not a new decoder.
- ❌ Not a new engine.
- ❌ Not a change to the RC4 or XOR decoding logic.
- ❌ Not a modification to any Workspace source file.
- ✅ Only a discriminator that maps input shape → correct MITRE ID.

## 4 · Alternatives Considered

**(a) Do nothing.**
Rejected. Charter Rule 3 is violated for the 187 mislabelled rows,
and analyst trust in ATT&CK attribution degrades every time the
label doesn't match the payload.

**(b) Modify `crypto-detect` in Workspace directly.**
Rejected. Workspace Protection Policy forbids it without a Workspace
ADR. Also, `crypto-detect` is used by many chains — a global change
risks regressions on the true-RC4 cases we want to preserve.

**(c) Refine the `crypto-detect` regex to be stricter.**
Rejected as insufficient. The problem is not the XOR signature
itself; it's the assumption that any XOR = RC4. Shape discrimination
is the right level; regex refinement is the wrong level.

**(d) Add a downstream re-labeller in Workspace only when
`reached_shellcode == False`.**
Rejected. This would still be a Workspace modification. Doing it in
NivXForge preserves the isolation boundary.

**(e) Wait for more evidence before acting.**
Rejected. The evidence is already sufficient: 187 concrete rows,
one diagnostic report, one confirmed real case (Case 0001) matching
the mislabelled shape exactly. The fix is small, deterministic, and
reversible.

## 5 · Workspace Impact

- **Is any Workspace file affected?** **No.**
- **Files modified in Workspace:** zero.
- All code lives under `/app/backend/nivxforge/attribution/`
  (new module).
- Decision A1 remains in force. This ADR does NOT propose mounting
  the NivXForge router. The discriminator is library code with no
  runtime coupling until a separate future ADR authorises the mount.
- **Compatibility contract:** identical to Phase 0 — verified by
  `test_workspace_isolation.py` and
  `test_workspace_compatibility.py`.

**Structural test that will prove non-mutation:** same as ADR-0001 —
the two Phase 0 compatibility tests remain the release gate.

## 6 · Success Criteria

- **Regression proof:** unit tests under
  `nivxforge/tests/test_mitre_shape.py` that assert:
  - Case 0001's exact input classifies as Shape A → attributes
    include `T1027.010` and `T1140`, and do NOT include `T1027.013`.
  - A canonical RC4-on-binary-blob input classifies as Shape B →
    attributes include `T1027.013`.
  - An ambiguous input classifies as Shape C → no RC4-specific
    attribution emitted.
  - Zero false-positive attribution across a fixture set drawn
    from the mislabelled 187 rows (fixtures must be sanitized
    before being committed).
- **Benchmark proof:** discriminator runs in <5 ms per input on the
  reference container.
- **Compatibility proof:** all Phase 0 tests remain green. Workspace
  regression suite remains green.
- **Attribution accuracy proof:** on a re-run classification pass
  against the 220-row diagnostic corpus, expected re-distribution:
  ~187 rows → T1027.010 (+ T1140), ~13 rows remain T1027.013,
  ~20 rows Shape C (no RC4-specific tag). This becomes the
  regression fixture for future engine changes.
- **Missing-Evidence tally row this ADR decrements:** "MITRE
  attribution accuracy on obfuscation techniques" — expected drop
  from 187 mislabelled → 0 mislabelled in the diagnostic corpus.

## 7 · Consequences

- **Unlocks:** analyst-visible ATT&CK labels become evidence-backed
  for this family. Downstream telemetry / dashboards that key on
  T1027.013 begin to reflect the true RC4-shellcode population.
- **Forbids (until follow-up ADR):** no change to Workspace's
  `crypto-detect` output surface. Workspace continues to emit
  whatever it does today until an explicit Workspace ADR reverses
  that.
- **Ordering note:** independent of ADR-0001 but complementary. If
  both accepted, ADR-0004 is smaller and can ship first as a
  low-risk win; ADR-0001's framework benefits from having an
  accurate T1027.010 population to measure coverage against.

---

## Acceptance checklist (to complete before status → Accepted)

- [ ] Human review of §2 evidence citations against
  `DIAGNOSTIC_RC4_SHELLCODE_2026-02-28.md`.
- [ ] Confirmation that the three shape classes (A / B / C) cover
  the observed corpus without adding new heuristics beyond the
  diagnostic's findings.
- [ ] Sanitisation policy agreed for fixture inputs (redact any PII
  or customer-identifying content before committing tests).
- [ ] `IMPLEMENTATION_ROADMAP.md §3` entry drafted (do not commit
  until ADR is Accepted).
- [ ] `DECISION_LOG.md` row prepared (do not commit until ADR is
  Accepted).
