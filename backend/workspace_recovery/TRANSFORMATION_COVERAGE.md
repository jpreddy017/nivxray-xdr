# Workspace Transformation Coverage — Live Matrix

**Contract**: every milestone (M1 – M10) appends a row to this matrix.
**Coverage is measured by real-world decode correctness, not by
implementation completeness.**

Columns:

- **Transformation** — name of the deterministic operation
- **Implemented** — code exists in `backend/workspace/convergence/` or
  is invoked deterministically by the Convergence Engine
- **Certified** — passes on real-world Level 2 samples (unseen inputs,
  not only the 11-sample corpus)
- **Notes** — free-form (regressions, corner cases, limitations)

The Convergence Engine is not considered production-ready until every
row in this matrix is either Certified or explicitly deferred to a
future workstream with a documented rationale.

---

## Coverage Matrix (append to during each milestone)

| Transformation | Implemented | Certified | Notes |
|----------------|:-----------:|:---------:|-------|
| Base64 | ⏳ | ⏳ | M1 target |
| UTF-16LE | ⏳ | ⏳ | S001 anchor · M6 must certify |
| UTF-8 | ⏳ | ⏳ |  |
| Hex | ⏳ | ⏳ |  |
| Octal | ⏳ | ⏳ |  |
| Binary | ⏳ | ⏳ |  |
| ASCII decimal | ⏳ | ⏳ |  |
| Gzip | ⏳ | ⏳ | S05 anchor |
| Deflate | ⏳ | ⏳ |  |
| Brotli | ⏳ | ⏳ |  |
| RC4 | ⏳ | ⏳ | S07 anchor |
| AES | ⏳ | ⏳ |  |
| ROT-N | ⏳ | ⏳ |  |
| Caesar | ⏳ | ⏳ |  |
| XOR (single-byte) | ⏳ | ⏳ | S06 anchor |
| XOR (multi-byte) | ⏳ | ⏳ |  |
| PowerShell aliases (post-decode) | ⏳ | ⏳ | must NOT hijack primary chain |
| PowerShell backticks | ✅ | ⏳ | M3 · `content-backtick-escape-strip` (outside strings, guards EOL) |
| PowerShell format operator `-f` | ⏳ | ⏳ |  |
| PowerShell join operator `-join` | ✅ | ⏳ | M2 · quote-safe literal folding; `-join` operator + `[String]::Join()` |
| PowerShell string concatenation | ✅ | ⏳ | M2 · S04 anchor advanced; `'a'+'b'` and `"a"+"b"` (interpolation-safe) |
| CMD caret escape | ⏳ | ⏳ | S03 anchor |
| CMD runtime reconstruction | ⏳ | ⏳ |  |
| Environment-variable substitution | ✅ | ⏳ | M3 · 13 static Windows defaults; user/host-specific vars excluded by design |
| Array slicing / index tricks | ✅ | ⏳ | M3 · single/range/list on SQ literals; enables S013 |
| Unicode normalization | ⏳ | ⏳ | S08 anchor |
| Char-code array (JS · decimal) | ⏳ | ⏳ |  |
| Bash pipeline `rev` / `xxd` / `tr` | ⏳ | ⏳ | S02 anchor |

**Legend**: ⏳ pending · ✅ implemented · 🏆 certified · ⛔ deferred

## Real-World Sample Ledger (Level 2 · append to during each milestone)

_Every unseen real-world sample tested during a milestone gets an entry
here. This is the source of truth for "how many real-world samples now
decode correctly?" — the third of the five mandatory milestone
questions._

<!-- rows appended by the implementing agent per milestone -->
