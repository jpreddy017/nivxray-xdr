# NivXRay · ARB Architectural Direction — ICUE

**Ratified:** 2026-02 · ARB (Owner directive)
**Document owner:** Architecture Review Board
**Status:** Approved · Directional · Governs post-P0 evolution
**Supersedes:** The ACDE Phase 1–6 sketch previously captured in `ROADMAP.md`.
That sketch is retained here as the sequencing appendix.

---

## 1. The Direction

**NivXRay must evolve from a decoder-composition tool into an
*Intelligent Canonical Understanding Engine* (ICUE):**

> The engine understands the INPUT first, then deterministically
> builds the correct decoding recipe.

### Verbatim owner statement (preserved as source of truth)

> Today, when a previously unseen command line is provided, NivXRay
> often returns `OUTPUT = INPUT` or performs only a partial decode.
>
> The issue is not the individual decoders.
> The issue is that the platform does not yet have an intelligence
> layer that understands the input before deciding which decoding
> strategy to execute.

### Rejected framing — "run decoder A, then B, then C"

Today's implicit pipeline is *push-model*: fire every registered
transformation, keep whichever changes. This works for known
patterns and fails on unseen combinations.

### Approved framing — understand-first, plan, execute, evaluate

```
INPUT
   ↓
[S1]  Interpreter Identification         (PS · CMD · Bash · Python · JS · VBS · MSHTA · WMI · Office · …)
   ↓
[S2]  Technique Detection                (b64 · hex · UTF-16 · XOR · gzip · zlib · string concat · env-var
                                          assembly · char arrays · backticks · Unicode escapes · reverse ·
                                          ROT · AES wrapper · RC4 wrapper · compression · …)
   ↓
[S3]  Layer Discovery                    (how many encoding hops remain — entropy delta + printable ratio + syntax hint)
   ↓
[S4]  Recipe Planner                     (compose decoder plugin chain from detected techniques)
   ↓
[S5]  Deterministic Decoder Execution    (each stage is a pure Rule 20 plugin)
   ↓
[S6]  Progress Evaluation                (did entropy drop · printable rise · wrapper depth shrink ·
                                          new interpreter emerge · new IOC recovered · canonicality score)
   ↓
if S6.progress_positive → loop back to [S1]  (a new interpreter or technique may have emerged)
otherwise              → STOP with a *reasoned* stability-gate message
   ↓
CANONICAL ARTIFACT
   ↓
INVESTIGATION
```

### Deterministic Progress Evaluation — required contract

After each decoding stage the engine MUST answer:

- Did another encoding layer disappear?
- Did the output become more executable?
- Was another interpreter identified?
- Was meaningful content recovered?
- Did entropy decrease?
- Did printable content increase?

**Yes → continue. No → stop and explain why.**

Example stability-gate message (analyst-facing):

```
Decoder Stability Gate reached.
Remaining payload appears to require:
  • AES decryption key
  • Remote payload retrieval
  • Runtime-only variable
```

This is far more useful than `OUTPUT = INPUT`.

### Success metric

For the vast majority of real-world command lines, NivXRay must
automatically answer:

- What interpreter is this?
- Is it encoded?
- How many layers exist?
- What techniques are present?
- What deterministic recipe should be executed?
- What is the final decoded command?
- What would actually execute?
- What is the resulting investigation?

**The analyst must not have to determine the recipe manually.**

### Long-term target

**~95%+ automatic deterministic recovery** for supported real-world
command-line obfuscation techniques.

For the remaining cases (unknown encryption keys, runtime-only
dependencies), the engine explains what blocked further deterministic
recovery — never returns `OUTPUT = INPUT` without an explanation.

---

## 2. What ICUE is NOT

- **Not a new decoder.** Every existing Rule 20 decoder plugin is
  reused as a *capability* the planner may invoke.
- **Not an LLM.** ICUE is strictly deterministic. LLMs may enrich
  the investigation *after* canonical recovery, never inside it.
- **Not a permission to rewrite L0.** The frozen L0 Convergence
  Engine remains the substrate. ICUE wraps it — S5 executes through
  L0 registered transformations.
- **Not an authorization to break Rule 20 sequencing.** ICUE is a
  post-P0 evolution; PR-4..PR-8 and P1 corpus expansion still ship
  first unless the owner explicitly reprioritises.

---

## 3. Where ICUE reuses what already exists

| ICUE Stage | Reuses |
|---|---|
| S1 · Interpreter ID | Rule 19 positive-ID conventions; frontend `inputClassifier.js` heuristics (currently UX-only) |
| S2 · Technique Detection | The 24 transformations in `workspace/convergence/registry.py` self-describe their `consumes` field — that's the seed technique catalogue |
| S3 · Layer Discovery | Rule 21 signals `terminal_state`, `confidence`, `decoded_output == raw_input` already exist on the response envelope |
| S4 · Recipe Planner | To be built. First deterministic surface where ICUE writes new code |
| S5 · Deterministic Execution | Runs through the frozen L0 `converge()` loop |
| S6 · Progress Evaluation | To be built. Rule 23 (stability gate) is its termination anchor |

---

## 4. Sequencing appendix — how ICUE fits the roadmap

Locked sequence remains binding (Rules 20 / 21 / 22 / 23):

```
1. PR-4  Executive Summary + Attack Story                 ← in preview, awaiting deploy + ARB sign-off
2. PR-5  MITRE + IOC + Capability cards
3. PR-6  Certificate + Raw Decode cards
4. PR-7  Route consolidation (24 pages → 7 routes)
5. PR-8  Export bar wiring + Workspace persistence
───────── P0 Workspace complete ─────────
6. P0-C1  PowerShell Invocation Simplifier                 ← queued generic plugin (Rule 22 Category C)
───────── P0 Capability backlog complete ─────────
7. P1  Corpus Expansion                                    ← organic; grows via gap-triage
───────── P1 milestone complete ─────────
8. ICUE Phase 1 · Interpreter Identifier (S1)              ← the *first* ICUE deliverable
9. ICUE Phase 2 · Capability Registry (S4 seed)
10. ICUE Phase 3 · Recipe Planner (S4)
───────── ICUE decision-making surface complete ─────────
11. Phase B · Stage Quality Gates (S6)                     ← Rule 23 becomes actionable here
12. Phase C · Deterministic Self-Healing (S7)
───────── ICUE autonomous-decoding surface complete ─────────
13. ICUE Phase 4 · Progress Evaluation runtime binding
14. ICUE Phase 5 · Deterministic Self-Healing hooks
15. ICUE Phase 6 · Evidence Verification Engine
```

**Any earlier attempt to implement ICUE Phases 1+ violates Rules 20 /
21 / 23 simultaneously.** Only the owner can authorise an override.

---

## 5. Guiding architectural principle

> **NivXRay must never ask "which decoder should I run?"**
> **It must ask "what am I looking at, what deterministic transformations are present, and what is the next provably correct step toward a canonical representation?"**

This principle is codified as `Rule 24` in `GOVERNANCE_RULES.md`.

---

## 6. What ICUE does not eliminate

Even at 95%+ automatic recovery, new obfuscation primitives will
appear. ICUE will autonomously *combine* known techniques on unseen
inputs — but a genuinely new primitive still requires one new
Rule 20 plugin (that's Rule 22 Category C, unchanged).

**The goal is not "never add another decoder."**
The goal is:

- New *combinations* of known techniques → handled automatically by ICUE
- New *primitives* (a class of transformation NivXRay has never seen)
  → still require one new plugin, but only one

That distinction is what separates an evolving analyst platform from
an endless collection of one-off fixes.

---

**End of Architectural Direction · ICUE**
