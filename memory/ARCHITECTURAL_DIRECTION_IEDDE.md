# NivXRay · ARB Architectural Direction — IEDDE

**Ratified:** 2026-02 · ARB (Owner directive)
**Codename:** *Intelligent Evidence-Driven Decoding Engine* (IEDDE)
**Document owner:** Architecture Review Board
**Status:** Approved · Directional · Governs post-P0 evolution
**Supersedes:** All earlier "ACDE Phase 1–6" sketch and the interim ICUE
draft. Both are retained in git history only. IEDDE is the ratified
document going forward.

---

## 1. Primary Goal (verbatim owner statement — source of truth)

> Given any command line (plain text or encoded), automatically
> understand what it is, determine the correct deterministic decoding
> strategy, recover the canonical form whenever possible, and stop only
> when no further deterministic recovery is justified.
>
> The objective is to make NivXRay understand the input first, then
> automatically choose the correct deterministic decoding recipe,
> rather than relying on individual decoder plugins or sample-specific
> fixes.

## 2. Current Limitation being solved

Today the engine largely works as:

```
INPUT
   ↓
Try Decoder A
   ↓
Try Decoder B
   ↓
Try Decoder C
   ↓
Maybe one works
```

Inevitable consequences:

- `OUTPUT = INPUT`
- One-off decoder patches
- Technique-specific fixes
- Difficulty handling previously unseen obfuscation

The long-term solution is an evidence-driven decoding engine — not an
ever-growing list of independent decoders.

## 3. Proposed Engine

```
INPUT
   │
   ▼
1. Interpreter Identification
   │
   ├── PowerShell
   ├── CMD
   ├── Bash
   ├── Python
   ├── JavaScript
   ├── Perl
   ├── PHP
   └── ...
          │
          ▼
2. Technique Detection
   │
   ├── Base64          ├── XOR
   ├── UTF-16LE        ├── RC4
   ├── Hex             ├── AES wrapper
   ├── Compression     ├── String concatenation
   ├── Character arrays├── Environment variables
   ├── Launcher wrappers├── Unicode escapes
   └── ...
          │
          ▼
3. Layer Discovery
   Determine:
     • How many deterministic layers exist?
     • Which techniques belong to each layer?
          │
          ▼
4. Recipe Planner
   Automatically build the optimal deterministic decoding sequence.
     • Do not guess.
     • Do not brute-force every decoder.
     • Choose only the transformations justified by evidence.
          │
          ▼
5. Execute ONE deterministic transformation
          │
          ▼
6. Progress Evaluation
   After every stage evaluate:
     • Did canonical recovery improve?
     • Did confidence increase?
     • Was another deterministic layer exposed?
     • Is another deterministic technique now visible?
          │
          ▼
   YES  → Continue
   NO   → Decoder Stability Gate → Canonical Output Reached
```

## 4. Decoder Stability Gate (contract)

The engine must **never** continue decoding simply because another
decoder exists. It must ask:

> *"Do I have objective evidence that another deterministic
> transformation exists?"*

- **YES** → continue.
- **NO** → stop immediately.

If recovery cannot continue because deterministic information is
missing, the engine returns a *reasoned* stop message. Example:

```
Remaining Layer: AES encrypted
Reason:          Decryption key unavailable
Canonical deterministic recovery completed.
```

Never guess. Never hallucinate. Always explain why decoding stopped.

## 5. Canonical Artifact — TWO required outputs

IEDDE mandates that the engine emit **two** distinct outputs:

### 5.1  Canonical Artifact

The fully recovered deterministic script or command.

**Example (LSASS payload):**
```
Get-Process lsass
```

### 5.2  Investigation Metadata

```
Interpreter:      PowerShell
Original launcher: powershell.exe
Flags:            -NoProfile
Recovered layers: 4
Techniques:       String Concatenation
                  Invocation Wrapper
                  Launcher Wrapper
```

**Rule:** The OUTPUT panel shows the Canonical Artifact only.
The Investigation Metadata surface (Summary / Story / Certificate
lenses) shows the launcher, flags, techniques, and recovered-layer
count. This preserves all investigation context without polluting the
canonical output.

## 6. Architectural Benefits (why IEDDE resolves current concerns)

This approach naturally addresses many current implementation
concerns raised during PR-4:

- **Interpreter ownership** becomes explicit (Stage 1) rather than
  regex-driven at the plugin level (Rule 19 is now enforced by the
  Planner, not by each plugin).
- **Decode and Auto Investigate** both consume the same canonical
  artifact — parity guaranteed by design (Rule 14 becomes a
  consequence, not an obligation).
- **Launcher unwrapping** occurs only when the Recipe Planner
  determines the script has reached a canonical state — not when a
  loose "some other fold fired in this iteration" heuristic is
  satisfied.
- **L0** becomes a stable execution engine rather than the place
  where new intelligence is continually added. All planning moves
  up-stack; L0 only *executes* what the Planner asked for.
- **New capabilities** are introduced by teaching the engine to
  recognise new techniques and plan recipes — not by continually
  patching sample-specific decoders (Rule 22 Category C remains but
  becomes rare).

## 7. New workflow (contrast)

```
Understand  →  Detect  →  Plan  →  Execute  →  Evaluate  →  Decide  →  Repeat  →  Stop
```

instead of

```
Try decoder → Try another decoder → Patch another sample
```

## 8. Long-Term Vision

The goal is not perfect decoding for every possible input. Some
payloads will remain unresolved because they require external
information (unknown encryption keys, remote content, runtime-only
state).

The goal is that, for any command line:

1. NivXRay understands what it is.
2. Selects the correct deterministic decoding strategy automatically.
3. Continues decoding only when evidence justifies another
   transformation.
4. Stops cleanly when deterministic recovery is complete OR no
   further deterministic progress is possible.
5. Produces the best possible canonical output together with a clear
   explanation of any remaining unresolved layers.

**Target:** systematic path toward ~95%+ automatic deterministic
decoding while avoiding both under-decoding (`OUTPUT = INPUT`) and
over-decoding.

---

## 9. What IEDDE is NOT

- **Not a new decoder.** Every existing Rule 20 primitive is reused
  as a capability the Planner may invoke.
- **Not an LLM.** IEDDE is strictly deterministic. LLMs may enrich
  the Investigation Metadata *after* canonical recovery, never inside
  the decoding pipeline.
- **Not a permission to rewrite the frozen L0 execution loop.** IEDDE
  wraps L0. Stage 5 executes through the existing L0 registered
  transformations.
- **Not an authorization to break Rule 20 sequencing.** IEDDE is a
  post-P0 evolution.

---

## 10. Sequencing — how IEDDE fits the roadmap

Locked sequence (Rules 20 / 21 / 22 / 23 / 24 remain binding):

```
1. PR-4  Executive Summary + Attack Story                 ← in preview, awaiting deploy + ARB sign-off
2. PR-5  MITRE + IOC + Capability cards
3. PR-6  Certificate + Raw Decode cards
4. PR-7  Route consolidation (24 pages → 7 routes)
5. PR-8  Export bar wiring + Workspace persistence
───────── P0 Workspace complete ─────────
6. P0-C1  PowerShell Invocation Simplifier                 ← SHIPPED (out of sequence, owner-authorised)
                                                             (see §12 Immediate compliance items)
7. P0-C2  PowerShell Launcher Unwrap                       ← SHIPPED (out of sequence, owner-authorised)
                                                             (see §12 Immediate compliance items)
───────── P0 Capability backlog complete ─────────
8. P1  Corpus Expansion                                    ← organic; grows via gap-triage
───────── P1 milestone complete ─────────
9.  IEDDE Stage 1 · Interpreter Identifier                 ← first IEDDE deliverable
10. IEDDE Stage 2 · Technique Detector
11. IEDDE Stage 3 · Layer Discovery
12. IEDDE Stage 4 · Recipe Planner                         ← the engine's new brain
───────── IEDDE decision-making surface complete ─────────
13. IEDDE Stage 5 · Execution binding to frozen L0 loop    ← executes only planner-selected primitives
14. IEDDE Stage 6 · Progress Evaluation + Stability Gate   ← Rule 23 becomes fully actionable
───────── IEDDE evidence-driven surface complete ─────────
15. Canonical Artifact / Investigation Metadata split      ← two-surface output contract (§5)
16. Evidence Verification Engine                           ← optional post-canonical enrichment
```

## 11. Guiding architectural principle (Rule 24, restated)

> **NivXRay must never ask "which decoder should I run?"**
> **It must ask "what am I looking at, what deterministic transformations are provably present, and is there objective evidence that another one is next?"**

---

## 12. Immediate compliance items raised by IEDDE about recent changes

These are the concerns IEDDE explicitly calls out about the L0
additions shipped this session (`structural-ps-invocation-simplify`,
`structural-ps-launcher-unwrap`). They are captured here for the
next PR-review pass rather than as immediate rework, unless the
owner decides otherwise.

**#12.1 · Launcher-unwrap firing rule is not yet evidence-driven.**
Today it fires when "any structural fold fired in the same
iteration." IEDDE §6 says it must fire only when the Recipe Planner
determines the script has reached a canonical state. Until Stage 4
lands, the current heuristic is a **stand-in** — audit note.

**#12.2 · Canonical Artifact / Investigation Metadata split is
partially realised.**
The OUTPUT panel now correctly shows the Canonical Artifact
(`Get-Process lsass`). The Investigation Metadata surface (launcher,
flags, recovered-layer count) is already in the Summary / Story /
Certificate lenses (PR-4 / PR-6). Cross-referencing between the two
surfaces is not yet enforced by contract — audit note.

**#12.3 · Interpreter ownership is still regex-driven at the plugin
level.**
The `_PS_POSITIVE_ID_RE` guard in `structural.py` performs a
regex-based positive-ID check. IEDDE §6 says interpreter ownership
belongs to Stage 1 (Interpreter Identification), not to each plugin.
Once Stage 1 lands, the per-plugin guard collapses to a single call.
Until then the regex is authoritative — audit note.

**#12.4 · Rule 19 negative-shadow test coverage is minimal.**
Only bash `&` and CMD `&` are shadow-tested. Perl, PHP, Ruby, and
Python payloads that happen to contain `&('literal')` sequences are
not shadow-tested. Recommended follow-up: extend
`tests/test_ps_invocation_simplifier.py` with those shadows before
P0-C1 is formally accepted.

None of these are blocking — they are IEDDE-compliance debts to be
retired as Stages 1–6 land.

---

**End of Architectural Direction · IEDDE**
