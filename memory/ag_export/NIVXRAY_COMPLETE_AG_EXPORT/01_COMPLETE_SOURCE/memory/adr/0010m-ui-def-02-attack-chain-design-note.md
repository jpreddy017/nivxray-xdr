# ADR-0010m · UI-DEF-02 · Attack Chain Design Directive (owner-locked)

**Status**: 📌 Design directive recorded. NOT authorised for implementation.
**Recorded**: 2026-08-12 (Session-19, mid-Item-5)
**Blocked on**: Item 5 completion → 12-case regression → then UI-DEF-02.
**Companion**: ADR-0023 §3c (MITRE Convergence) · ADR-0010i (UI-DEF-01 predecessor).

---

## Owner directive (verbatim intent)

> "Don't put 'No Evidence' everywhere. It creates visual noise.
> Keep all 14 MITRE ATT&CK tactic lanes structurally available, but only render evidence-backed matches.
> If NivXRay detects T1059.001 / T1562.001 / T1564.003 / T1105, the graph automatically places those into their corresponding tactic lanes.
> Clicking a node shows: Technique · Tactic · Evidence · Normalized command · Related artifact · Confidence · Provenance."

---

## Locked design principles for UI-DEF-02

### 1. Two DISTINCT analytical views — kept separate on purpose
```
                 ┌── Evidence Trajectory (6-lane · artifact view)
                 │      Execution · Transformation · Network/C2 ·
                 │      File System · Registry · Persistence
Evidence ────────┤
                 │
                 └── Attack Chain (14-lane · ATT&CK projection view)
                        Reconnaissance · Resource Development ·
                        Initial Access · Execution · Persistence ·
                        Privilege Escalation · Defense Evasion ·
                        Credential Access · Discovery ·
                        Lateral Movement · Collection ·
                        Command and Control · Exfiltration · Impact
```
The problem was never "having both". The problem was each view **independently
inventing its own MITRE mapping**. UI-DEF-02 does NOT collapse the views —
it converges the MITRE source that feeds them.

### 2. Single authoritative MITRE set feeds both views
```
                    Evidence
                        ↓
             ONE authoritative MITRE set
              (services.die.api.analyze)
                        ↓
              Technique → ATT&CK tactic
                        ↓
                  14 ATT&CK tactics
                        ↓
                Matched techniques only
                        ↓
      ┌─────────────────┼─────────────────┐
      ▼                 ▼                 ▼
 Attack Chain      Attack Story        Verdict
```
Retire the divergent `/api/analyze::mitre_map` regex path (or make it a
diagnostic-only chip) — see ADR-0010j §5 for the two-mapper asymmetry
root cause.

### 3. 14-lane Attack Chain rendering rules

- **Structurally show all 14 tactic lanes** — the scaffold is always visible.
- **Populate only lanes with real evidence-backed matches.**
- **Empty lane rendering**: thin horizontal divider under the tactic label.
  Nothing else. **NO "No Evidence" / "No Detection" / "Empty" chips.**
- **Populated lane rendering**: technique cards positioned inside the lane,
  connected by directional arrows when a chain edge exists.
- **Node click**: opens a detail panel showing (in this order):
  1. Technique (id + name)
  2. Tactic (parent lane label)
  3. Evidence (exact snippet from the DIE analyzer)
  4. Normalized command (canonical DIE reconstruction)
  5. Related artifact (IOC / LOLBIN / file / registry)
  6. Confidence (per-technique, from the evidence gate)
  7. Provenance (which mapper produced this technique — analyst-catalogue
     vs regex — as a diagnostic chip during transition; permanent surface
     stays convergent after the divergent path is retired)

### 4. Cruise-Missile principle preserved
The 14-lane view MUST show the full progression when multiple tactics
have evidence. Never truncate to the "first tactic" — the whole point of
the ATT&CK projection is to reveal chain depth.

### 5. UI-Truth principle preserved
- No lane is "coloured" in a way that implies stronger claim than
  evidence supports.
- Empty lanes are structurally present but visually neutral (label +
  thin divider). No positive/negative implication.
- Confidence must be visible on every populated node; unknown-confidence
  nodes render with a neutral badge.

---

## Concrete visual sketch (reference; final CSS is UI-DEF-02's job)

```
RECONNAISSANCE
────────────────────────────────

RESOURCE DEVELOPMENT
────────────────────────────────

INITIAL ACCESS
────────────────────────────────

EXECUTION
   ┌──────────────────────┐
   │ PowerShell           │
   │ T1059.001            │
   └──────────────────────┘

DEFENSE EVASION
   ┌──────────────────────┐     ┌────────────────────────┐
   │ Execution Policy     │────▶│ Hidden PowerShell      │
   │ Bypass · T1562.001   │     │ Window · T1564.003     │
   └──────────────────────┘     └────────────────────────┘

PERSISTENCE
────────────────────────────────

...  (remaining 10 lanes structurally present, empty)
```

---

## Non-goals of UI-DEF-02

- Does NOT modify the 6-lane Evidence Trajectory view (that stays as fixed
  per UI-DEF-01 · ADR-0010i).
- Does NOT change the DIE analyzer output.
- Does NOT touch verdict scoring.
- Does NOT introduce a third MITRE mapper.

## Prerequisites (still locked)

1. Item 5 (bounded TI latency) — **in progress**
2. 12-case regression against frozen corpus — pending
3. Owner explicit "Start UI-DEF-02" — pending

Only after all three does implementation begin.
