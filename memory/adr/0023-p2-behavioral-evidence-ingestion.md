# ADR-0023 · P2 = Behavioral Evidence Ingestion

**Status:** 📌 LOCKED (architectural intent only — no code path exists)
**Decided:** 2026-08-12
**Predecessor:** ADR-0010e (Real Investigation Proof · REDIRECT)
**Grounding material (read-only reference):**
- `Windows_LOLBAs_360_Training-1(2).pdf` — 34 pp. covering LOLBAs, parent-child process relationships, PPID spoofing, Sysmon Event IDs, process-tree anomaly detection
- `Windows Security Log Encyclopedia_new.pdf` — 7 pp. covering Windows Security Event IDs (4624/4625/4648/4672/4688/4697/4720/4732/4756/4768/4769/4776/5140/5145/1102, etc.)

---

## 1 · The locked directive

> **P2 = Behavioral Evidence Ingestion.**
>
> Sysmon/EVTX is only the *first telemetry adapter*. Its purpose is to produce **canonical behavioral evidence** — especially process creation and parent-child relationships — that feeds the *existing* Evidence / IKG → Correlation → ATT&CK / Verdict → Attack Story → Report pipeline.
>
> Parent-child relationships are **evidence, not truth**. Process-tree conclusions must be correlated with command line, image path, hashes / signatures, DLL / file activity, network, registry, user / session, Windows and Sysmon events, and temporal relationships. **PPID spoofing must be treated as an explicit limitation** (Sysmon alone cannot reliably detect it; kernel-callback ETW, session-ID / integrity mismatch, and grandparent anomaly checks are required, per LOLBA training §22).
>
> **Do NOT create a parallel Process Tree engine or a separate product.**
>
> P2 does not open until the LIVE-product remediation set (§4) passes regression against the frozen 12-case corpus.

## 2 · Canonical flow (unchanged by P2)

```
                          INPUT
                            │
                 Universal Input Router
                            │
              ┌─────────────┴─────────────┐
              │                           │
             DIE                      Telemetry
       (LIVE today)             (P2 · future adapter)
              │                           │
              │                    Process events
              │                    File events
              │                    Registry events
              │                    Network events
              │                    Auth / session events
              │                           │
              └──────────────┬────────────┘
                             ↓
                Evidence Normalization
                             ↓
             Investigation Knowledge Graph
                    (shadow today)
                             ↓
                       Correlation
                             ↓
                 ┌───────────┴───────────┐
                 ↓                       ↓
               ATT&CK                  Verdict
                 │                       │
                 └───────────┬───────────┘
                             ↓
                       Attack Story
                             ↓
                          Report
```

P2 adds a **producer of evidence** to the graph. Nothing downstream is duplicated, forked, or bypassed.

## 3 · Investigation cadence (unchanged)

The six-question analyst rhythm that NivXRay is optimising for:

1. **WHO** started it? (session / user / logon type / privilege)
2. **WHAT** executed? (image / command line / hash / signature)
3. **HOW** was it executed? (parent chain / DLLs loaded / arguments)
4. **WHAT** was created or downloaded? (files / registry writes)
5. **WHERE** did it connect? (DNS / network destinations)
6. **WHAT** changed? (services / scheduled tasks / persistence)

→ **correlate the evidence** → **verdict** → **explain** → **report**.

The goal is not more telemetry for its own sake. The goal is a cruise-missile investigation engine that follows the evidence chain toward root cause rather than stopping at the first indicator.

## 3a · Cruise-Missile Guidance Principle (locked)

The single design principle every subsequent NivXRay improvement — remediation
items, telemetry adapters, IKG projections, verdict logic — must honour:

> **NivXRay does not stop when it finds an indicator. It pursues the evidence
> until it can explain the incident.**

Cruise-missile behaviour, made explicit:

* **Acquire** the target — accept any supported input (command, script, file,
  document, and eventually telemetry).
* **Navigate** — decode, deobfuscate, unwrap recursively until the raw
  behavioural surface is exposed.
* **Discover new evidence** — extract every observable (IOCs, LOLBINs, parent
  chain, hashes, DLLs, files, network, registry, session).
* **Course-correct** — every newly-discovered observable can re-open the
  investigation, feed new decode/enrich queries, and pull additional evidence
  into the graph.
* **Pursue recursively** — a URL yields a payload; a payload yields commands;
  commands yield new IOCs; new IOCs yield new correlations — the loop closes
  only when the investigation can be *explained*, not when the first
  suspicious token is detected.
* **Correlate** — parent-child, temporal, session, and identity edges combine
  observables into an attack chain.
* **Judge** — verdict is a function of the *correlated evidence set*, never of
  a single indicator.
* **Preserve the flight record** — the complete chain (input → decoded layers
  → observables → correlations → ATT&CK → verdict → impact) is written to a
  deterministic, reproducible report that survives the original analyst.

### Concrete illustration (locked into this ADR so future agents cannot re-invent it)

**Weak "indicator-detector" reasoning (what NivXRay must NOT collapse into):**
```
rundll32.exe   →   suspicious
```

**Cruise-missile reasoning (what NivXRay must progressively achieve):**
```
WINWORD.EXE
   ↓ (Sysmon Event 1 — parent-child edge; Office → LOLBIN combination
      from LOLBA training §3.2)
RUNDLL32.EXE
   ↓ (command line + image path + signer + hash correlated;
      T1218.011 candidate)
C:\Users\Public\update.dll          (Sysmon 7 image-loaded; unusual path;
                                      Sysmon 11 file-create if just dropped)
   ↓
External Network Connection         (Sysmon 3 + Sysmon 22 DNS; IOC extracted)
```

The verdict is **not** "rundll32.exe = suspicious". The verdict is the
*explanation of the correlated chain*: an Office document spawned a signed
system binary that loaded a non-system DLL from a public writeable path and
initiated an external connection — a defensible malicious-execution
narrative that another analyst can reconstruct from the persisted evidence
alone.

### How each in-flight workstream serves the missile

* **The five §4 preconditions** repair the *guidance system* (verdict
  calibration + narrative + recursive decode + missing signature + latency
  bound). Nothing to do with new sensors — the existing sensors must aim
  correctly first.
* **P2 Behavioral Evidence Ingestion** adds *sensors* (Sysmon / EVTX /
  Windows Security event streams). More observables into the same graph.
* **IKG + Correlation + Attack Story** (shadow today) provide *navigation
  and relationship awareness* — how observables combine into a chain.
* **Recursive decode + observable-driven re-enrichment** is what lets the
  missile *continue pursuing the target* rather than exploding on the first
  encoded blob.
* **The deterministic report** is the *complete flight record* — every
  observable, every decoded layer, every correlation, every verdict input,
  reproducibly reconstructable.

**No workstream may violate this principle.** If a proposed feature would
make NivXRay stop earlier, present a fabricated verdict, hide a decode
layer, or emit a conclusion without a reconstructable evidence chain — it
is rejected by this ADR without further debate.

## 3b · UI-Truth Principle (locked 2026-08-12)

Emerging directly from UI-DEF-01 (see ADR-0010i):

> **A UI must never display a stronger claim than the underlying evidence
> supports.**

Operationally:

* A visualisation that colour-codes an unclassified node as *Reconnaissance*
  (because cyan happens to be the fallback) is a rejected pattern.
* A panel title that promises "Cyber Kill Chain × MITRE ATT&CK" while
  actually rendering DIE artifact-category lanes is a rejected pattern.
* A verdict pill that says *Malicious* when only weak evidence exists is a
  rejected pattern.
* When evidence is missing, insufficient, or ambiguous, the UI must
  **admit uncertainty visibly** — neutral colour + "Unclassified / no
  phase" label + honest verdict language such as *"Suspicious behaviour
  observed; additional evidence required to establish intent"*.

This rule is enforceable at design-review time and at regression time (the
frozen 12-case corpus + Phase-B pb-01 both include cases where the correct
NivXRay answer is *not-malicious-with-caveats*, and any UI that fakes
confidence on those cases fails the gate).

## 3c · Convergence Architecture (target, not code yet · UI-DEF-02)

UI-DEF-01 exposed a deeper architectural issue: `/api/analyze::mitre_map`
(regex-driven) and `services.die.api.analyze::techniques` (analyzer-
catalogue-driven) can emit *different technique sets for the same input*.
NivXRay currently carries **two competing MITRE truths**. Provenance chips
are useful diagnostically but must not become the permanent excuse.

The target end-state (target, not code):

```
                    INPUT
                      │
                      ▼
              ┌───────────────┐
              │  DIE / Analyse │
              └───────┬───────┘
                      │
              Evidence Normalisation
                      │
                      ▼
              ┌───────────────┐
              │  MITRE Mapper │  ← ONE authoritative surface
              └───────┬───────┘
                      │
                techniques[]
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       Verdict    Narrative   Attack Story
          │           │           │
          └───────────┼───────────┘
                      ▼
                    Report
```

Individual detectors may remain different internally; the *output contract*
must converge to a single technique-set stream that Verdict, Narrative,
Attack Story, and Report all consume identically.

**UI-DEF-02 is NOT part of the current remediation queue.** Sequence
preserved: Item 4 → Item 5 → 12-case regression → THEN UI-DEF-02
convergence. Do not attempt UI-DEF-02 out of order.

## 3d · Evidence-Producer Constraint (locked 2026-08-12)

> **P2 telemetry must produce evidence, not interpret it.**
>
> Sysmon / EVTX / Windows Security event streams — and every future
> telemetry source — feed the *same* Evidence Normalisation → Correlation
> → Authoritative MITRE Mapper → Verdict → Explain → Report chain. They
> do **not** compute their own verdict. They do **not** carry their own
> MITRE technique catalogue. They do **not** run in parallel to DIE.

The correct topology when P2 eventually opens:

```
             INPUTS
                │
       ┌────────┴────────┐
       │                 │
   Artifact          Behavioural
   evidence          evidence
   (DIE today)       (P2 · future)
       │                 │
       └────────┬────────┘
                ▼
        Evidence Normalisation
                ▼
             Correlation
                ▼
        Authoritative ATT&CK
        (UI-DEF-02 convergence)
                ▼
              Verdict
                ▼
             Explain
                ▼
             Report
```

Explicit rejections this rule enforces:

* No *"Sysmon verdict"* — a Sysmon Event 1 alone must never emit a
  malicious label.
* No *"Process-tree interpretation engine"* — process ancestry is
  evidence entering the graph, not a parallel analytical pipeline.
* No *"parallel MITRE technique catalogue for telemetry"* — the
  authoritative MITRE surface (UI-DEF-02) is the single mapper for
  every evidence source.
* No *"per-adapter narrative engine"* — narrative is generated once,
  by the deterministic-narrative bridge (Item 2), from the merged
  evidence set.

The design invariant: **NivXRay is one investigation engine with
multiple evidence producers, not a collection of analyzers.** Any
proposed P2 sub-feature that violates this is rejected by this ADR
without further debate.

## 4 · Preconditions before P2 opens (owner-locked)

P2 does **not** open until *all five* of the following pass a regression run against the frozen 12-case corpus in `/app/memory/experiments/rip/`:

1. **Risk-score recalibration** — LOLBIN + external-URL + known-bad-TTP combinations cross into `Malicious` reliably (per ADR-0010e §10 finding: 3 / 8 malicious cases were mis-labelled `Low Risk`)
2. **Deterministic analyst narrative** — `/api/die/narrate` populated from the existing DIE technique + LOLBIN + IOC record
3. **Recursive decode iteration** — nested base64 / PowerShell layers surfaced (per ADR-0010e case-8 finding)
4. **T1562.004 signature** — `netsh advfirewall … state off` mapped to Disable-or-Modify-System-Firewall
5. **Bounded TI-lookup latency** — `/api/analyze` TI hit path capped by a deterministic wall-clock budget

Regression contract: `python3 /app/memory/experiments/rip/harness.py` must show zero drift on verdict labels, ATT&CK sets, and determinism after each of the five items land.

## 5 · What P2 produces when it eventually opens

**Canonical behavioral evidence records** derived from Sysmon / EVTX and Windows Security event streams. The training material catalogues exactly which event IDs matter and what fields they carry — this ADR does not re-invent that schema, it defers to those documents as the authoritative reference:

- **Sysmon Event 1** (Process Creation): `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `Hash`, `CreatorProcessId`, `ProcessId`, `User`, `LogonGuid`, `LogonType`, `UtcTime`
- **Sysmon 3 / 7 / 8 / 10 / 11 / 12-13 / 15 / 17-18 / 19-21 / 22 / 25** — network / image-loaded / remote-thread / process-access / file-create / registry / ADS / pipe / WMI-subscription / DNS / process-tampering
- **Windows Security 4624 / 4625 / 4648 / 4672 / 4688 / 4697 / 4720 / 4732 / 4756 / 4768 / 4769 / 4776 / 5140 / 5145 / 1102** — logon success / logon failure / explicit credentials / special privileges / new process / service install / account & group mgmt / Kerberos TGT & service tickets / DC validation / share access / audit-log clear
- **Suspicious parent-child combinations catalogued in LOLBA training §3.2** (verbatim reference — do not re-encode here): `winword.exe → cmd.exe / powershell.exe / wscript.exe / mshta.exe`, `excel.exe → powershell.exe`, `outlook.exe → cmd.exe`, `powerpnt.exe → wscript.exe`, `acrobat.exe → cmd.exe`, `svchost.exe → cmd.exe`, `mshta.exe → powershell.exe`, `wscript.exe → powershell.exe`, `regsvr32.exe → cmd.exe`, `rundll32.exe → cmd.exe`, `WmiPrvSE.exe → cmd.exe`, `spoolsv.exe → cmd/ps` (PrintNightmare)

Each record is emitted as normalised evidence into the graph, **not** as a standalone verdict. Verdict remains a downstream function of the correlated evidence set.

## 6 · Explicit limitations that P2 must inherit as first-class constraints

- **PPID spoofing (T1134.004)** — Sysmon-reported parent is the *STARTUPINFOEX-supplied* PPID, which the attacker controls. Detection requires kernel-callback ETW, session-ID / integrity-level mismatch, grandparent anomaly, and desktop-handle validation. Any P2 implementation MUST expose this limitation to the analyst rather than presenting the process tree as authoritative truth.
- **Process masquerading (T1036.005)** — image name equality is not identity. Path + hash + signer must be correlated.
- **Audit-log tampering (1102)** — presence of the clear-event, or gaps in event streams, is itself evidence.
- **Session context** — Session 0 vs Session 1 vs interactive session distinctions carry authority meaning. Cannot be ignored.

## 7 · Explicit non-goals of P2

- No parallel "Process Tree" analytical engine
- No separate ProcessTree product surface
- No standalone Sysmon-only verdict (verdict is always the graph's function, not one adapter's)
- No promotion of IKG / Verdict v3 / Case Engine / Adapters / Artifact Store from shadow to live without a separate owner-authorised gate
- No ingestion added before the §4 preconditions all clear
- No new `NIVX_FLAG_*` introduced by this ADR
- No Workspace change triggered by this ADR
- No Route change triggered by this ADR

## 8 · Governance

- This ADR is **memory-only**. Zero product code exists as a result.
- Future agents (fork, new session, testing agent) must treat this as the architectural frame for any conversation about Sysmon, EVTX, process tree, telemetry ingestion, or P2.
- Any deviation from §1 requires an explicit owner sign-off recorded as ADR-0023a (or superseding).
- REMINDERS.md and PRD.md carry pointers to this ADR so it is discoverable without full-corpus search.

**End of ADR-0012.**
