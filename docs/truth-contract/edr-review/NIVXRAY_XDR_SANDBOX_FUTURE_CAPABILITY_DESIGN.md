# NivXRay XDR · SANDBOX · FUTURE CAPABILITY · NOT IMPLEMENTED

> **STATUS: DESIGN ARTIFACT ONLY.** Owner decision 4-b (2026-09-05).
> **There is no Sandbox product surface, no navigation entry, no API, and no detonation engine in NivXRay XDR.**
> This document is the future UX contract. It must not be read as a description of shipped capability.

---

## 1 · Hard boundary (non-negotiable)

| Allowed | Forbidden until a real detonation engine exists |
|---|---|
| This design specification | A Sandbox nav item in `XdrShell.jsx` |
| Wireframe-level layout description | Any `/api/*/sandbox*` endpoint |
| Data contract definition | **Simulated detonation** |
| Epistemic-state treatment | **Fake process tree** |
| — | **Fake network activity** |
| — | **Fake sandbox verdict** |
| — | **Fake VM / fake screenshots / fake dropped files** |

Any Sandbox surface shipped before the engine must render exactly one thing:

```
⊘  SANDBOX — FUTURE CAPABILITY · NOT IMPLEMENTED
   No detonation engine is configured. NivXRay will not display
   dynamic-analysis results it did not produce.
```

That block uses the **`capability_unavailable`** epistemic state (`⊘`, `--nx-ep-nocap`) delivered in Phase 1-a — the same treatment already used for the 8 response actions whose integrations are unconfigured.

## 2 · Current truth about dynamic analysis

| Capability | State | Evidence |
|---|---|---|
| Detonation / dynamic analysis | **NOT IMPLEMENTED** | no engine, no API, no collection |
| Third-party sandbox **lookup** | PARTIAL | `services/ioc_intelligence/providers/hybrid_analysis.py` — a *reputation lookup*, **not** detonation |
| Static artifact analysis | IMPLEMENTED | `services/artifact_intelligence/analyzers/` incl. AG-added `archive.py`, `shellcode.py` |
| Artifact store | IMPLEMENTED | `v2_artifact_store` (15 docs), `/api/v2/artifacts/*`, `/api/v2/decoded-artifacts/{sha256}` |

**So NivXRay can already reason about an artifact statically. It cannot execute one.** The gap is execution infrastructure, not analysis logic.

## 3 · Future UX contract (when an engine exists)

Entry point is **entity-centric**, reached from a HASH node in the Evidence Graph — not a standalone destination:

```
HASH
 ├── File Evidence            (exists today)
 ├── Malware Intelligence     (exists today)
 ├── Sandbox                  ← FUTURE
 ├── Related Endpoints        (needs Entity 360 · CAT-10)
 └── Hunting                  (needs a hunting plane · CAT-09)
```

Submission → result progression, each stage carrying an explicit epistemic state rather than a spinner-then-answer:

| Stage | Epistemic state while pending |
|---|---|
| Submitted | `not_run` ○ |
| Detonating | `running` (pulse) |
| Behavioural report | `evidence_present` ◆ / `no_evidence` ◇ |
| Verdict contribution | must flow through **VEEE as a contributor**, never as an independent verdict |

**Critical architectural constraint:** a sandbox verdict must enter the product as **one more VEEE contributor** (`source: "sandbox"`, `weight: n`), exactly like `detection`, `iue.severity_hint` and `ice.matches` do today (`xdr_veee.py:49-69`). It must **never** become a second verdict engine, and it must never bypass `verdict_stage2`.

Report panes (all optional, all honest-empty when absent): process tree · file writes · registry · network contacts · dropped artifacts · screenshots · extracted IOCs → routed to the existing IOC/TI planes.

## 4 · Prerequisites (in dependency order)

1. **Execution infrastructure** — isolated VM/container with snapshot+rollback. Not available in the current environment; this is the actual blocker.
2. **Artifact submission transport** — chunked upload; the artifact store already exists.
3. **Detonation adapter contract** — same DSM/parser/normalizer pattern the telemetry plane already uses, so behavioural output lands in `xdr_canonical_evidence` like every other source. **No parallel pipeline.**
4. **VEEE contributor registration** — additive weight, published like the existing weights.
5. **Network containment policy** — a detonating sample must not reach production networks.

## 5 · Reference material

Vendor sandbox/dynamic-analysis consoles supplied by the owner are retained as **interaction** references only (submission → progress → behavioural report → IOC extraction → verdict contribution). Per the owner's standing instruction: no vendor visual identity, layout, component styling, icons, typography or proprietary interaction design is to be reproduced.

## 6 · Why this stays unbuilt for now

Detonation without the upstream planes would produce isolated results with nowhere to land: there is no Entity 360 to attach them to (CAT-10), no hunting plane to pivot into (CAT-09), and no live telemetry to correlate against (CAT-12, 0 configured sources). Sandbox is correctly sequenced **after** the current foundation work.

## END · Design artifact · NOT IMPLEMENTED · no production surface exists
