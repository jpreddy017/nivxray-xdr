<!-- NIVX-DOC
layer: TARGET_SPEC
status: AUTHORED
-->

> **TARGET** specification. Live command states:
> `08_VALIDATION/REALITY_MATRIX.md`.

# RESPONSE ARCHITECTURE

The most disciplined component in the platform, and the one whose
discipline should be copied everywhere else. Adopts
`memory/P0_2_EDR_RESPONSE_SURFACE.md`,
`memory/STEP2_RESPONSE_SERVICE_DEPLOY.md`.

## 1 · Distributed by design

```
NIVXRAY XDR      recommend · orchestrate · approve · record
      ↓
NIVXFORGE EDR    execute
      ↓
ENDPOINT         the actual control plane
      ↓
NIVXRAY XDR      verify · record outcome
```

XDR never touches an endpoint directly. This matches the reference
pattern (`PUBLICLY_DOCUMENTED`) and adds a stage the reference contract
does not require: **verification before success.**

## 2 · Lifecycle — the invariant

```
REQUESTED → APPROVED → DISPATCHED → EXECUTING → EXECUTED → VERIFIED
```

| State | Means | Does **not** mean |
|---|---|---|
| `REQUESTED` | an analyst asked | anything happened |
| `APPROVED` | authorisation granted | dispatched |
| `DISPATCHED` | handed to the executor | executing |
| `EXECUTING` | executor started | succeeded |
| `EXECUTED` | executor **claims** completion | **verified** |
| `VERIFIED` | post-action evidence confirms effect | — |
| `CAPABILITY_UNAVAILABLE` | cannot be performed here | failed |
| `VERIFICATION_FAILED` | claimed executed, evidence disagrees | — |
| `FAILED` | executor failed | — |

**Only `VERIFIED` is backed by post-action evidence. A stub or simulation
may NEVER be marked executed or verified.**

The state distribution on the live system is itself the proof this is
real: commands sit in `AUTHORIZED`, `CAPABILITY_UNAVAILABLE`, `VERIFIED`,
`VERIFICATION_FAILED` and `FAILED`. A system that fabricated success
would not have a `VERIFICATION_FAILED` row.

## 3 · Target identity binding — the strongest safety property

A `KILL_PROCESS` command binds to the observed process's **start
identity**, not its PID.

Verification requires the probe to carry that same identity basis
(`identity_basis == "start_ticks"` on Linux). If it does not, the result
is `VERIFICATION_IDENTITY_UNPROVEN` — because:

- a PID can be free because the process exited on its own (not evidence
  the kill worked), and
- a PID can be occupied by an unrelated newer process (not evidence
  about the target).

So the platform reports one of exactly three honest outcomes: the target
is gone under its observed start identity; the target is still running;
or the PID is now held by a **different** later process.

**Windows implication.** The identity basis must become pluggable — on
Windows it is PID + process creation time. Until that exists, a Windows
kill could be *claimed* but never *verified*, and the lifecycle would
correctly refuse to call it success. This is a first-class requirement in
`04_DEVELOPMENT/SENSOR_DEVELOPMENT_GUIDE.md`.

## 4 · Approval

Approval is separated from request and from execution, gated by RBAC and
recorded in `xdr_audit_log`. A dispatch without a matching approval is an
invariant violation.

Isolation policy projection (approval requirements, asset restrictions)
must come strictly from authoritative backend policy, never be inferred
by the UI — tracked as P0-2D.

## 5 · Action catalogue — the honesty debt

**18 actions catalogued · 2 operational · 16 `NON_OPERATIONAL` stubs.**
The EDR Response surface prints this ratio on screen, which is honest —
but offering 18 actions where 2 work is still a product-honesty problem.

| Action | State | Note |
|---|---|---|
| `KILL_PROCESS` | **operational + verified** | Linux only; start-identity bound |
| `ISOLATE_ENDPOINT` | `CAPABILITY_UNAVAILABLE` | `BLOCKED_ENVIRONMENT` — no `CAP_NET_ADMIN` in this pod. **Never simulated** |
| `RELEASE_ISOLATION` | `CONTRACT_DEFINED` | P0-2B; must reuse the identical lifecycle |
| 15 others | `NON_OPERATIONAL` | each requires `ADOPT` / `WIRE` / `DEPRECATE` |

**Required by `CLOSED_BETA`:** every catalogued action either has a real
adapter with a verification probe, or is removed from the catalogue. An
analyst must never be offered an action that cannot execute.

## 6 · Runtime

| Component | Location | Role |
|---|---|---|
| response service | `apps/nivxray-xdr-response` `:8056` | lifecycle authority; SQLite execution SSOT |
| XDR boundary | `backend/routers/xdr_respond_boundary.py` | forwards; **fails closed** when the engine is down — never a silent success |
| EDR execution | `backend/edr_plane/response.py` + sensor | execution + verification probe |
| EDR surface | `nivxforge/pages/EdrResponsePage.jsx` | renders derived lifecycle state |

Aliases: the command plane accepts the same identifiers the read plane
does. Requesting an action by `device_iid` previously returned
`404 ENDPOINT_NOT_ENROLLED` — a **false statement about enrolment** — and
is now resolved at the boundary while the enrolment registry remains the
authority.

## 7 · Safety requirements not yet met — `SPEC_PENDING`

Tracked in `07_SECURITY/RESPONSE_SAFETY.md`:

1. **Blast radius.** Could one request isolate a whole fleet? Undefined.
2. **Idempotency** on retry.
3. **Rate limiting** per analyst, per endpoint.
4. **Emergency stop** for in-flight actions.
5. **Windows identity basis** (§3).

## 8 · The transferable lesson

This component is trusted because **it refuses to claim success it cannot
prove**, and because its refusals are visible states rather than hidden
failures. `CAPABILITY_UNAVAILABLE`, `VERIFICATION_FAILED` and
`ENDPOINT_NOT_RESOLVED` look like weaknesses on screen; they are the
reason the `VERIFIED` rows can be believed.

Every other plane should adopt the same shape: **name the absence,
never imply the negative.**
