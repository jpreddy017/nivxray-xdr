# P0-INFRA-1 · PREVIEW RUNTIME STABILITY — INVESTIGATION (OPEN)

Opened 2026-09-26 on owner directive *STOP P0-D — PREVIEW AVAILABILITY
INCIDENT*. **P0-D not started. No EDR/XDR functionality was altered.
Nothing was re-published.** Investigation was read-only.

## FINDING

The application is not crashing. **The preview pod is being recreated by
the platform**, and the Cloudflare `502 · Host: Error` is the window in
which the origin does not exist.

Evidence, all from inside the container:

| Evidence | Reading |
|---|---|
| PID 1 | `entrypoint.sh`, **age resets** — 18 s old at 09:09:36 UTC, 352 s old at 09:34:16 UTC |
| supervisord | re-initialises from scratch at each event (fresh PID + its root banner) — 09:06:21, 09:09:32, **09:28:24** UTC |
| pod IP | **changes every boot** — Vite logged `10.208.140.207 → 10.208.132.160 → 10.208.132.176 → 10.208.131.102`. A new IP means a new pod, not a restarted process |
| service state each boot | backend, frontend, mongodb, nginx-code-proxy, sensor, collector, response all reach RUNNING in **1–6 s**. **No FATAL. No BACKOFF. No exit codes. No restart loop.** |
| binding | backend `uvicorn --host 0.0.0.0 --port 8001`; frontend `vite --host 0.0.0.0 --port 3000`, "ready in 544–977 ms" — both correct, both fast |
| memory | cgroup v2 `memory.max` 8 GiB · `memory.current` ≈ 2.09 GiB · `oom_kill 0` (counter resets with the pod, so a PREVIOUS pod's OOM is not visible from inside) |
| cpu | `cpu.max 200000/100000` → a **2-CPU quota** shared by uvicorn + Vite + MongoDB + three app workers |
| disk | `/` 16 % used (98 GiB free) · `/app` 62 % (3.8 GiB free) — no disk-pressure eviction |
| platform monitor | `/var/log/monitor.log` merely restarts with the pod; it records **no application failure**. Its only warnings are `localhost:8010` (code-server, deliberately not started) |

### Pod recreations, 2026-09-26 (UTC)

`02:40 · 06:19 · 06:22 · 06:38 · 06:45 · 07:02 · 07:42 · 07:57 ·
08:07 · 08:15 · 08:17 · 09:06 · 09:09 · 09:28`

The owner's 502 at **09:07:10** falls directly inside the 09:06:21
recreation. The `refused to connect` screenshot is the same condition
seen from the embedded preview pane.

### Timeline of one event (09:06 UTC)

| | |
|---|---|
| T0 09:06:21 | new pod · `entrypoint.sh` PID 1 · supervisord cold start |
| T1 09:06:22 | all services spawned |
| T2 09:06:24–27 | every service RUNNING (backend 1.5 s, Vite <1 s) |
| T3 09:07:10 | **Cloudflare 502 · Host: Error** — the old pod is gone and the ingress has not yet settled on the new one |
| T4 09:09:32 | recreated **again**, three minutes later |

### What this rules out

Not an application crash · not a restart loop · not a bad bind address or
port · not an OOM inside the current pod · not disk pressure · not a
React route bug (the origin itself is absent, which is why unrelated
routes fail identically).

### What cannot be answered from inside

The **termination reason** (OOMKilled vs Evicted vs node pressure vs
rescheduling vs idle reclaim) lives in platform/kubelet pod events, which
are not readable from within the container. Notably, the 09:28:24
recreation happened while the container was **idle apart from a 20-second
probe** — no test run, no build — which argues against "our CPU load
caused it" for that event at least. Emergent support has been asked for
the platform-side reason (reply relayed to the owner verbatim; escalation
path: support@emergent.sh with entity `630704a1-621f-478b-9b86-a321772d01bf`,
timestamps 09:06:21 / 09:09:32 / 09:28:24 UTC and Cloudflare Ray IDs
`a4111de3fabc2e33`, `a4111de62b452e33`).

## FIX APPLIED

**None to the application — deliberately.** There is no application
defect to fix, and changing EDR/XDR behaviour would only hide the 502.
What was added is measurement, not a workaround:

* `/app/memory/availability_probe.sh` → `/app/memory/availability_probe.log`
  — a read-only external probe, every 20 s, over `/`,
  `/xdr/control-center`, `/edr/computers`, one EDR trajectory route and
  `/api/health`, recording the HTTP status plus the PID-1 age and the
  backend/frontend uptimes on every sweep. The probe dies with the pod,
  so a **gap in its log is itself the outage record**.

## AVAILABILITY PROOF

Window 09:10:57 → 09:24:35 UTC · 40 sweeps · **200 on all five routes,
every sweep · 0 non-200** · backend and frontend uptime climbed
monotonically to 15:05, so neither restarted during the window.

Then, at **09:28:24 UTC, the pod was recreated again** and the probe
process died with it — which is the honest result: the environment was
stable for ~18 minutes and then the platform replaced it again. The
incident is **NOT closed**.

## REMAINING RISK

1. The recreations are **ongoing and outside our control**; each one is a
   30–60 s user-visible 502. Only Emergent support can supply the reason.
2. A 2-CPU quota is shared by six services. Long CPU-heavy runs (the
   `tests/edr` suite takes ~4 min under pytest-xdist) are a plausible
   aggravating factor even though the 09:28 event happened while idle —
   so heavy suites should not be run while the owner is reviewing the
   console.
3. `oom_kill` counters reset with the pod, so an OOM in a *previous* pod
   would be invisible from inside. This cannot be ruled out locally.
4. Per support: preview runs on shared resources with no self-service
   "keep alive"; a deployed app runs on dedicated tier resources with a
   pod disruption budget. That is the platform's answer for stable 24/7
   availability.
