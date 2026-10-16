# Stage 2B Part 2 — isolated host acceptance package

Date: 2026-10-16
Branch: `engineering/e3-stage2b-package`
Disposition: **no host provisioned, no image built, no service started.**
Production remains **NO-GO**.

---

## Baseline verification — PASS

| Item | Expected | Observed |
|---|---|---|
| Bundle SHA-256 (Part 1) | `58d52d5c…e7a019` | **MATCH** |
| Branch | `engineering/e3-stage2b-package` | confirmed |
| E3 ancestor `1dc4e358…` | ancestor of HEAD | **CONFIRMED** |
| `prepare.py --verify-only` | pass | "Pinned source verified" |
| Working tree | clean | 0 entries |

---

## Deliverable · Branch, commits, trees

| Item | Value |
|---|---|
| Part 1 application commit | `b30497f8281dc74555bd5585442565b631a41591` |
| Part 1 packaging commit | `a1e1be573329471ac737998cb34344e8e9b4aeed` |
| **Part 2 application commit (new pin)** | `1516fe71995bd23f4868f48b01e27e12331866dd` / tree `ab9127d8647d0303eef53e5ab549b435e5e3a0e0` |
| **Part 2 packaging commit (HEAD)** | `1efa6dc8f7164bc6c1278e7e3891cd618843e220` / tree `b0fe6fa33a23b911bc8c1b61d0af57dbf7fa21ed` |
| Bundle | `/app/rocket-evidence/e3/nivxray-e3-stage2b-part2.bundle` — 23,523,587 bytes, SHA-256 `704d0561052ac9e2e8d770e326c417bab0269c28b6094f7f143297ff8cf799f0` |
| Bundle re-verified | fresh clone: tip/tree match, 10 commits, no alternates, `fsck` clean, acceptance scripts carry mode `100755` |

`diff(1516fe71, HEAD)` is six files, **all** under `deploy/stage1-staging/` —
the packaging-only admission control still holds and was not weakened.

### Changed-file inventory (6 files vs the Part 1 HEAD)

| File | Change |
|---|---|
| `tools/rocket_e2e/acceptance_trace.py` | +8/−2 (**in the pinned commit**): `ROCKET_XDR_ORIGIN` selects the API origin; the backend `sys.path` insert is conditional so the trace also runs from inside the backend image |
| `deploy/stage1-staging/acceptance/host_acceptance.sh` | new, executable, 13 fail-closed phases |
| `deploy/stage1-staging/acceptance/egress_denied.sh` | new, executable, kernel-enforced negative test |
| `deploy/stage1-staging/test_acceptance_scripts.py` | new, 17 static checks that need no Docker |
| `deploy/stage1-staging/source.json` | repinned to `1516fe71` / `ab9127d8` |
| `deploy/stage1-staging/test_package.py` | pin assertions updated |
| `deploy/stage1-staging/README.md` | +19 documenting the procedure and required secret-file names |

Why the pin moved again: `verify_source()` requires the packaging candidate to
contain no application changes. The trace fix is application-side, so it went
into the pinned commit and the pin followed it. Provenance is unchanged in
strength — still three checks, still requiring descent from `1dc4e358…`.

---

## Task A · Target host specification

### Hard requirements

| # | Requirement |
|---|---|
| H1 | Linux, kernel ≥ 5.10, with `iptables`/`nftables` available to the container runtime |
| H2 | Docker Engine ≥ 24 with **Compose v2** (`docker compose version` must succeed) |
| H3 | Single declared architecture: **ARM64 or AMD64**, not mixed. All base images (`python:3.11-slim`, `nginx:1.27-alpine`, `mongo`) are official multi-arch |
| H4 | 4 vCPU, 8 GB RAM, 40 GB disk |
| H5 | Default-deny **host** egress for the staging bridge, enforced by host firewall or an isolated VLAN/namespace, independently proven |
| H6 | Named volumes `mongo-data` and `response-state` on local disk; no NFS, no bind mount into the clone |
| H7 | Secrets directory **outside** the clone, mode `0700`, with four `0600` files |
| H8 | A reviewed private registry, so images can be referenced by immutable digest |
| H9 | SSH: key-only, `PasswordAuthentication no`, `PermitRootLogin no`, no agent forwarding, access restricted to operator source addresses |
| H10 | No route, DNS entry, tunnel, VPN or credential to any production system |

**Containers need no extra capabilities.** The package relies on Docker-managed
isolation (`internal: true`) plus host-enforced controls. Every workload keeps
`cap_drop: [ALL]`; `CAP_NET_ADMIN` is required only by the *daemon*, never
granted inside a container. `test_acceptance_scripts.py` fails if
`--privileged`, `--cap-add`, host networking or `sudo` ever appears.

### Recommendations

Dedicated disposable VM; 8 vCPU / 16 GB for comfortable build times;
`live-restore: false`; `userns-remap` for defence in depth; auditd on the
Docker socket; `python-snappy` install proven on the chosen architecture;
`docker builder prune` between runs.

---

## Task B · Staging service verification

| Service | State | Posture |
|---|---|---|
| **MongoDB** | modelled | authenticated, least-privilege app account via `mongo-init.js`, `private` only, unpublished, 1 GB / 1 CPU / 256 pids, `restart: "no"` |
| **Backend** | modelled | `read_only`, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`, 2 GB / 2 CPU / 128 pids, `init`, non-root `nivxray`, `private` only |
| **Worker** | in-process, **gated OFF** (`NIVX_EDR_WORKERS_DISABLED=1`), verified in the startup log. Separate worker acceptance stays a HOLD |
| **Response engine** | modelled | non-root `10001:10001`, `read_only`, `cap_drop: ALL`, `no-new-privileges`, 512 MB / 0.5 CPU / 64 pids, state on `response-state`, healthcheck, `private` only |
| **Gateway** | modelled | `read_only`, tmpfs, 128 MB / 0.5 CPU / 64 pids, the only `ingress` member, published `127.0.0.1:18081` only |
| **Frontend** | existing static hosting model retained; prepared context emits `.env.staging` pinning the build to the isolated staging API origin; CSP `connect-src` limited to self plus that origin |

### Is collector integration necessary?

**No, not for authenticated ingestion acceptance.** Evidence: the trace ingests
a rendered Sysmon Event 1 directly through `POST /api/xdr/ingest/telemetry`
using a provisioned machine principal holding `collectors.enroll` against a
registered collector record, and the backend answers `REASONED` with
`selected_dsm_id=microsoft-sysmon`, promoting a real incident. The collector
container is an **additional delivery transport**, not part of the ingestion
authority path. Deploying it would add an outbound-delivery component to an
egress-denied network for no acceptance value, so it is deliberately excluded
and recorded as a deferred item.

All preserved: tenant isolation, non-root execution, read-only filesystems,
dropped capabilities, no-new-privileges, resource limits, simulation-only
response, and no production secret, database or origin anywhere.

---

## Task C · Executable acceptance procedure

`deploy/stage1-staging/acceptance/host_acceptance.sh <phase>` — each phase
aborts on the first error (`set -euo pipefail`) and every check is written so
that an unexpected success is a FAIL.

```bash
export STAGING_ROOT=/opt/nivxray/clone
export STAGING_SECRETS=/etc/nivxray-staging        # 0700, outside the clone
export STAGING_EVIDENCE=/var/log/nivxray-staging-acceptance
export STAGING_API_ORIGIN=https://<isolated-staging-host>
export STAGING_REGISTRY=<reviewed-private-registry>
export PYTHON_BASE=python@sha256:<reviewed-digest>

for phase in prereq provenance build digests preflight up health \
             egress internal trace response evidence; do
  ./deploy/stage1-staging/acceptance/host_acceptance.sh "$phase" || break
done
./deploy/stage1-staging/acceptance/host_acceptance.sh down     # add -v to drop volumes
```

| Phase | What it proves |
|---|---|
| `prereq` | Docker + Compose v2 reachable, Linux, seccomp available, secrets dir outside the clone at `0700` |
| `provenance` | clean tree, `prepare.py --verify-only`, full packaging admission suite |
| `build` | deterministic export, backend and response images built, export carries no `data/` |
| `digests` | images pushed and **immutable `@sha256:` digests recorded**; response image asserted to run as `10001:10001` |
| `preflight` | four secret files present at `0600`; `preflight.py` admission |
| `up` / `health` | services healthy; `/api/health` through the gateway; EDR worker gate observed in the log |
| `egress` | kernel-enforced external denial (Task D negative test) |
| `internal` | `mongodb:27017` and `response:8080` reachable from the backend, **and** the engine returns **401** to an unauthenticated internal call |
| `trace` | the 25-check authenticated XDR acceptance, run from a throwaway container on the private network |
| `response` | forwarder `not_wired`, `forwarded == 0`, and no execution in any state implying real dispatch |
| `evidence` | per-service logs, container posture dump, `SHA256SUMS.txt` |
| `down` | compose down, temporary context removed, review tags deleted |

### Required secret-file names (names only, never values)

`$STAGING_SECRETS/compose.env` — `MONGO_IMAGE`, `BACKEND_IMAGE`, `NGINX_IMAGE`,
`RESPONSE_IMAGE`, `MONGO_ENV_FILE`, `BACKEND_ENV_FILE`, `RESPONSE_ENV_FILE`,
`STAGING_FRONTEND_ORIGIN`.

`backend.env` — `MONGO_URL`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`,
`EMERGENT_LLM_KEY`, `EDR_AUTH_PEPPER`, `XDR_AUDIT_MASTER_SECRET`,
`XDR_SECRETS_MASTER`, `NIVXRAY_SIGNING_SECRET`, `XDR_ROOT_KEY`,
`EDR_ENROLLMENT_TOKEN_TTL_SECONDS`, `EDR_AGENT_SESSION_TTL_SECONDS`,
`JWT_EXPIRE_HOURS`, `RESPONSE_ENGINE_SERVICE_CREDENTIAL`.

`mongo.env` — `MONGO_INITDB_ROOT_USERNAME`, `MONGO_INITDB_ROOT_PASSWORD`,
`MONGO_INITDB_DATABASE`, `STAGING_MONGO_USER`, `STAGING_MONGO_PASSWORD`.

`response.env` — `RESPONSE_ENGINE_SERVICE_CREDENTIAL` (must equal the backend value).

---

## Task D · Security acceptance criteria

| Area | PASS | FAIL |
|---|---|---|
| **Network egress** | no default route, raw TCP to `1.1.1.1:443`/`8.8.8.8:53`/`93.184.216.34:80` denied, DNS denied — in backend, response **and** mongodb; gateway loopback-only; `${project}_private` reports `Internal=true` | any probe reaches a routable address, or any private workload holds a default route |
| **Tenant authorization** | analyst A sees only tenant A; cross-tenant ingest returns `TENANT_ISOLATION_VIOLATION`; foreign tenant header refused; scope is `authority=server` | any cross-tenant read, write or ingest succeeds |
| **Response approval** | execute is admitted and held at `WAITING_APPROVAL`; approval transitions only after an authorized analyst approves | any action reaches a terminal success without approval |
| **Simulation-only** | forwarder `not_wired`, `forwarded == 0`, no execution in `EXECUTING/RUNNING/FORWARDING_EVIDENCE/FAILED_EXECUTION/FAILED_TARGET/FAILED_FORWARDING`; only the `STUB_NO_SIDE_EFFECT` action completes | a `REAL_PRODUCT_API` action reaches `SUCCEEDED`, or anything is forwarded |
| **Database isolation** | `nivxray_stage1_staging` only, least-privilege app account, unpublished, empty but for synthetic provisioning | root authority used, port published, or any non-synthetic record present |
| **Secret handling** | four files outside the clone at `0600` in a `0700` dir; distinct cryptographic secrets ≥ 32 chars; the service credential reuses none of them and matches on both sides; `preflight.py` discloses no values | any secret inside the clone, group/world-readable, reused, or a placeholder |
| **Image provenance** | all four images referenced by `@sha256:`; backend built with `SOURCE_SHA`/`SOURCE_TREE` from `source.json`; digests recorded | any tag reference, or a digest that does not match the recorded build |
| **Resource limits** | memory, cpus and pids limits present on every service; `init: true` where declared | any service without limits |
| **Restart behaviour** | every service `restart: "no"` — nothing self-revives after `down` | any `unless-stopped`/`always` |

### Negative test — kernel-enforced, not application-level

`acceptance/egress_denied.sh` deliberately **bypasses all application code**:
it runs `socket.create_connection` to routable IP literals, reads
`/proc/net/route`, and calls `getaddrinfo` *inside* each container. No Python
socket guard, allowlist or SDK setting can influence the outcome. If a workload
were relying on an application-level guard, these raw probes would still succeed
and the script would exit non-zero. Denial is corroborated host-side by
`docker network inspect --format '{{.Internal}}'`, which reports the kernel
packet-filter posture Docker installed, and by the absence of a default route —
something no application can fake.

---

## Task E · Current environment validation

Executed here, without Docker and without any privileged operation:

| Check | Result |
|---|---|
| Part 1 bundle SHA-256 | **PASS** |
| E3 ancestry of HEAD | **PASS** |
| `prepare.py --verify-only` after repin | **PASS** |
| `test_package.py` | **16 passed**, 0 failed |
| `test_acceptance_scripts.py` | **17 passed**, 0 failed |
| Combined `deploy/stage1-staging` suite | **33 passed**, 0 failed, 0 skipped |
| `bash -n` on both scripts | **PASS** |
| Embedded heredoc Python compiles | **PASS** |
| Authenticated XDR trace with `ROCKET_XDR_ORIGIN` set | **25/25 PASS**, 0 failed, 0 blocked |
| Part 2 bundle re-verified in a fresh clone | **PASS** (10 commits, no alternates, exec bits intact) |

### Minimal correction made

One real defect blocked reproducibility: `acceptance_trace.py` hardcoded
`http://127.0.0.1:18001` and unconditionally inserted `<root>/backend` on
`sys.path`. On an isolated host MongoDB is unpublished, so the trace must run
from inside the private network where the API is `http://backend:8001` and the
backend modules are the image's working directory. Two lines now read
`ROCKET_XDR_ORIGIN` and make the path insert conditional. Re-verified at
**25/25** with no behavioural change to any check.

### BLOCKED until a target host exists

`prereq`, `build`, `digests`, `up`, `health`, `egress`, `internal`, `trace`
(container-run form), `response` (live engine form), `evidence`, `down` — all
require a container runtime this pod does not have (`docker`, `podman`,
`nerdctl` absent) and capabilities it does not hold (`CAP_NET_ADMIN`,
`CAP_NET_RAW`, `CAP_SYS_ADMIN` all absent; `unshare -n`, `ip netns add`,
`nft add table` all EPERM).

> **No successful Docker acceptance is claimed.** Nothing was built, started or
> isolated. The egress negative test has **never been executed**; its result is
> **BLOCKED**, not PASS.

---

## Rollback and cleanup

Staging-only; there is nothing in production to roll back.
`host_acceptance.sh down` stops the stack, removes the temporary export
context and deletes the review tags; append `-v` to destroy `mongo-data` and
`response-state`. Then revoke the synthetic credentials, delete the registry
review tags, and discard the clone. Because every service is `restart: "no"`,
nothing self-revives. Recovery point: commit `1efa6dc8…` and the verified
bundle.

---

## PASS / FAIL / BLOCKED matrix

| # | Check | Status |
|---|---|---|
| 1 | Part 1 bundle integrity | **PASS** |
| 2 | E3 ancestry and pinned-source verification | **PASS** |
| 3 | Packaging admission tests (16) | **PASS** |
| 4 | Acceptance-script static admission (17) | **PASS** |
| 5 | Script syntax and embedded Python | **PASS** |
| 6 | Authenticated XDR trace, 25 checks | **PASS** (Emergent stack) |
| 7 | Simulation-only response, source + compose | **PASS** |
| 8 | Part 2 bundle re-verification | **PASS** |
| 9 | Host prerequisites | **BLOCKED** |
| 10 | Image build and digest recording | **BLOCKED** |
| 11 | Service health on a host | **BLOCKED** |
| 12 | **Kernel-enforced egress denial** | **BLOCKED** |
| 13 | Authorized internal reachability | **BLOCKED** |
| 14 | Live engine simulation-only proof | **BLOCKED** |
| 15 | EDR worker/queue acceptance | **BLOCKED** (deliberately gated off) |
| 16 | Collector delivery path | **DEFERRED** (not required — see Task B) |
| 17 | Browser/DOM acceptance | **BLOCKED** |

---

## Remaining security HOLDs — none waived

FULL_E2E (egress), authenticated browser/DOM acceptance, real Mongo
concurrency/reconciliation and target-host resource gates, EDR worker
acceptance, collector missing-signature acceptance and replay durability,
credential/runtime hygiene and owner rotation, NCI permission/service
delegation, legacy cache exposure and migration, CI-09 and related security
gates plus SDK provenance, dependency reproducibility (resolved wheels and base
OS packages still need capture and approval), exact release packaging, and
production/release approval.

---

## Recommendation

> **Ready for host execution — pending owner provisioning of an isolated
> Docker-capable host.**

The package is complete and self-checking: provenance verifies, 33 packaging
and script-admission tests pass, both scripts are syntactically valid and
fail-closed, the response engine is integrated under hardened simulation-only
settings, and the 25-check authenticated trace passes against the disposable
stack with the new origin plumbing.

Nothing further can be proven in this environment. The decisive outstanding
item is the kernel-enforced egress negative test, which must be **executed**,
not asserted. On a host meeting H1–H10 the procedure is a mechanical run of
thirteen phases.

No GitHub push, merge, deployment, provisioning, production access, real
containment or evidence forwarding occurred. Stopping after the host acceptance
package as instructed.
