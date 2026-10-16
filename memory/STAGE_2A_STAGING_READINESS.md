# Stage 2A — Baseline verification & staging readiness

Date: 2026-10-16
Scope: **assessment and preparation only.** Nothing was deployed, provisioned,
pushed or started. Stage 2B was not begun.

> This document is deliberately written **outside the source tree**
> (`/app/memory/` and `/app/rocket-evidence/e3/`) so the verified baseline
> commit and tree remain byte-identical to the authoritative values below.

---

## A · Baseline verification — **PASS**

| Item | Expected | Observed | Result |
|---|---|---|---|
| Bundle SHA-256 | `36515e1d…80e757` | `36515e1d9624f3ee5bf5182b0e57e8e3bee75f56ea4a4acf72de4b4d7580e757` | **MATCH** |
| Bundle size | — | 23,502,285 bytes | recorded |
| `git bundle verify` | valid | "records a complete history", ref `refs/heads/engineering/e3-stabilization` | **PASS** |
| Commit | `1dc4e358…b50e24` | `1dc4e35809c4b30bda15d0ed25db06c6feb50e24` | **MATCH** |
| Tree | `19955236…bec55f` | `1995523652e25ff86de3cec19741199e55bec55f` | **MATCH** |
| Working tree | clean | 0 modified/untracked entries | **CLEAN** |
| `git fsck` | clean | no errors | **PASS** |
| Alternates | none | none | **PASS** |

The exact validated source tree is available at `/app/rocket-p0/src` on branch
`engineering/e3-stabilization`. **No substitute commit or baseline was used.**

### Outstanding HOLDs (from `memory/E3_FINAL_ACCEPTANCE_2026-10-16.md`)

All ten remain open and **none was waived**: FULL_E2E (egress), authenticated
browser/DOM acceptance, real Mongo concurrency/reconciliation/target-host
resource gates, collector missing-signature acceptance and replay durability,
credential/runtime hygiene and owner rotation, NCI permission/service
delegation, legacy cache exposure and migration, CI-09 and related security
gates plus SDK provenance, exact candidate packaging and EDR feature
development, and production/release approval.

### Uncommitted, generated or sensitive artifacts

- Uncommitted: **none**. Working tree is clean.
- Real secret files: **none tracked.** Only three `*.env.example` templates
  under `deploy/stage1-staging/`, which carry key names and no values.
- **Tracked runtime state — must not ship in an image:**
  - `apps/nivxray-xdr-response/data/executions.db` — mutated by the engine at
    runtime. It was dirtied by the Stage D trace and had to be restored before
    commit. Already an open hygiene HOLD.
  - `apps/nivxray-xdr-collector/.state/connectors.json` — collector runtime state.
- Untracked but present on disk: `apps/nivxray-xdr/node_modules` (gitignored,
  from the Stage B frontend run) and `/app/rocket-e2e/` disposable Mongo
  storage. Neither is part of the baseline.

---

## B · Existing staging architecture

**A hardened, purpose-built isolated staging stack already exists** at
`deploy/stage1-staging/`. It should be the basis of Stage 2B rather than
anything new.

### Reusable components (high confidence)

| Path | What it gives you |
|---|---|
| `deploy/stage1-staging/compose.yml` | MongoDB + backend + nginx gateway. Backend is `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, tmpfs `/tmp`, `mem_limit 2g`, `cpus 2`, `pids_limit 128`, `init: true`, `restart: "no"`. Mongo 1g/1cpu/256 pids. Gateway 128m/0.5cpu/64 pids, read-only, tmpfs. |
| | **`networks.private` is `internal: true`** — Docker programs kernel firewall rules that deny all egress for backend and Mongo. Only the gateway joins `ingress`, published on `127.0.0.1:18081` only. |
| | Images are required as **sha256-pinned digests** (`${MONGO_IMAGE:?…}` etc.) — the compose refuses to start without them. |
| | Safe defaults already set: `NIVX_TENANT_REGISTRY_ENFORCE=true`, `ADMIN_FORCE_PASSWORD_CHANGE=true`, `AUTO_INVESTIGATE_V1=off`, `NIVX_FILES_SWEEP_ENABLED=0`, `XDR_RESPONSE_SERVICE_URL=""`. |
| `deploy/stage1-staging/prepare.py` | Verifies pinned Git objects and exports clean build contexts. **Never deploys.** Refuses production hostnames (`nivxray.nivxforge.com`, `xdr.nivxforge.com`, `edr.nivxforge.com`, `xdr.nivxray.com`) and non-HTTPS/credentialed origins. |
| `deploy/stage1-staging/preflight.py` | Offline admission checks on owner-provisioned config. Requires secret files to live **outside the repository** with `0600` permissions, and allows only key names present in the templates. Names only, never values. |
| `deploy/stage1-staging/mongo-init.js` | Creates the staging database and a least-privilege application user. |
| `deploy/stage1-staging/gateway.conf` | nginx on `8080` proxying to `backend:8001`. |
| `deploy/stage1-staging/{backend,compose,mongo}.env.example` | Complete key-name inventory. |
| `deploy/stage1-staging/test_package.py` | 10 packaging admission tests. |
| `scripts/refuse-root-deployment.sh` | Existing guard against root deployment. |

### Service inventory and gaps

| Service | Config today | Staging gap |
|---|---|---|
| MongoDB | in `stage1-staging/compose.yml`, authenticated, internal network | none |
| Backend | in compose, hardened, `deploy/stage1-staging/backend.Dockerfile` (`${PYTHON_BASE}` arg, multi-stage) | none |
| Gateway (nginx) | in compose | none |
| Frontend | `apps/nivxray-xdr/Dockerfile` (node:20-alpine → nginx:1.27-alpine) and `deploy/stage1-staging/vercel.json` | **Not a compose service.** Stage 1 assumed Vercel hosting. Needs adding as an internal service, or an explicitly reviewed external origin. |
| Response engine | `apps/nivxray-xdr-response/Dockerfile` | **Not in staging compose at all**, and the Dockerfile is **unhardened**: runs as root, no non-root user, no healthcheck, and `COPY . .` would bake the tracked `data/executions.db` into the image. |
| Collector | `apps/nivxray-xdr-collector/Dockerfile` | **Not in staging compose.** Needs `XDR_STATE_DIR` on a writable volume and `XDR_AUTO_START_CONNECTORS` off. |
| Workers | EDR durable processing supervisor inside the backend process | Gated by `NIVX_EDR_WORKERS_DISABLED=1` (added during P4). No separate worker container exists. |
| **Redis** | **Not used.** No Redis client is pinned in `backend/requirements.txt` or any app's requirements; the grep hits are detection-content strings only. | **No Redis is required.** Do not provision one. |

### Does an isolated staging environment already exist?

**On paper yes, running nowhere.** `deploy/stage1-staging/` is a complete,
reviewed design, but there is **no evidence it has ever been executed**, and it
cannot be executed from this pod (section C). `deploy/docker-compose.yml` is a
*separate, softer* production-floor stack (`mongo:7` unpinned, Mongo port
published to the host, `restart: unless-stopped`) and **must not** be used for
isolated staging.

### Baseline mismatch in the packaging tooling — **action required**

`deploy/stage1-staging/source.json` pins:

```
commit ff66afe36efff3c0396b6e92ebaf21cae05d649a
tree   c2cdaf83a3ec7824f937ecc50bfd634637f0d632
```

That is the **Stage 1** commit, not the E3 baseline. Because the E3 history was
sanitized to a single root commit, `ff66afe3…` does not exist in this
repository, so `prepare.py` → `verify_source()` aborts and `test_package.py`
reports **8 passed / 2 errors**. This is the tooling correctly refusing an
unpinned tree, not a regression.

**Stage 2B must re-pin `source.json` to `1dc4e358…` / `19955236…` as an
explicit, reviewed commit.** It is the one source change Stage 2B requires and
it was deliberately not made during Stage 2A.

### ARM64 / AMD64

Base images are all official multi-arch (`python:3.11-slim`, `node:20-alpine`,
`nginx:1.27-alpine`), so either architecture builds. Two caveats:

1. **All E3 validation ran on ARM64 / CPython 3.11.17.** The owner's earlier
   note that ARM64 work is separate still stands; Stage 2B must declare the
   target architecture and re-run the gates there.
2. `python-snappy==0.7.3` required `libsnappy-dev` at install time on ARM64
   (it resolved through a `cramjam` wheel). The backend build context must
   prove this dependency installs on the chosen target architecture, or Snappy
   codec coverage silently regresses.

### Isolation from production

Confirmed achievable: `prepare.py` actively refuses production hostnames,
`preflight.py` forces secrets outside the repo at `0600`, compose demands
digest-pinned images and separate env files, `DB_NAME` is fixed to
`nivxray_stage1_staging`, and the `private` network is `internal: true`. No
production credential, database or DNS record is referenced anywhere in the
staging configuration.

---

## C · Security isolation feasibility — **BLOCKED on this host**

| Capability | State |
|---|---|
| `CAP_NET_ADMIN` | **ABSENT** |
| `CAP_NET_RAW` | **ABSENT** |
| `CAP_SYS_ADMIN` | **ABSENT** |
| `unshare -n` | `Operation not permitted` |
| `ip netns add` | `Operation not permitted` |
| `ip link add` | `Operation not permitted` |
| `nft add table` | `Operation not permitted` |
| **Container runtime** | **none** — `docker`, `dockerd`, `podman`, `nerdctl`, `buildah` all absent |
| External egress | reachable (`api.anthropic.com` → HTTP 405, DNS resolves) — therefore **not denied** |

Evidence: `/app/rocket-evidence/e3/egress_isolation_probe.txt`.

Kernel-enforced egress restriction **cannot** be established here, and with no
container runtime the existing compose cannot even be built or started. No
application-level network guard was substituted, and no privileged host change
was attempted.

### Exact target-host requirements

1. Linux host with a working **Docker Engine ≥ 24** (Compose v2) or Podman
   equivalent, and permission to create user-defined bridge networks.
2. `CAP_NET_ADMIN` available to the container runtime so `internal: true`
   networks actually install the deny rules, plus `iptables`/`nftables`
   present. Verify with: a container on `private` cannot resolve DNS and cannot
   reach any routable address, while the gateway on `ingress` can be reached on
   `127.0.0.1:18081` only.
3. Independent confirmation of **egress denial at the host** too — the pod
   showed that reachable egress is the default, so the target host must be
   firewalled or run in an isolated network namespace/VLAN. Host-level denial
   must be proven, not asserted in the compose attestations.
4. Declared architecture (ARM64 **or** AMD64) with ≥ 4 vCPU, ≥ 8 GB RAM and
   ≥ 40 GB disk (section D).
5. No shared bind mount, tunnel, VPN route or DNS entry to any production
   system; no production secret material on the host.
6. `mongosh` and `curl` inside the respective images for the existing
   healthchecks to function.

---

## D · Staging execution blueprint

### Architecture and dependency map

```
                    ingress (host-published, loopback only)
                             127.0.0.1:18081
                                   |
                             [ gateway:nginx 8080 ]   read-only, cap_drop ALL
                                   |  proxy_pass
  ======================= private network (internal: true, NO EGRESS) =========
                                   |
                            [ backend:8001 ]  read-only, cap_drop ALL,
                                   |          NIVX_EDR_WORKERS_DISABLED=1
                 +-----------------+------------------+
                 |                                    |
          [ mongodb:27017 ]                  [ response-engine:8080 ]
          authenticated, named volume        XDR_RESPOND_ENV=staging
          DB nivxray_stage1_staging          credential-gated, gateways UNSET
                 |
          [ collector ]  (optional, phase 2) XDR_AUTO_START_CONNECTORS=off
```

Startup order is already encoded by `depends_on` + healthchecks:
**mongodb (healthy) → backend (healthy) → gateway**. Response engine and
collector attach to `private` and depend on backend health.

### Infrastructure and resource footprint

| Service | CPU | Memory | Disk | Notes |
|---|---:|---:|---:|---|
| mongodb | 1 | 1 GB | 10 GB volume | limits already in compose |
| backend | 2 | 2 GB | — | tmpfs `/tmp` 256 MB |
| gateway | 0.5 | 128 MB | — | tmpfs only |
| response engine | 0.5 | 512 MB | 1 GB volume | **to be added**, needs writable `XDR_RESPOND_STATE_DIR` |
| frontend (if containerised) | 0.5 | 256 MB | — | static nginx |
| collector (optional) | 0.5 | 512 MB | 1 GB volume | **to be added** |
| Build headroom | — | — | ~15 GB | images + layers |
| **Total** | **~5 vCPU** | **~4.5 GB** | **~40 GB** | recommend 4–8 vCPU / 8 GB |

### Environment variable inventory — **names only, no values**

*Backend, required (`deps._REQUIRED_ENV`, startup refuses without them):*
`MONGO_URL`, `DB_NAME`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`,
`EMERGENT_LLM_KEY`.

*Backend, production secret closure (`security/secret_policy.py`):*
`EDR_AUTH_PEPPER`, `XDR_AUDIT_MASTER_SECRET`, `XDR_SECRETS_MASTER`,
`NIVXRAY_SIGNING_SECRET`, `XDR_ROOT_KEY`, `NIVX_DEPLOYMENT_ENV`.
Placeholder and development values are refused in production mode.

*Backend, staging behaviour:* `CORS_ORIGINS`, `NIVX_TENANT_REGISTRY_ENFORCE`,
`ADMIN_FORCE_PASSWORD_CHANGE`, `AUTO_INVESTIGATE_V1`,
`NIVX_FILES_SWEEP_ENABLED`, `JWT_EXPIRE_HOURS`,
`EDR_ENROLLMENT_TOKEN_TTL_SECONDS`, `EDR_AGENT_SESSION_TTL_SECONDS`,
`NIVX_AI_ENABLED`, **`NIVX_L3_DISABLE`** (set `1` — `NIVX_AI_ENABLED` does not
gate L3), **`NIVX_EDR_WORKERS_DISABLED`**, **`NIVXRAY_REPO_ROOT`** (only if
tests are run in-container), `XDR_RESPONSE_SERVICE_URL`,
`RESPONSE_ENGINE_SERVICE_CREDENTIAL`, `XDR_RESPONSE_SERVICE_TIMEOUT`.

*Response engine:* `XDR_RESPOND_ENV`, `RESPONSE_ENGINE_SERVICE_CREDENTIAL`,
`XDR_RESPOND_STATE_DIR`, `XDR_RESPOND_CORS_ORIGINS`,
`XDR_RESPOND_ALLOW_UNAUTHENTICATED_DEV` (**must be unset or `0`**),
`NIVX_BASE_URL`, `NIVX_EDR_DISPATCH_TIMEOUT`, `NIVX_RESPONSE_EVIDENCE_URL`,
`NIVX_RESPONSE_EVIDENCE_TOKEN`, `NIVX_RESPONSE_EVIDENCE_TIMEOUT`
— the last three **left unset** so no gateway is wired.

*Collector (if deployed):* `MONGO_URL`, `DB_NAME`, `NIVX_COLLECTOR_ID`,
`XDR_COLLECTOR_ID`, `NIVX_TENANT_ID`, `NIVX_INGEST_URL`, `NIVX_INGEST_TOKEN`,
`NIVX_INGEST_AUTH_MODE`, `NIVX_INGEST_TIMEOUT`, `NIVX_RECEIPT_URL`,
`NIVX_RECEIPT_TIMEOUT`, `NIVX_RECONCILE_TOKEN`, `XDR_STATE_DIR`,
`XDR_CORS_ORIGINS`, `XDR_AUTO_START_CONNECTORS` (**off**),
`XDR_DISABLE_DELIVERY_WORKER`.

*Mongo:* `MONGO_INITDB_ROOT_USERNAME`, `MONGO_INITDB_ROOT_PASSWORD`,
`MONGO_INITDB_DATABASE`, `STAGING_MONGO_USER`, `STAGING_MONGO_PASSWORD`.

*Compose:* `MONGO_IMAGE`, `BACKEND_IMAGE`, `NGINX_IMAGE`, `MONGO_ENV_FILE`,
`BACKEND_ENV_FILE`, `STAGING_FRONTEND_ORIGIN` (+ new `RESPONSE_IMAGE`,
`RESPONSE_ENV_FILE`).

**Never set in staging:** `VERCEL_TOKEN`, `TEST_ANALYST_NIVXLIVE_PASSWORD`, or
any production credential. All secret files live outside the repo at `0600`,
enforced by `preflight.py`.

### Database and Redis isolation

- Fresh named volume, fresh `nivxray_stage1_staging` database, least-privilege
  application user created by `mongo-init.js`; root credentials used only for
  initialisation. Authentication must be **on** (unlike the pod's unauthenticated
  disposable instance). No dump, restore or copy from any production database.
- The response engine keeps its own SQLite store at `XDR_RESPOND_STATE_DIR` on a
  dedicated volume — **not** the image-baked `data/executions.db`.
- **Redis: not required and must not be provisioned.** No client dependency exists.

### Network isolation and firewall requirements

1. `private` stays `internal: true`; only the gateway joins `ingress`.
2. Gateway publishes to **`127.0.0.1` only** — never `0.0.0.0`.
3. Host-level default-deny egress for the staging bridge, independently proven.
4. No production DNS, hosts entry, tunnel or VPN route on the host.
5. Positive proof required: from inside `backend`, DNS resolution and outbound
   TCP must both fail; from the host, `127.0.0.1:18081/api/health` must succeed.

### Safe deployment sequence

1. Import the verified bundle into a fresh clone; confirm commit `1dc4e358…`
   and tree `19955236…`.
2. **Re-pin `source.json`** to the E3 commit/tree (reviewed change) and confirm
   `test_package.py` reaches 10/10.
3. Provision secret/env files outside the repo at `0600`; run `preflight.py`.
4. Build images on the target architecture; record each image **sha256 digest**
   and set `MONGO_IMAGE`/`BACKEND_IMAGE`/`NGINX_IMAGE`/`RESPONSE_IMAGE`.
5. Prove egress denial **before** starting the application (step 5 of section C).
6. `compose up` in dependency order; wait for healthchecks.
7. Verify the backend refuses to serve on missing/placeholder secrets.
8. Confirm `NIVX_EDR_WORKERS_DISABLED=1` appears in the startup log.
9. Seed only synthetic tenants/identities; force the admin password change.
10. Run the acceptance entry criteria below.

### Rollback procedure

Staging-only, nothing in production to roll back. `compose down` (add `-v` to
destroy volumes), delete the staging database and volumes, remove the built
images by digest, revoke the synthetic credentials, and discard the isolated
branch/worktree. Baseline `1dc4e358…` and the verified bundle remain intact as
the recovery point. Because `restart: "no"` is set, no container self-revives.

### Acceptance test entry criteria

Stage 2B acceptance may begin only when **all** hold:

1. Bundle/commit/tree verified on the target host; working tree clean.
2. `test_package.py` 10/10 after the `source.json` re-pin.
3. `preflight.py` passes with secrets outside the repo at `0600`.
4. All images digest-pinned; digests recorded.
5. **Kernel-enforced egress denial positively proven** on both the container
   network and the host.
6. Backend health green; worker-disable log line present.
7. Backend proven to refuse placeholder/missing secrets.
8. Response engine reachable only with the service credential; evidence
   gateways unset; `forwarder: not_wired`; zero execution records.
9. Database empty apart from synthetic provisioning.
10. Backend gates re-run **on the target architecture**: 774 passed / 0 failed,
    A0.5 74/0, frontend 420/0, Vite build PASS, RC3.0 benchmark PASS.

### Blockers and security HOLDs

**Hard blockers for Stage 2B**

| # | Blocker | Owner action |
|---|---|---|
| B1 | No container runtime and no `CAP_NET_ADMIN`/`CAP_SYS_ADMIN` in this pod | Provide a target host (section C) |
| B2 | `source.json` pins a non-existent Stage 1 commit | Approve re-pin to `1dc4e358…` / `19955236…` |
| B3 | Response engine absent from staging compose and its Dockerfile is unhardened (root, no healthcheck, bakes `data/executions.db`) | Approve adding a hardened service + non-root image |
| B4 | Host-level egress denial unproven | Firewall/namespace the target host and prove it |
| B5 | Frontend has no compose service (Stage 1 assumed Vercel) | Decide: internal container, or reviewed external origin |

**Lower severity**

| # | Finding |
|---|---|
| L1 | `apps/nivxray-xdr-response/data/executions.db` and `apps/nivxray-xdr-collector/.state/connectors.json` are tracked runtime state; untrack before image build |
| L2 | `deploy/docker-compose.yml` is a softer production-floor stack (unpinned `mongo:7`, published Mongo port, `restart: unless-stopped`) — must not be used for isolated staging |
| L3 | ARM64-only validation; `python-snappy` needs `libsnappy-dev` proof on the chosen architecture |
| L4 | Collector not yet modelled in staging |

**All ten E3 release HOLDs remain open and unwaived.** Stage 2A waived none and
weakened no security contract.

---

## E · GO / NO-GO recommendation for Stage 2B

> **CONDITIONAL GO — on a provisioned target host. NO-GO in this environment.**

The engineering baseline is verified and clean, and the staging design is
already written to a high standard: internal-only networking, digest-pinned
images, read-only root filesystems, dropped capabilities, resource caps, secrets
forced outside the repository, and tooling that actively refuses production
hostnames. That is a strong foundation and should be reused, not rebuilt.

Stage 2B cannot proceed **here**: there is no container runtime, and the
capabilities needed for kernel-enforced isolation are absent — the same
constraint that blocked FULL_E2E. Proceeding would mean substituting
application-level guards for kernel isolation, which is explicitly prohibited.

Clear B1–B5 and Stage 2B becomes a low-risk, mechanical execution of the
sequence above. **Production remains NO-GO** independently of staging.

Awaiting instruction before beginning Stage 2B.
