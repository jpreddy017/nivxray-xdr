# Stage 2B Part 1 — staging package repair

Date: 2026-10-16
Branch: `engineering/e3-stage2b-package` (isolated; never pushed)
Disposition: **no deployment performed.** Production remains **NO-GO**.

---

## Deliverable 1 · Branch, commits and trees

| Item | Value |
|---|---|
| Branch | `engineering/e3-stage2b-package` |
| Baseline parent | `1dc4e35809c4b30bda15d0ed25db06c6feb50e24` / tree `1995523652e25ff86de3cec19741199e55bec55f` (verified E3) |
| Commit 1 — application hardening (**the pinned packaging source**) | `b30497f8281dc74555bd5585442565b631a41591` / tree `d3429be0c847add8a086dc81aa83379743617fe4` |
| Commit 2 — packaging (**HEAD**) | `a1e1be573329471ac737998cb34344e8e9b4aeed` / tree `c6947a872c82a503a6107ff5bf5fad3c318405d3` |
| Working tree | clean (0 entries) |
| Bundle | `/app/rocket-evidence/e3/nivxray-e3-stage2b-part1.bundle` — 23,511,981 bytes, SHA-256 `58d52d5c3702a3473d3a5e2bdf023cb686abedfa419bea0d30b8b547f5e7a019` |
| Bundle re-verified | fresh clone: tip and tree match, 8 commits, no alternates, `fsck` clean, **0 tracked `.db`/`.sqlite` files** |

### Why the pin is commit 1 and not the E3 commit directly

`prepare.verify_source()` enforces that the packaging candidate contains **no
application changes** — every path in `diff(pinned, HEAD)` must sit under
`deploy/stage1-staging/`. Pinning `1dc4e358…` directly while also hardening the
response image and untracking runtime state would have put application paths in
that diff, and the only way to make it pass would have been to widen the
allowlist — i.e. weaken the admission control I was told to preserve.

So the work is split: commit 1 carries the reviewed application changes, the pin
points at commit 1, and commit 2 is packaging-only. `diff(b30497f8, HEAD)` is
exactly nine files, all under `deploy/stage1-staging/`.

**Provenance was strengthened, not relaxed.** `source.json` now also records
`e3_acceptance_commit` / `e3_acceptance_tree`, and `verify_source()` performs
three checks instead of one: the pinned tree matches, the E3 acceptance tree
matches, and the pinned commit **descends from** that verified baseline.

---

## Deliverable 2 · Changed-file inventory (17 files vs the E3 baseline)

**Commit 1 — application (8 files, pinned source)**

| File | Change |
|---|---|
| `apps/nivxray-xdr-response/Dockerfile` | +35/−? rewritten: multi-stage, non-root uid/gid 10001, read-only app tree (0555/0444), `data/` and `tests/` removed, state dir defaulted to a mount point, `HEALTHCHECK` added |
| `apps/nivxray-xdr-response/.dockerignore` | new (18 lines) |
| `apps/nivxray-xdr-collector/.dockerignore` | new (18 lines) |
| `.gitignore` | +8: ignore `apps/nivxray-xdr-response/data/` and `apps/nivxray-xdr-collector/.state/` |
| `apps/nivxray-xdr-response/data/executions.db` | **untracked** (24,576 bytes of runtime state removed from Git) |
| `apps/nivxray-xdr-collector/.state/connectors.json` | **untracked** (19 lines) |
| `backend/tests/test_stage2b_runtime_state_hygiene.py` | new, 10 tests |
| `tools/rocket-validation/run.py` | +1/−1: register the new test in the boundaries gate |

**Commit 2 — packaging (9 files, all under `deploy/stage1-staging/`)**

| File | Change |
|---|---|
| `source.json` | repinned to `b30497f8` / `d3429be0`, plus E3 provenance fields and a `response` path |
| `prepare.py` | +22: descendant check, response build context exported, stricter context `.dockerignore`, frontend `.env.staging` emitted |
| `preflight.py` | +19: `RESPONSE_IMAGE` digest admission, service-credential validation and cross-file match |
| `compose.yml` | +51: hardened `response` service, `response-state` volume, backend wiring |
| `test_package.py` | +94: seven new/extended tests |
| `compose.env.example` | +2 (`RESPONSE_IMAGE`, `RESPONSE_ENV_FILE`) |
| `backend.env.example` | +1 (`RESPONSE_ENGINE_SERVICE_CREDENTIAL`) |
| `response.env.example` | new (names only) |
| `README.md` | +35: response build procedure, simulation-only statement, frontend staging env, updated build args |

No application behaviour was changed. No security contract was weakened. No
unrelated code was touched.

---

## Deliverable 3 · Test counts

| Suite | Passed | Failed | Skipped | Note |
|---|---:|---:|---:|---|
| `deploy/stage1-staging/test_package.py` | **16** | 0 | 0 | was **8 passed / 2 errors** |
| `prepare.py --verify-only` | PASS | — | — | "Pinned source verified" |
| `backend/tests/test_stage2b_runtime_state_hygiene.py` | 10 | 0 | 0 | new |
| boundaries gate | **122** | 0 | 0 | 112 → 122 |
| response gate | 39 | 0 | 0 | unchanged |
| tenant gate | 104 | 0 | 0 | unchanged |
| response engine own suite (`apps/nivxray-xdr-response/tests`) | 39 | 0 | 0 | engine, service auth, vendor adapters |

Broader suites (decoder, command, frontend, A0.5, RC3.0) were **not re-run**:
commit 1 changes no Python that those suites import, and commit 2 touches only
packaging. Re-running them would have added cost without covering any changed
code path.

---

## Deliverable 4 · Updated staging package

Export is reproducible: two consecutive exports produced byte-identical
manifests covering **2,131 files** from the pinned commit.

Services now modelled: `mongodb`, `backend`, **`response`**, `gateway` — all on
the `internal: true` `private` network except the gateway, which also joins
`ingress` and publishes only to `127.0.0.1:18081`.

**Response engine security posture**

| Control | Setting |
|---|---|
| User | `10001:10001`, non-root, dedicated system account |
| Filesystem | `read_only: true`, app tree `0555`/`0444`, tmpfs `/tmp` 64 MB |
| Capabilities | `cap_drop: [ALL]`, `no-new-privileges:true` |
| Resources | 512 MB, 0.5 CPU, 64 pids, `init: true`, `restart: "no"` |
| Network | `private` only, **no published ports** |
| State | `response-state` volume at `/var/lib/nivxray-respond`; nothing in the image |
| Health | unauthenticated `/health` probe only |
| Auth | `RESPONSE_ENGINE_SERVICE_CREDENTIAL` required on every `/api/respond/*` call |

**Simulation-only, by construction**

- `XDR_RESPOND_ENV: production` → the unauthenticated development bypass in
  `security/service_auth.py` is unreachable, since it requires
  `development`/`test`.
- `XDR_RESPOND_ALLOW_UNAUTHENTICATED_DEV: "0"` pinned, belt and braces.
- `NIVX_BASE_URL`, `NIVX_RESPONSE_EVIDENCE_URL`, `NIVX_RESPONSE_EVIDENCE_TOKEN`
  all blank → forwarder reports `not_wired`; no real endpoint containment and
  no external evidence forwarding is reachable.
- Approval-gated actions still require approval; the engine's own 39 tests pass.

**Frontend** keeps its existing static hosting model — not replaced. The
prepared context now carries `apps/nivxray-xdr/.env.staging` pinning
`REACT_APP_NIVXRAY_API_URL` to the isolated staging API origin, so a build
cannot silently default to a production host. The CSP rewrite already restricted
`connect-src` to self plus that origin. A test asserts the emitted file contains
the staging origin and **no** `nivxforge.com`.

---

## Deliverable 5 · Security assessment

**Improved by this work**

1. The response engine no longer runs as root and no longer bakes its execution
   database into an image layer — previously `COPY . .` on a tracked
   `data/executions.db` would have shipped real execution records.
2. Runtime state left Git entirely, so test runs stop dirtying the tree and a
   populated store can no longer reach a build context. A guard test fails if
   any `.db`/`.sqlite` is ever tracked again.
3. Source provenance is strictly stronger: three checks, and the pinned commit
   must descend from the independently verified E3 baseline.
4. Service-credential admission is new: the credential must be ≥ 32 characters,
   free of placeholder markers, **not reused** for any cryptographic purpose,
   and identical in the backend and response env files — a mismatch would
   otherwise fail closed at 401 only at runtime.
5. `RESPONSE_IMAGE` must be a sha256 digest, like every other image.
6. The engine is reachable only from inside the egress-denied private network.

**Unchanged and preserved**

Internal-only networking, loopback-only publication, Mongo least-privilege app
account, distinct cryptographic secrets, secrets outside the repository at
`0600`, production-hostname refusal, tenant registry enforcement, forced admin
password change, and the A0.5 authorization contracts.

**Residual risks (not mitigated here)**

- `XDR_RESPOND_CORS_ORIGINS` is blank; if a browser must reach the engine
  directly in Part 2, that value needs explicit review rather than widening.
- The engine image's `HEALTHCHECK` uses `urllib` against its own loopback; it
  proves liveness, not authorization posture. Authorization is proven by the
  boundaries/response suites and the Stage D trace instead.
- Dependency reproducibility is still not bit-for-bit (pre-existing README
  caveat): resolved wheels and base OS package versions must be captured and
  approved before release.

---

## Deliverable 6 · Remaining target-host requirements

Unchanged from Stage 2A and **still unmet in this environment**:

1. Working container runtime (Docker Engine ≥ 24 / Compose v2 or Podman).
   This pod has none, so **nothing was built and nothing was started.**
2. `CAP_NET_ADMIN` available to the runtime so `internal: true` installs real
   kernel deny rules. This pod lacks `CAP_NET_ADMIN`, `CAP_NET_RAW` and
   `CAP_SYS_ADMIN`.
3. Host-level default-deny egress, independently proven — the pod demonstrated
   reachable egress is the default.
4. Declared architecture (ARM64 or AMD64) with ≥ 4 vCPU, ≥ 8 GB RAM, ≥ 40 GB
   disk; `python-snappy` install proven on that architecture.
5. Digest references for `MONGO_IMAGE`, `BACKEND_IMAGE`, `NGINX_IMAGE` and
   `RESPONSE_IMAGE` recorded after building on the target host.
6. Owner-provisioned `compose.env`, `backend.env`, `mongo.env` and the new
   `response.env`, all outside the repository at `0600`.

> **No kernel-enforced egress acceptance is claimed.** It has not been executed
> on a suitable host, and no application-level guard was substituted for it.

---

## Deliverable 7 · GO / NO-GO for Stage 2B Part 2

> **GO for Part 2 — conditional on a provisioned target host.**

The package itself is now complete and self-consistent: provenance verifies,
admission tests pass 16/16, the export is reproducible at 2,131 files, the
response engine is integrated under hardened, simulation-only settings, runtime
state is out of Git and out of every build context, and the frontend keeps its
existing architecture while being pinned away from production.

Of the five Stage 2A blockers, **B2 (source pin), B3 (response engine) and B5
(frontend) are closed**. **B1 (container runtime and capabilities) and B4
(host egress denial) remain open and are environmental, not code.** Part 2
cannot build or run anything until a suitable host exists.

All ten E3 release HOLDs remain open and unwaived. No push, merge, deployment,
provisioning, production access or real response action occurred.

Stopping after Part 1 as instructed.
