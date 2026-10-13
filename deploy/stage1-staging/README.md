# Stage 1 isolated staging package — NOT a deployment approval

Application source is fixed at `ff66afe36efff3c0396b6e92ebaf21cae05d649a`,
tree `c2cdaf83a3ec7824f937ecc50bfd634637f0d632`. Packaging changes only; no
engine/UI/authentication code changes and no Stage 2A source. Existing EDR
modules in the pinned monolith are preserved dependencies, not activated features.
Native UI: `apps/nivxray-xdr`; never build `/frontend` or the old Workspace.

## Disposition and topology

GO for package review. HOLD for provisioning, startup, deployment, production,
EDR, MITRE exposure, NCI admission/service delegation and automatic telemetry.
This package is a reference for an independently owned non-production Docker
host, not an unverified Emergent deployment recipe. If Emergent cannot enforce
the network, process/resource, ingress and independent database controls below,
stop: do not adapt them into weaker settings. No paid infrastructure is created.

Vercel staging-only native frontend -> staging TLS ingress -> loopback gateway
-> one backend process -> authenticated MongoDB on an internal Docker network.
Only gateway joins an ingress network. Backend/Mongo publish no ports. Mongo
uses a fresh project-scoped volume and a readWrite app account restricted to
`nivxray_stage1_staging`; root credentials are separate. No data restore, shared
production cluster, production secrets, endpoint agents, Redis, response engine,
standalone collector, live connectors or durable NCI queues are included.

Docker `internal: true` is one control, not proof of complete host isolation.
Use a non-production host with no production service/volume on it. Owner must
enforce host firewall rules denying backend/Mongo traffic to host services,
production networks, cloud metadata and the Internet, for IPv4 and IPv6.
No external LLM/TI access is allowed during this slice. Background startup tasks
can fail because egress/root writes are denied: failures must be assessed, never
silenced. Container resource allocations are provisional budgets, not measured
sizing; require host headroom and validate CPU/RSS/PID exhaustion independently.

Gateway rejects response/action/EDR paths, endpoint admission, legacy artifact
and decoder access, plus percent-encoded/path-traversal tricks. The API backend
is reachable only through this gateway. Direct host access, another reverse
proxy, or an internal administrative tunnel would bypass this boundary and is
prohibited. API paths intentionally blocked must show honest unavailable states
in the native UI; UI preservation is not permission to enable those paths.

`AUTO_INVESTIGATE_V1=off` and retention sweep off are deliberate admission
HOLDs. Job/WebSocket ownership and decoder tests still run locally/CI. To test
those APIs live later, require a separately approved narrowed ingress/flag
configuration after legacy-cache and Mongo/worker acceptance. Do not silently
remove gateway blocks to make an end-to-end test pass.

## Required configuration (names only)

Templates contain blank names, not credentials or defaults. Owner provisions
secrets through the approved secret store into private files outside Git, with
mode 0600. Never use `docker compose config` without `--quiet` because it prints
resolved secrets. Do not upload env files, logs containing inputs, or credentials.

* `compose.env.example`: image digests, external env-file paths and staging
  frontend origin. Image references must use independently reviewed sha256
  digests. Backend digest must correspond to the pinned build and labels below.
* `backend.env.example`: Mongo connection, administrator, LLM startup key,
  authentication/audit/vault/signing keys and TTLs. All independent of production.
  URI must target service `mongodb`, port 27017, database/authSource
  `nivxray_stage1_staging`, using the staging app account, with URI-escaped
  credentials. Do not use root. No arbitrary extra env keys are admitted.
* `mongo.env.example`: independent root/app account names/passwords and the
  staging database name. Initialization applies only to a NEW empty volume;
  changed env files do not rotate existing Mongo credentials.
* Frontend public build settings: `XDR_PROD_API_ORIGIN`,
  `XDR_GUARD_EXPECTED_API`, `NIVX_PRODUCT_SCOPE`,
  `NIVX_CROSS_PRODUCT_ORIGINS`, `NIVX_WORKSPACE_ORIGIN`.

Backend `NIVX_DEPLOYMENT_ENV=production` invokes existing strict secret checks
on isolated staging resources. It is a security mode, not production targeting.
Literal `staging` is unsupported. Existing mandatory EDR pepper/TTLs are supplied
only to satisfy monolith validation, not to admit EDR devices. `EMERGENT_LLM_KEY`
is mandatory even for deterministic startup; an approved independent staging
credential is required. Do not use a fabricated key or relax startup validation.

## Preparation/build (safe local steps, no startup)

Prerequisites: Python 3.12, Git with the pinned objects, Node/Yarn 1.22.22 and,
for image work, a Docker builder. Existing dependency files remain untouched.
Choose owner-verified staging origins; generic `.invalid` template cannot deploy.
The preparation script checks ancestry and scope and reads only pinned Git blobs.
It excludes runtime databases, dotfiles/secrets, old Workspace, tests/docs/exports
from runtime context. Backend runtime modules, including inherited shared modules,
remain byte-identical. Frontend Vercel/CSP overlay is recorded separately.

```bash
python deploy/stage1-staging/prepare.py --verify-only
python -m unittest discover -s deploy/stage1-staging -p test_package.py -v
git diff --check ff66afe36efff3c0396b6e92ebaf21cae05d649a HEAD
python deploy/stage1-staging/prepare.py --context "$STAGING_CONTEXT" --api-origin "$STAGING_API_ORIGIN"
```

Context must be new and outside the repository. Set the public variables below
to the same isolated API origin; the existing script otherwise defaults to the
production API. Cross-product origin variables remain unset. Build only locally:

```bash
cd "$STAGING_CONTEXT/apps/nivxray-xdr"
npx --yes yarn@1.22.22 install --frozen-lockfile --non-interactive
CI=true NIVX_PRODUCT_SCOPE=xdr NIVX_CROSS_PRODUCT_ORIGINS=0 NIVX_WORKSPACE_ORIGIN='' \
  XDR_PROD_API_ORIGIN="$STAGING_API_ORIGIN" XDR_GUARD_EXPECTED_API="$STAGING_API_ORIGIN" \
  bash scripts/vercel-build.sh
```

Use prepared context root with `backend.Dockerfile`; `PYTHON_BASE` must be a
reviewed Python 3.11 Linux sha256 digest. Build, do not run:

```bash
docker build --build-arg PYTHON_BASE="$PYTHON_BASE" \
  --build-arg SOURCE_SHA=ff66afe36efff3c0396b6e92ebaf21cae05d649a \
  --build-arg SOURCE_TREE=c2cdaf83a3ec7824f937ecc50bfd634637f0d632 \
  -f "$STAGING_CONTEXT/backend.Dockerfile" -t nivxray-stage1-staging:review "$STAGING_CONTEXT"
```

Record backend image ID/digest, labels, dependency inventory, runtime versions,
build logs with secrets excluded, and SHA256 for source-manifest.json and every
frontend dist file. Requirements include existing non-exact dependencies;
matching application source is not bit-for-bit dependency reproducibility.
Capture/approve resolved wheels and base/OS package versions before release.
No version substitutions, resolver bypasses or integrity relaxation are allowed.

For Vercel, a NEW staging-only project uses root `apps/nivxray-xdr`, prepared
`vercel.json`, frozen install, existing build script, `dist`, independent settings
and Deployment Protection. CSP permits connections only to self and the explicit
staging HTTPS/WSS origin. First deployment may be called Production inside this
new project; it must still have NO production domain/config/resources. Uploading
prepared source/deploying or linking projects is NOT authorized by this package.
Use an explicit prepared-source deployment workflow later, never a default Git
build that ignores the staging overlay. CSP and scope/render behavior need browser
acceptance; do not weaken CSP when external assets fail.

## Offline checks before any approved startup

```bash
python deploy/stage1-staging/preflight.py --config "$STAGING_COMPOSE_ENV"
docker compose --env-file "$STAGING_COMPOSE_ENV" -f deploy/stage1-staging/compose.yml config --quiet
```

Never issue `up` in this preparation task. Before future owner-authorized startup:
verify empty-volume identity, no production routing/credentials, host firewall,
image labels/digests, application secret policy, TLS/CORS and available resources.
Nginx config must pass `nginx -t` on the reviewed image. Verify the backend's
existing startup/index/seed sequence succeeds or gives explicitly assessed errors
on isolated Mongo, without enabling optional features or writable source mounts.
Read-only root may expose a real startup incompatibility: report it as BLOCKED;
approve a specific staging-only writable volume only after identifying its need.

## Deterministic CI and synthetic acceptance

`stage1-staging-package.yml` has no deploy command, secrets or write permission.
It checks package negatives and source scope; a separate job checks the exact
Stage1 preservation tests, native 124-test suite and unchanged build guard using
an unused synthetic HTTPS origin. CI success does not certify a hosted system.

After approved deployment, use ONLY synthetic records and isolated app accounts:

1. Record SHA/tree/image/artifact/backend origin and configuration names; liveness
   is not database readiness. Assert required indexes/unique ownership constraints,
   startup seeds and audit persistence on staging Mongo. Test job concurrency and
   restart/reconciliation separately; HOLD until evidenced.
2. Provision users AND existing RBAC memberships with supported grants for
   Administrator-A, Analyst-A and MSSP-A/B. C is unauthorized, B can be suspended.
   Use existing provisioning authorities, never fabricated client permission sets.
3. Browser login/password rotation, scope switch/refresh/history, direct routes,
   queue/investigation loading, delayed responses, missing verdict/score and 401/403.
   Confirm zero browser requests to production origins and CSP denial of attempted
   production API access. No production request is sent to prove this.
4. Manual Command Intelligence submits `{input, automatic:true}` with harmless
   plain and UTF-16LE/Base64 commands; require `command-intelligence/1`, original
   evidence, failure/limitations and truthful spans. Test malformed/oversized input,
   timeout/process cleanup and concurrent busy admission on the actual staging host.
5. Test foreign/revoked/suspended tenant reads against the gateway and real stored
   grants; 401/403 must not cause alternate requests or stale evidence presentation.
6. Response, EDR, telemetry/collector, legacy-cache and job routes remain denied.
   Test gateway denial using harmless nonexistent identifiers with staging accounts.
   Confirm no response engine/service credential/endpoint exists and no backend
   connection to production is possible. Never send an executable action to an
   endpoint, even as a negative test. Inventory nested/encoded routes and WebSockets.
7. Stop on any build/startup/auth/ownership/resource/contract/network failure.
   Record exact PASS/FAIL/SKIP/BLOCKED counts; missing gates are not passes.

Mongo/RBAC regression procedure already exists in
`docs/releases/XDR_RC2_READINESS_2026-10-12.md`; use its disposable loopback-only
synthetic fixture, not a staging or production URI. Existing Stage1 519 backend /
124 frontend results are historical preservation evidence, not this package's
runtime acceptance. This package does not rerun the separate 647 NCI suite.

## Rollback and outstanding HOLDs

Before startup, owner records a staging-only project/service/volume inventory.
On failure, stop only these staging services. Preserve logs with secrets/evidence
redacted and the synthetic volume for diagnosis; do not run volume deletion or
restore production data. A later approved reset recreates the empty staging volume.
Frontend rollback changes ONLY the staging project to its previous reviewed
artifact (or removes staging access if this is its first deployment). Restore
matched backend/frontend artifacts and compatible staging storage; never relax
authentication to restore access. Production domains and services stay untouched.

HOLDs: independent release/security review; CI completion; image/dependency and
host sizing; authenticated browser/API acceptance; legacy unowned cache exposure;
Mongo concurrency/reconciliation; job/stream admission; NCI permissions/delegation;
response execution authorization; IOC/CI-09/credential/runtime hygiene; MITRE;
EDR feature work; production release. No gate is closed by package publication.

Next owner action: approve the target staging host/project and evidence that it
can enforce this isolation profile. If choosing the created Emergent staging
project, obtain platform confirmation of separate Mongo/credentials and outbound,
ingress, resource and storage controls before granting deployment authorization.
