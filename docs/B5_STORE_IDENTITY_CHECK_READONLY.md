# B5 — STORE IDENTITY CHECK (READ-ONLY)

Executed 2026-09-29. Read-only configuration/routing/runtime evidence only.
No patch, no deploy, no endpoint change, no sensor/domain repointing, no data copy,
no synthetic telemetry, no UI work, no E3.
Network activity performed: DNS resolution + two unauthenticated `GET /api/health` calls
(no payload, no ingest path, no authentication, no telemetry).

## CHECK 1 — CUSTOM DOMAIN ROUTING (nivxray.nivxforge.com)

| Evidence | Value |
|---|---|
| DNS A records | `162.159.142.117`, `172.66.2.113` (Cloudflare edge) |
| `nivxforge.com` apex | same two Cloudflare IPs |
| Response headers | `server: cloudflare`, `cf-ray: ...-ORD`, `via: 1.1 google`, `strict-transport-security`, `referrer-policy`, `x-content-type-options` |
| `GET /api/health` | `200 {"status":"ok","service":"nivxray-api"}`, `x-request-id: nvx-4873ceb31f7c` |
| Deployment binding (repo deployment metadata) | `deployer-agent-docs/RCA_814dd0d5-...MD`: "**Deployment:** greeting-app-5782 · **Custom domain:** nivxray.nivxforge.com (verified) · frontend_type = cloudflare · target-3" |
| Production runtime shape (same RCA) | k8s Deployment, **2 replicas**, nginx fronting **:8080**, backend uvicorn **:8001**, resource **tier_0** (250m CPU / 512Mi), HPA/VPA disabled |
| Production database configuration | **NOT VISIBLE FROM THIS POD.** The deployed pods receive their own env/secrets at deploy time; no production `MONGO_URL` is present in or readable from this workspace. Nothing redacted because nothing was found. |

So: the custom domain terminates at Cloudflare and is served by the **deployed production runtime** of the `greeting-app-5782` app — a separate set of k8s pods with its own nginx layer and its own injected configuration. It is the same *codebase/app*, not the same *runtime*.

## CHECK 2 — CURRENT POD IDENTITY (where my queries ran)

| Evidence | Value |
|---|---|
| Container hostname | `agent-env-630704a1-621f-478b-9b86-a321772d01bf` |
| Environment classification | **PREVIEW / agent development pod** — env var `preview_endpoint = https://greeting-app-5782.preview.emergentagent.com` |
| Preview DNS | `104.18.10.243`, `104.18.11.243` (different Cloudflare edge set; `cf-ray ...-ATL`) |
| Preview `GET /api/health` | `200 {"status":"ok","service":"nivxray-api"}`, plus preview-only headers (`access-control-allow-origin: *`, `cache-control: no-store`, `x-robots-tag: noindex`, `__cf_bm` cookie scoped to `preview.emergentagent.com`) — a header profile the production origin does NOT emit |
| Backend process | `uvicorn`/`python` listening `0.0.0.0:8001` in THIS container (pid 22384/22386) |
| Datastore actually queried | `MONGO_URL = mongodb://localhost:27017`, `DB_NAME = test_database` |
| Datastore process | `mongod --bind_ip_all`, **pid 278, running INSIDE this same agent container**, listening `0.0.0.0:27017` |
| Ingress exposure of that mongod | none — only `3000` (frontend) and `8001` (`/api`) are routed through the preview ingress; `27017` is not exposed |
| Job metadata | `.emergent/emergent.yml`: `job_id 486146a0-9a5d-462a-8072-904d27d6c533`, created `2026-09-27T13:34:38Z` (this forked workspace) |

Equivalence was NOT inferred from branch, repo, app name, or schema.

## CHECK 3 — STORE EQUIVALENCE

```
STORE_IDENTITY = DIFFERENT_STORE_PROVEN
```

Concrete basis (not a code/schema/name argument):

1. The evidence store I queried is a **container-local `mongod` (pid 278)** running inside the agent development container `agent-env-630704a1-...`, addressed as `mongodb://localhost:27017`.
2. That mongod is reachable **only from inside this container** — port 27017 has no ingress route, no service exposure, and no public address.
3. The production runtime serving `nivxray.nivxforge.com` is a **different set of k8s pods** (2 replicas, own nginx:8080, own tier_0 resource envelope, own injected configuration), in a different deployment, behind a different Cloudflare edge path.
4. Therefore **no request delivered to `nivxray.nivxforge.com` can possibly write into the store I queried.** The sensor's bytes cannot land in `test_database` on this container's loopback.

Corollary, stated explicitly: **absence of EID5 in the store I queried is NOT evidence that the production/custom-domain backend has not received EID5.** The prior `B5_EID5_DELIVERY_RECHECK` arrival conclusions apply ONLY to this preview store and must not be read as a production receive failure.

This also explains why this store only ever shows the September 22 / September 25 XDR-collector rows: those rows were ingested into this workspace's local store during earlier preview-side work, and no sensor traffic has ever been delivered to this store's ingress.

## CHECK 4 — DIFFERENT STORE IS PROVEN: READ-ONLY ACCESS OPTIONS

Nothing was modified. No data copied. Domain and endpoint untouched.

Access I have today:
- Full read of the **preview** store (`localhost:27017` / `test_database`) — **not authoritative** for endpoint telemetry.
- Read of the repository, deployment metadata in-repo, and unauthenticated production HTTP endpoints.
- **No** production `MONGO_URL`, no production DB credentials, no production shell, no production log access from this pod.

Read-only methods that WOULD be authoritative, in order of directness:

1. **Production-state diagnosis via the Emergent deployer in debug/diagnose mode** (read-only RCA: reads pod runtime, build/pipeline logs, production secret *presence*, DB binding, routing). This is the designed read-only path to answer "what database is the production backend bound to, and is it receiving?" — it diagnoses, it does not deploy and cannot write to production data. **I have NOT invoked it; it needs your explicit go-ahead since it touches the deployment surface.**
2. **Authenticated read-only API queries against `https://nivxray.nivxforge.com`** using the existing admin login and the already-built read endpoints (e.g. endpoint list, raw-event stats, trajectory by host, canonical evidence lookup by ProcessGuid). This asks production for its own evidence without writing anything. Requires: your consent to authenticate against production, and confirmation of which credential to use. **NOT done — I did not authenticate to production.**
3. **Production deployment panel / secrets view (owner-side)** to read the production `DB_NAME` and Mongo binding directly. Requires owner action; I cannot read it.

What would be required from you for each: (1) approval to run the deployer in debug mode; (2) approval + credential for authenticated production reads; (3) nothing from me — owner-side UI read.

## CHECK 5 — SAME STORE

Not applicable (`DIFFERENT_STORE_PROVEN`). No polling performed.

## CHECK 6 — RECEIVE-BOUNDARY REINTERPRETATION

The earlier statement "PENDING DOWNSTREAM BOUNDARY = BACKEND RECEIVE" is **superseded and was imprecise**, because it was measured against a store that is not the sensor's destination.

Corrected:

```
PENDING_BOUNDARY = AUTHORITATIVE_RECEIVE_STORE_IDENTITY
```

Now resolved one step further: the authoritative store is **not** the one queried, and is **not currently readable from this pod**. No telemetry loss is inferred anywhere.

## EVIDENCE TABLE

| Question | Evidence | Result |
|---|---|---|
| Sensor destination | owner read-only service/config check | `https://nivxray.nivxforge.com` (CONFIRMED, unchanged) |
| Custom-domain routing | DNS `162.159.142.117` / `172.66.2.113` (Cloudflare); in-repo deploy RCA: deployment `greeting-app-5782`, custom domain verified, frontend_type cloudflare, target-3; `GET /api/health` → 200 `nivxray-api` | Production deployed runtime (2 replicas, nginx:8080, tier_0) |
| Current Emergent environment | `preview_endpoint` env var; container `agent-env-630704a1-...`; preview-only response headers; job `486146a0-...` | PREVIEW / agent development pod |
| Current database | `MONGO_URL=mongodb://localhost:27017`, `DB_NAME=test_database`, `mongod` pid 278 inside this container | Container-local, no ingress exposure |
| Same runtime? | different pods, different nginx layer, different edge path, different header profile | **NO** |
| Same evidence store? | queried store is loopback-only inside the agent container; unreachable from production pods | **NO — DIFFERENT_STORE_PROVEN** |
| Can current query prove production/custom-domain receive? | queried store cannot receive traffic addressed to the custom domain | **NO** |
| Next authoritative boundary | production DB binding / production-side read not available from this pod | `AUTHORITATIVE_RECEIVE_STORE_IDENTITY` → needs an approved read-only production read |

## STATUS

```
STORE_IDENTITY     = DIFFERENT_STORE_PROVEN
PENDING_BOUNDARY   = AUTHORITATIVE_RECEIVE_STORE_IDENTITY

B5_EID5_END_TO_END = WAITING_FOR_DELIVERY
```

Not marked PASS. No defect demonstrated in the sensor, the endpoint, the domain, or the pipeline — so not BLOCKED. No loss inferred.

STOP FOR OWNER REVIEW.
