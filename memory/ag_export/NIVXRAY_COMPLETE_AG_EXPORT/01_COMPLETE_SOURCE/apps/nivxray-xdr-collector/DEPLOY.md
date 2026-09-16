# NivXRay XDR Collector · Deployment Runbook

**Status:** ready for production integration.
**Audience:** platform operator.

The collector is a stateful, long-lived HTTP service. It is NOT
deployable to Vercel. Choose a runtime that supports long-lived
processes and persistent disk.

---

## 1 · Prerequisites

| | |
| --- | --- |
| **Base backend** | The authoritative NivXRay ingest endpoint (see [`INGEST_CONTRACT.md`](./INGEST_CONTRACT.md)) is live and reachable from the chosen collector host. |
| **Tokens** | A service-account bearer token minted by base NivXRay, scoped to the ingest endpoint only. |
| **Persistent volume** | ≥ 5 GiB on the collector host, mounted at `${XDR_STATE_DIR}`. Contains `connectors.json` + `outbox.db`. Backup as part of standard platform backups. |
| **CORS** | Explicit allow-list for the Vercel-hosted XDR frontend, e.g. `https://nivxray-xdr.vercel.app`. |
| **TLS** | HTTPS terminated in front of the collector (load balancer, ingress, or the platform's built-in TLS). The XDR frontend is served over HTTPS on Vercel; mixed-content is not acceptable. |

---

## 2 · Environment variables

| Var | Required | Purpose |
| --- | --- | --- |
| `NIVX_INGEST_URL` | ✅ | Full URL of the authoritative NivXRay ingest endpoint. |
| `NIVX_INGEST_TOKEN` | ✅ | Bearer token for `NIVX_INGEST_URL`. |
| `NIVX_INGEST_TIMEOUT` | | Delivery timeout in seconds (default `10`). |
| `XDR_STATE_DIR` | ✅ | Persistent directory. Falls back to in-memory (data lost on restart) if unset. |
| `XDR_COLLECTOR_ID` | | Fleet-wide unique identifier. Defaults to `collector-local`. Set per instance if running > 1. |
| `XDR_CORS_ORIGINS` | ✅ | Comma-separated origin allow-list, e.g. `https://nivxray-xdr.vercel.app`. |
| `XDR_AUTO_START_CONNECTORS` | | `1` (default) — restart persisted connectors on boot. `0` — require explicit `/start`. |
| `XDR_DISABLE_DELIVERY_WORKER` | | Test/debug only. `1` disables the outbox worker. |

Never bake tokens into the image. Inject via the runtime's secret
store (Docker/Compose secrets, k8s Secret, Fly.io / Cloud Run secret,
Railway variable).

---

## 3 · Recommended hosts

| Host | Notes |
| --- | --- |
| **Fly.io** | `fly launch` + volume for `${XDR_STATE_DIR}`. Small, cheap, TLS terminated. |
| **Google Cloud Run (with a 2nd gen Filestore mount)** | Zero-ops. Requires the state directory to live on Filestore, not the ephemeral container disk. |
| **Railway** | Persistent volume + secret variables. Easy first target. |
| **AWS App Runner + EFS** | Good production posture; slightly more setup. |
| **Kubernetes** | Standard `Deployment` + `PersistentVolumeClaim` + `Ingress`. Recommended for tenants with existing k8s. |
| **Bare Docker on the tenant VPC** | For air-gapped / regulated tenants. |

---

## 4 · Deploy

```bash
# From the collector directory
cd /app/apps/nivxray-xdr-collector

# Build the image
docker build -t nivxray-xdr-collector:0.3.0-phaseB5 .

# Run with the required env vars
docker run -d \
  --name nivxray-xdr-collector \
  -p 8080:8080 \
  -v /var/lib/nivxray-collector:/state \
  -e XDR_STATE_DIR=/state \
  -e NIVX_INGEST_URL=https://nivxray.example.com/api/xdr/ingest \
  -e NIVX_INGEST_TOKEN=<bearer-token> \
  -e XDR_CORS_ORIGINS=https://nivxray-xdr.vercel.app \
  -e XDR_COLLECTOR_ID=collector-prod-1 \
  nivxray-xdr-collector:0.3.0-phaseB5
```

Point a public HTTPS URL at `:8080`. Note the URL — it goes into
Vercel next.

---

## 5 · Wire the XDR frontend (Vercel)

1. Open the `nivxray-xdr` Vercel project → **Settings → Environment
   Variables**.
2. Add `VITE_XDR_COLLECTOR_URL` = your collector's public HTTPS URL
   (no trailing slash), scope = Production.
3. Trigger a redeploy (push any commit or use "Redeploy latest").
4. Load `https://nivxray-xdr.vercel.app/xdr/admin/integrations` —
   the health strip should now show `INGEST HEALTHY` and the "COLLECTOR
   RUNTIME NOT DEPLOYED" banner should be gone.

---

## 6 · Production acceptance gates

Run these checks in order. All must pass before flipping traffic.

| Gate | How | Pass when |
| --- | --- | --- |
| 1. Collector reachable | `curl https://<collector>/health` | 200, `phase: B.5`, `worker.running: true` |
| 2. Base ingest configured | `curl https://<collector>/api/xdr/outbox/health` | `ingest.state == "connected"` |
| 3. Wire preflight | `POST /api/xdr/ingest-preflight` (or the wizard's Preflight button) | 2xx + `preflight_ok: true` |
| 4. Wizard → real collector CRUD | Create a Webhook connector in the UI | Connector row appears; `X-Collector-Instance-Id` matches `XDR_COLLECTOR_ID` |
| 5. 2xx → DELIVERED | Send an envelope through the connector | `/api/xdr/outbox/{id}` reports `status: delivered` |
| 6. Transient 5xx → RETRYING | Simulate 503 on the ingest | `status: retrying`, `attempts > 0`, `next_attempt_at` in the future |
| 7. Permanent 4xx → DEAD_LETTER | Simulate 400 | `status: dead_letter` |
| 8. Restart recovery | `docker restart nivxray-xdr-collector` while DELIVERING rows exist | On boot, rows are back to `queued` and drain cleanly |
| 9. Duplicate protection | Re-send an envelope with the same `source_event_id` | `events_duplicated` increments; only one outbox row |
| 10. Canonical evidence created | Base backend query | Evidence row exists with `parser_version` + `connector_id` from the collector |
| 11. SSOT / Verdict / IKG populated | Base backend query | Downstream tables receive the event |
| 12. Regression | Run the existing base backend test suite | 87/87 pass (or current baseline) |
| 13. `/api/health` on base | `curl https://nivxray.example.com/api/health` | Still 200 |

---

## 7 · Rollback

The collector is idempotent and stateful. Rollback is:

1. Stop the current container.
2. Optionally restore `${XDR_STATE_DIR}` from backup (only necessary
   if the schema was migrated in the new version).
3. Start the previous image tag.

No base-backend rollback is required — the ingest contract is
append-only and versioned by `parser_version` inside each envelope.
