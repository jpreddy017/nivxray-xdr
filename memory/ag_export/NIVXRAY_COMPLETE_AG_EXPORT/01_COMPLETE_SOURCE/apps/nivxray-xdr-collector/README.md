# NivXRay XDR Collector Service

Independently deployable **collection & transport plane** for NivXRay XDR.

## Architectural boundary (owner-locked)

| Plane | Owner |
| --- | --- |
| Canonical Evidence · SSOT · Verdict · IKG · Activity Inventory · Process Tree · Trajectory intelligence · Command Intelligence · MITRE · Correlation | **Existing NivXRay backend (authoritative)** |
| Connector framework · Collector runtime · Scheduling · Polling · Webhook / Syslog receivers · Checkpointing · Dedup · Provenance · Delivery to authoritative ingest | **This service (NivXRay XDR Collector)** |

This service **NEVER** decides "is this malicious". Its job ends at `canonical envelope delivered to the authoritative NivXRay ingestion API`.

## Phase B scope (this commit)

- Full connector framework: `Connector` interface + `Envelope`, `Checkpoint`, `Health`, `Capability`, `ConnectorMetrics`.
- **Three generic transports**:
  - `RestPollerConnector` — HTTP GET/POST with bearer/basic/api-key auth, cursor-based pagination, checkpoints, 429 handling.
  - `WebhookConnector` — inbound POST receiver, HMAC-SHA256 signature verification (constant-time), replay window (5 min).
  - `SyslogConnector` — UDP + TCP listeners, RFC3164 + RFC5424 parsers, bind-conflict safety.
- Runtime: async scheduler for pollers, socket manager for syslog, bounded per-connector dedup cache, best-effort outbox to authoritative NivXRay ingest.
- Persistent connector store (`XDR_STATE_DIR` mirrors instances to disk, credentials chmod 600, redacted in API responses).
- Full management API: source-types catalogue, CRUD, test/start/stop/inject, telemetry-health, data-sources.
- **27/27 pytest suite passes** (parsers, REST poller, webhook, syslog with real socket binds, end-to-end routes).

## What lands in later phases

- **Phase B.5** — durable outbox + DLQ + retry/backoff + observability + real forwarding to authoritative NivXRay ingestion.
- **Phase C** — vendor adapters: CrowdStrike Falcon · Microsoft Defender · SentinelOne · Cisco Secure Endpoint.
- **Phase D** — Windows collection: WEF · WinRM · WMI.
- **Phase E** — hardening: backpressure · replay · fleet scaling · production observability.

## API surface

```
GET    /health
GET    /
GET    /api/xdr/source-types                 → catalogue of transports
GET    /api/xdr/connectors                   → list (per-tenant via X-Tenant-Id)
POST   /api/xdr/connectors                   → create (rest|webhook|syslog)
GET    /api/xdr/connectors/{id}
PATCH  /api/xdr/connectors/{id}
DELETE /api/xdr/connectors/{id}
POST   /api/xdr/connectors/{id}/test         → dry-run (rest)
POST   /api/xdr/connectors/{id}/start        → scheduler / bind
POST   /api/xdr/connectors/{id}/stop
POST   /api/xdr/connectors/{id}/inject       → dev-only synthetic payload
POST   /api/xdr/webhooks/{secret_id}         → inbound webhook (HMAC-verified)
GET    /api/xdr/collectors
GET    /api/xdr/telemetry-health
GET    /api/xdr/data-sources
```

## Local dev

```bash
pip install -r requirements.txt pytest pytest-asyncio
uvicorn main:app --reload --port 8080
python -m pytest tests/ -q
```

Swagger: `http://localhost:8080/docs`

## Deployment (production runtime)

**Not Vercel** — Vercel is for the XDR SPA. Deploy this service anywhere that runs a long-lived Python process:

```bash
docker build -t nivxray-xdr-collector .
docker run -p 8080:8080 \
  -e NIVX_INGEST_URL=https://…/api/xdr/ingest \
  -e NIVX_INGEST_TOKEN=… \
  -e XDR_STATE_DIR=/var/lib/nivxray-collector \
  nivxray-xdr-collector
```

Recommended production hosts: Fly.io · Google Cloud Run · Railway · AWS App Runner · bare Docker on the tenant's VPC.

## Environment variables

| Var | Default | Purpose |
| --- | --- | --- |
| `XDR_COLLECTOR_ID` | `collector-local` | This collector instance's identity |
| `XDR_STATE_DIR` | *(unset — in-memory only)* | Directory for persisted connector configs (`connectors.json`, chmod 600) |
| `XDR_CORS_ORIGINS` | `*` | Comma-separated CORS allow-list; tighten in production |
| `XDR_AUTO_START_CONNECTORS` | `1` | Start persisted connectors on boot (`0` to require manual start) |
| `NIVX_INGEST_URL` | *(unset)* | Authoritative NivXRay ingestion endpoint |
| `NIVX_INGEST_TOKEN` | *(unset)* | Bearer token for the ingestion endpoint |
| `NIVX_INGEST_TIMEOUT` | `10` | Delivery timeout (seconds) |

## Guarantees

- Never returns fabricated telemetry.
- Never returns credentials in API responses (`config.credentials` is redacted to `***`).
- Never claims a connector is `CONNECTED` unless the underlying test passes.
- HMAC comparison is constant-time (`hmac.compare_digest`).
- Existing NivXRay repo untouched.
