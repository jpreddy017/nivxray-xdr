# NivXRay XDR Collector Service

Independently deployable **collection & transport plane** for NivXRay XDR.

## Architectural boundary (owner-locked)

| Plane | Owner |
| --- | --- |
| Canonical Evidence · SSOT · Verdict · IKG · Activity Inventory · Process Tree · Trajectory intelligence · Command Intelligence · MITRE · Correlation | **Existing NivXRay backend (authoritative)** |
| Connector framework · collector runtime · scheduling · polling · webhook / syslog receivers · Windows adapters · checkpoint · retry · rate-limit · normalisation · provenance | **This service (NivXRay XDR Collector)** |

This service **NEVER** decides "is this malicious". Its job ends at `canonical envelope delivered to the authoritative NivXRay ingestion API`.

## Phase A scope (this commit)

- `Connector` interface + `ConnectorRegistry` + canonical `Envelope`, `Checkpoint`, `Health`, `Capability`, `ConnectorMetrics`.
- Management API: `GET /api/xdr/connectors`, `.../:id`, `POST .../test|start|stop`, `GET /api/xdr/collectors`, `GET /api/xdr/telemetry-health`, `GET /api/xdr/data-sources`, `POST /api/xdr/webhooks/:src/:id` (501 in Phase A).
- Uvicorn-served FastAPI app, dockerised.
- **No vendor adapters registered** — the registry is empty by design, so the XDR Admin UI renders honest `NEVER CONNECTED` / `NO MATCHING EVIDENCE` states instead of synthesised sources.

## What lands in later phases

- **Phase B** — generic REST poller · webhook receiver · syslog TCP/UDP/TLS.
- **Phase C** — vendor adapters: CrowdStrike Falcon · Microsoft Defender · SentinelOne · Cisco Secure Endpoint.
- **Phase D** — Windows collection: WEF · WinRM · WMI.
- **Phase E** — hardening: backpressure · DLQ · replay · scaling · production observability.

## Local dev

```
pip install -r requirements.txt
uvicorn main:app --reload --port 8080
```

Swagger: `http://localhost:8080/docs`

## Deployment (production runtime)

**Not Vercel** — Vercel is for the XDR SPA. Deploy this service anywhere that runs a long-lived Python process:

```
docker build -t nivxray-xdr-collector .
docker run -p 8080:8080 nivxray-xdr-collector
```

Recommended production hosts: Fly.io · Google Cloud Run · Railway · AWS App Runner · bare Docker on the tenant's VPC.

## Environment variables

| Var | Default | Purpose |
| --- | --- | --- |
| `XDR_COLLECTOR_ID` | `collector-local` | This collector instance's identity |
| `NIVX_INGEST_URL` | *(not set)* | Authoritative NivXRay ingestion endpoint |
| `NIVX_INGEST_TOKEN` | *(not set)* | Auth token (never exposed to browsers) |

## Guarantee

- Never returns fabricated telemetry.
- Never returns credentials in API responses.
- Never claims a connector is `CONNECTED` unless the underlying test passes.
- Existing NivXRay repo untouched.
