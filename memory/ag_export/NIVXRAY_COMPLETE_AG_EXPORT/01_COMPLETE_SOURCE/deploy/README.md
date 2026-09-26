# NivXRay XDR · Deployment (P0-F · Sprint 1)

**Status:** Production floor — a reproducible baseline for V1 GA. **Not** a Kubernetes deployment (that is P0-J territory).

**Scope:** stands up the full stack — backend + frontend + Mongo — with sensible health checks, dependency ordering, and env-driven configuration.

---

## Quickstart

```bash
cp deploy/.env.example deploy/.env
# Set ADMIN_PASSWORD (required, no default).
vi deploy/.env

docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
```

Wait ~30s for Mongo → backend → frontend to reach healthy state, then:

```bash
curl http://localhost:8001/api/health              # → {"status":"ok",...}
curl http://localhost:8001/api/metrics | head -20  # Prometheus scrape
curl -I http://localhost:3000/                     # SPA served by nginx
open http://localhost:8001/api/docs                 # OpenAPI UI (Swagger)
```

Login with `admin@nivxray.com` + your `ADMIN_PASSWORD`; the app will require a password rotation on first sign-in (`ADMIN_FORCE_PASSWORD_CHANGE=true`).

## Verify the compose file without launching

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env config
```

The command exits 0 if the file is syntactically valid and every required env var is set. `ADMIN_PASSWORD` has no default and MUST be set in `deploy/.env` — the compose file uses `${ADMIN_PASSWORD:?...}` so the deploy fails fast with a clear message if you forget.

## What this gives you

| Concern | How it is handled |
|---|---|
| Reproducibility | Both images built from the repo — no drift between environments. |
| Health & readiness | Every service has a real `healthcheck` block; the backend waits on Mongo `service_healthy`, the frontend waits on backend `service_healthy`. |
| Config / secrets | Env-driven through `deploy/.env` (git-ignored). `ADMIN_PASSWORD` is required and validated at compose parse time. |
| Persistence | Named volume `nivxray-mongo-data`; `docker compose down` DOES NOT delete data. Use `docker compose down -v` to purge. |
| Non-root containers | Both backend + frontend run as unprivileged UIDs. |
| Log shipping | JSON structured logs on stdout (`P0-E` foundation) — Docker log driver captures them with rotation. |
| Prometheus scraping | `/api/metrics` on the backend is scrapable from anywhere on the `nivxray` compose network. |
| Startup ordering | `depends_on: condition: service_healthy` — no race conditions on cold start. |

## What this does NOT give you (yet)

- **Kubernetes / Helm** — separate P0-F successor / P0-J.
- **HA / replica set** — single Mongo node, single backend replica. Compose is a floor, not a cluster.
- **TLS termination** — put nginx/Caddy/Cloudflare in front for HTTPS.
- **Backup / restore workflow** — P0-G item.
- **SSO** — P0-C item.
- **Real vendor connectors** — P0-A item.

## Upgrade / rollback

```bash
# Roll forward
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d

# Roll back to a known-good tag
TAG=0.9.9 docker compose -f deploy/docker-compose.yml up -d
```

`ADMIN_FORCE_PASSWORD_CHANGE` is idempotent — enabling it does not force a rotation for admins who have already rotated.

## Where to plug in Prometheus + Grafana

Add a `prometheus.yml` scrape config that targets `nivxray-backend:8001` on the `nivxray` docker network:

```yaml
scrape_configs:
  - job_name: nivxray
    static_configs:
      - targets: ['nivxray-backend:8001']
    metrics_path: /api/metrics
```

Then a Grafana dashboard picks up:

- `nivxray_http_requests_total` (counter, labelled by method / route / status)
- `nivxray_http_request_duration_seconds` (histogram, labelled by method / route)
- `nivxray_http_requests_in_flight` (counter)

## Sprint 1 P0-F acceptance criteria

- [x] `docker compose config` parses cleanly with `deploy/.env`.
- [x] Backend image builds from repo — non-root, health-checked.
- [x] Frontend image builds from repo — nginx SPA-history-fallback.
- [x] Mongo persistence via named volume.
- [x] Env-driven configuration; `ADMIN_PASSWORD` required at parse time.
- [x] `/api/metrics` reachable from the compose network.
- [x] `/api/health` and `/api/docs` reachable from the host.
- [x] Documented in this README.
