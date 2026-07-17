# NivXRay · Operations & Deployment Documentation

> Feb 2026 — comprehensive guide for self-hosting NivXRay on a VPS,
> migrating from the Emergent platform, wiring integrations, and
> running the service in production.

## Documents in this directory

| File | Purpose |
|------|---------|
| [`CHECKLIST.md`](./CHECKLIST.md) | One-page Day-1 checklist — print, tick off, done. |
| [`DEPLOYMENT.md`](./DEPLOYMENT.md) | Full VPS deployment (Hetzner/DO), Docker Compose, TLS, DNS. |
| [`OPERATIONS.md`](./OPERATIONS.md) | Backups, monitoring, integrations (LLM, TI), migration from Emergent, incident response. |
| [`SECURITY.md`](./SECURITY.md) | Data safety, privacy toggles, compliance, customer-facing trust page copy. |

## Reading order

1. **First time deploying** → start with `CHECKLIST.md`, then `DEPLOYMENT.md`.
2. **Adding integrations (VT/OTX/Anthropic)** → `OPERATIONS.md § Integrations`.
3. **Enterprise customer asks about data safety** → `SECURITY.md`.
4. **Migrating from Emergent to your VPS** → `OPERATIONS.md § Migration`.

## Feedback / owner

- Repo: `github.com/jana017/NivXRay_NivXForge`
- Preview: Emergent-hosted (dev / staging)
- Production: `nivxray.nivxforge.com` (Emergent) → moving to Hetzner VPS
