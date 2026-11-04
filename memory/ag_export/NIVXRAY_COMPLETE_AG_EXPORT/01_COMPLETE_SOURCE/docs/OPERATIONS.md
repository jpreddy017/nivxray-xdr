# NivXRay · Operations, Integrations & Migration

## Migration — from Emergent to your VPS

### 1 · Dump preview + production DBs from Emergent

Since you don't have direct DB access on Emergent, use the export API you already have:

- Preview: nothing to migrate (dev data)
- Production: on `nivxray.nivxforge.com`, log in as admin → **Admin → Golden Vault → Export** (JSONL download). Save `vault_export.jsonl` locally.
- **Investigations**: right now there's no bulk-export endpoint — request one if needed, or start fresh on the VPS (recommended — investigations are typically ephemeral).

### 2 · Import into fresh VPS Atlas

```bash
# On your laptop
scp vault_export.jsonl nivx@<vps-ip>:/tmp/

# On VPS
docker exec -i nivxray-backend-1 python -c "
import json, os
from pymongo import MongoClient
db = MongoClient(os.environ['MONGO_URL'])[os.environ['DB_NAME']]
with open('/tmp/vault_export.jsonl') as f:
    docs = [json.loads(l) for l in f if l.strip()]
if docs: db.workspace_cases.insert_many(docs)
print(f'imported {len(docs)}')
"
```

### 3 · Point production DNS to the VPS

Once smoke tests pass on `app.nivxforge.com`:
- Update `nivxray.nivxforge.com` A record to VPS IP
- Old Emergent deploy can be decommissioned after 48 h grace period

### 4 · Cost cutover
- Cancel Emergent hosting (Profile → Billing → Downgrade)
- Keep the Emergent Universal Key subscription — you'll continue using it for LLM calls from the VPS
- Update pitch deck / customer emails with `app.nivxforge.com`

---

## Integrations

### LLM (required for AI DESCRIBE)

**Option A — Emergent Universal Key (recommended, works from anywhere)**:
```env
EMERGENT_LLM_KEY=sk-emergent-...
```

**Option B — bring-your-own Anthropic** (cheaper at scale):
```env
ANTHROPIC_API_KEY=sk-ant-...
```
Requires a small change in `backend/analysis_core.py` — swap Emergent client for the direct Anthropic SDK. Open an issue and I'll ship the switch.

### Threat Intel (all optional, all opt-in per investigation)

| Provider | Env var | Free tier | Signup |
|----------|---------|-----------|--------|
| VirusTotal | `VT_API_KEY` | 4 req/min, 500/day | virustotal.com/gui/join-us |
| AlienVault OTX | `OTX_API_KEY` | Unlimited (rate-limited) | otx.alienvault.com |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1000/day free | abuseipdb.com |
| Shodan (optional) | `SHODAN_API_KEY` | Paid only | shodan.io |
| Hybrid Analysis (optional) | `HYBRID_ANALYSIS_KEY` | Free for research | hybrid-analysis.com |

Toggle each ON in **Admin → Threat Intel**.

### Payments (future — for subscriptions)

When you're ready to charge customers:
- Stripe subscription mode (Recommended) — `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
- Plans: Free / Pro ($49/mo) / Enterprise (custom)
- I can wire this in a dedicated sprint (~2 days)

### SSO (Enterprise customers)

- Emergent-managed Google Auth — works out of the box
- SAML / Azure AD / Okta — requires Emergent Support ticket

---

## Backups & Disaster Recovery

### Nightly automated backup
- Cron: `0 3 * * * /opt/nivxray/scripts/backup.sh`
- Retains 7 days locally at `/opt/nivxray/backups/`
- Pushes to off-site (B2 or S3) if `rclone` configured

### Off-site backup (Backblaze B2 — cheapest)
```bash
sudo apt install rclone
rclone config  # follow prompts for B2
# add to backup.sh: rclone copy "$BACKUP_DIR/nivxray-$STAMP.gz" b2:nivxray-backups/
```
Cost: $6/TB storage, $10/TB download.

### Restore drill (do this monthly)
```bash
docker run --rm --network host \
  -v /opt/nivxray/backups:/dump mongo:7 \
  mongorestore --uri="$MONGO_URL_TEST" --archive="/dump/nivxray-<STAMP>.gz" --gzip
```

### RPO / RTO targets
- **RPO** (data loss window): 24 h (nightly backup)
- **RTO** (recovery time): 30 min for full restore on fresh VPS

---

## Monitoring

### Minimum viable
- **UptimeRobot** free plan — 5-min ping on `/api/health`
- **Slack/email alert** on failure
- **Disk-full cron** — alerts at 80 % full:

```bash
# /etc/cron.hourly/disk-check
#!/bin/bash
USED=$(df /opt/nivxray | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$USED" -gt 80 ]; then
    echo "NivXRay disk $USED% full" | mail -s "NivXRay disk alert" admin@nivxforge.com
fi
```

### Nice-to-have (Phase 2)
- Grafana + Loki for log aggregation
- Prometheus for metrics (via `/api/metrics` endpoint — needs to be added)
- Sentry for error tracking (`SENTRY_DSN` env var)

---

## Incident Response

### App is 5xx-ing
```bash
docker compose logs --tail 200 backend
docker compose logs --tail 200 caddy
docker compose ps                # any container unhealthy?
```
Common causes:
- Mongo Atlas IP whitelist changed → add VPS IP again
- Emergent LLM Key balance exhausted → top up in dashboard
- Disk full → prune docker: `docker system prune -af`

### Under attack (DoS)
- Enable Cloudflare in front of Caddy (free tier)
- UFW block suspicious ASN
- Restart Caddy: `docker compose restart caddy`

### Data corruption / bad deploy
- Rollback: `cd /opt/nivxray && git checkout <last-good-sha> && docker compose up -d --build`
- Restore DB: `mongorestore --uri="$MONGO_URL" --archive=<latest-backup>.gz --gzip --drop`

### Contact escalations
- Emergent Support (LLM key issues): support@emergent.sh
- Hetzner Support (VPS): via cloud console
- MongoDB Atlas (DB): via Atlas console

---

## Upgrade cadence

- **Security patches**: `unattended-upgrades` handles OS-level automatically
- **NivXRay app**: `git pull && docker compose up -d --build` weekly (pull latest from `main`)
- **Docker images**: monthly `docker system prune -af` to reclaim space
- **MongoDB Atlas**: auto-managed by Atlas

## Cost tracking (Month 1)

| Line item | Cost |
|-----------|------|
| Hetzner CX32 VPS | €6.99 |
| MongoDB Atlas M0 (free) | $0 |
| Domain (amortised) | $0.83/mo |
| UptimeRobot | $0 |
| Backblaze B2 backups (~5 GB) | $0.03 |
| **Total** | **~$8/mo** |

Scale-up projection: ~$80/mo at 20 paying customers (Atlas M10 + CX42 VPS).
