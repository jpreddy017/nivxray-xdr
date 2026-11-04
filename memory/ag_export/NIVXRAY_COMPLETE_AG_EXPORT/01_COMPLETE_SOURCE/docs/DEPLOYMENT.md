# NivXRay · VPS Deployment Guide

Full procedure to self-host NivXRay on a Hetzner Cloud (or any Linux VPS)
with Docker Compose, MongoDB Atlas, and Caddy-managed HTTPS.

## Architecture

```
                   ┌─────────────────────────────────────┐
                   │   Hetzner CX32 VPS  (Ubuntu 24.04)  │
                   │  ┌─────────────────────────────────┐│
                   │  │  Caddy (auto-HTTPS reverse-proxy)││
                   │  │     :80  →  redirect 443         ││
                   │  │     :443 →  TLS terminator       ││
                   │  └───────┬──────────────┬───────────┘│
                   │          │              │            │
                   │  ┌───────▼─────┐  ┌─────▼────────┐   │
                   │  │  frontend   │  │   backend    │   │
                   │  │  React :3000│  │  FastAPI:8001│   │
                   │  └─────────────┘  └──────┬───────┘   │
                   │                          │            │
                   └──────────────────────────┼────────────┘
                                              │ mongodb+srv://
                                              ▼
                                    ┌─────────────────┐
                                    │  MongoDB Atlas  │
                                    │   (M0 → M10)    │
                                    └─────────────────┘
```

## 1 · Provision the VPS

**Hetzner Cloud** → New Project → New Server:
- Location: **Falkenstein** (EU) or **Ashburn** (US) — pick closest to your users
- Image: **Ubuntu 24.04 LTS**
- Type: **CX32** (€6.99/mo) — 4 vCPU / 8 GB RAM / 80 GB SSD
- Networking: IPv4 + IPv6
- SSH key: upload your `~/.ssh/id_ed25519.pub`
- Name: `nivxray-prod-1`

Wait 30 s. Note the IPv4.

## 2 · DNS

At your DNS provider (Cloudflare / Route53 / GoDaddy):

```
Type   Name   Value            TTL
A      app    <VPS-IPv4>       300
AAAA   app    <VPS-IPv6>       300  (optional)
```

Verify: `dig app.nivxforge.com +short` returns the VPS IP.

## 3 · Baseline VPS hardening

```bash
ssh root@<ip>

# non-root user
adduser nivx
usermod -aG sudo nivx
rsync --archive --chown=nivx:nivx ~/.ssh /home/nivx

# disable password + root SSH
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh

# firewall
ufw allow OpenSSH
ufw allow 80
ufw allow 443
ufw --force enable

# fail2ban + auto-updates
apt update && apt install -y fail2ban unattended-upgrades
systemctl enable --now fail2ban
dpkg-reconfigure -f noninteractive unattended-upgrades
```

Log out. Reconnect as `nivx`:

```bash
ssh nivx@<ip>
```

## 4 · Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker --version && docker compose version
```

## 5 · MongoDB Atlas

1. https://cloud.mongodb.com → New Project → New Cluster
2. **M0 Free tier** (256 MB RAM) — enough for the first 6 months
3. Cloud provider: AWS / GCP / Azure — pick region close to your VPS
4. Database Access → Add user `nivxray` with a strong password
5. Network Access → Add IP → paste your VPS IPv4
6. Connect → "Drivers" → copy the `mongodb+srv://...` connection string

## 6 · Clone + configure

```bash
sudo mkdir -p /opt/nivxray && sudo chown -R $USER:$USER /opt/nivxray
cd /opt/nivxray
git clone git@github.com:jana017/NivXRay_NivXForge.git .
cp .env.example .env
```

Edit `.env` with your favourite editor (`nano .env`). See
[`OPERATIONS.md § Integrations`](./OPERATIONS.md#integrations) for the
full list of env vars.

**Minimum required**:
```env
MONGO_URL=mongodb+srv://nivxray:<pwd>@<cluster>/nivxray_prod
DB_NAME=nivxray_prod
JWT_SECRET=<64-char random>
ADMIN_EMAIL=admin@nivxforge.com
ADMIN_INITIAL_PASSWORD=<strong>
EMERGENT_LLM_KEY=<from Emergent dashboard>
REACT_APP_BACKEND_URL=https://app.nivxforge.com
CORS_ORIGINS=https://app.nivxforge.com
DOMAIN=app.nivxforge.com
```

Generate a strong secret: `openssl rand -hex 32`

## 7 · docker-compose.yml

Create `/opt/nivxray/docker-compose.yml`:

```yaml
services:
  backend:
    build: ./backend
    env_file: .env
    expose: ["8001"]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8001/api/health"]
      interval: 30s
      timeout: 5s
      retries: 3

  frontend:
    build: ./frontend
    env_file: .env
    expose: ["3000"]
    restart: unless-stopped
    depends_on: [backend]

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports: ["80:80", "443:443"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on: [backend, frontend]

volumes:
  caddy_data:
  caddy_config:
```

## 8 · Caddyfile

Create `/opt/nivxray/Caddyfile`:

```
{$DOMAIN} {
    # API traffic → backend
    handle /api/* {
        reverse_proxy backend:8001
    }
    # Everything else → frontend
    handle {
        reverse_proxy frontend:3000
    }
    header Strict-Transport-Security "max-age=63072000; includeSubDomains"
    header X-Content-Type-Options "nosniff"
    header X-Frame-Options "DENY"
    header Referrer-Policy "strict-origin-when-cross-origin"
    encode zstd gzip
}
```

## 9 · Launch

```bash
docker compose up -d --build
```

Watch it come up:
```bash
docker compose logs -f
```

You'll see Caddy fetch a Let's Encrypt certificate. Wait ~30 s.

**Verify**:
```bash
curl -sS https://app.nivxforge.com/api/health
# {"status":"ok","service":"nivxray-api"}
```

Open `https://app.nivxforge.com` in browser → NivXRay login.

## 10 · First-login

- Log in with `ADMIN_EMAIL` + `ADMIN_INITIAL_PASSWORD`
- You'll be forced to change the password
- Go to **Admin → Threat Intel** and paste your VT / OTX / AbuseIPDB keys
- Go to **Admin → Privacy Settings** — leave everything default (AI ON, TI opt-in) unless a specific customer requires otherwise

## 11 · Backup script

Create `/opt/nivxray/scripts/backup.sh`:

```bash
#!/bin/bash
set -euo pipefail
STAMP=$(date +%F-%H%M)
BACKUP_DIR=/opt/nivxray/backups
mkdir -p "$BACKUP_DIR"
docker run --rm --network host \
  -e MONGO_URL="$(grep '^MONGO_URL=' /opt/nivxray/.env | cut -d= -f2-)" \
  -v "$BACKUP_DIR:/dump" mongo:7 \
  mongodump --uri="$MONGO_URL" --archive="/dump/nivxray-$STAMP.gz" --gzip
# Retain 7 days locally
find "$BACKUP_DIR" -name 'nivxray-*.gz' -mtime +7 -delete
# Optional: push to B2/S3
# rclone copy "$BACKUP_DIR/nivxray-$STAMP.gz" b2:nivxray-backups/
```

```bash
chmod +x /opt/nivxray/scripts/backup.sh
crontab -e
# Add:
0 3 * * * /opt/nivxray/scripts/backup.sh >> /var/log/nivxray-backup.log 2>&1
```

## 12 · Upgrade procedure

```bash
cd /opt/nivxray
git pull
docker compose up -d --build
docker system prune -f  # cleanup old images
```

## Rollback

```bash
cd /opt/nivxray
git log --oneline -20     # find last-good commit
git checkout <sha>
docker compose up -d --build
```

## Emergency shutdown

```bash
docker compose down
# to reboot the box:
sudo reboot
```

## Multi-node scaling (when you have >50 concurrent analysts)

- Add another CX32 → run just `backend` container behind Caddy load-balance
- Move MongoDB Atlas to **M10 dedicated cluster** (~$60/mo)
- Use `redis:7` sidecar for session cache (optional)
- Consider Kubernetes when you cross 3+ VPS nodes

Not needed for the first year.
