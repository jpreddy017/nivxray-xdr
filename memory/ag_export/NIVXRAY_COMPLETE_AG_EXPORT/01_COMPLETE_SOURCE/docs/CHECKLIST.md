# NivXRay · Day-1 Checklist

Print this, tick each box. If everything's green you've deployed.

## 🌐 Before you touch a VPS
- [ ] Domain purchased (e.g. `nivxforge.com`)
- [ ] Decide subdomain (`app.nivxforge.com` recommended for the tool)
- [ ] Emergent LLM Key copied from Emergent dashboard (Profile → Universal Key)
- [ ] VirusTotal API key from https://virustotal.com/gui/join-us
- [ ] AlienVault OTX key from https://otx.alienvault.com
- [ ] AbuseIPDB key from https://abuseipdb.com
- [ ] MongoDB Atlas account created (Free M0 cluster is fine to start)

## 💻 VPS provisioning
- [ ] Hetzner Cloud account created
- [ ] SSH keypair generated (`ssh-keygen -t ed25519`)
- [ ] SSH public key uploaded to Hetzner
- [ ] VPS provisioned (CX32 — 4 vCPU / 8 GB / 80 GB, Ubuntu 24.04 LTS, Falkenstein)
- [ ] IPv4 noted: __________
- [ ] IPv6 noted (optional): __________

## 🔗 DNS
- [ ] `A` record `app` → VPS IPv4
- [ ] `AAAA` record `app` → VPS IPv6 (optional)
- [ ] Propagation confirmed (`dig app.nivxforge.com`)

## 🔒 OS hardening
- [ ] SSH into VPS: `ssh root@<ip>`
- [ ] Create non-root user: `adduser nivx && usermod -aG sudo nivx`
- [ ] Copy SSH key to user: `rsync --archive --chown=nivx:nivx ~/.ssh /home/nivx`
- [ ] Disable password + root SSH (`/etc/ssh/sshd_config` → `PasswordAuthentication no`, `PermitRootLogin no`)
- [ ] `sudo systemctl restart ssh`
- [ ] UFW allow: `sudo ufw allow OpenSSH && sudo ufw allow 80 && sudo ufw allow 443 && sudo ufw enable`
- [ ] fail2ban: `sudo apt install -y fail2ban && sudo systemctl enable fail2ban`
- [ ] `sudo apt install -y unattended-upgrades`

## 🐳 Docker installation
- [ ] `curl -fsSL https://get.docker.com | sh`
- [ ] `sudo usermod -aG docker nivx`
- [ ] Log out + back in
- [ ] `docker --version && docker compose version` → both work

## 🗄️ MongoDB Atlas
- [ ] Free M0 cluster created (any region close to VPS)
- [ ] Database user created (username `nivxray`, strong password)
- [ ] Network access: allow VPS IP (or `0.0.0.0/0` temporarily)
- [ ] `MONGO_URL` copied from Atlas "Connect" dialog

## 📄 App deployment
- [ ] `git clone git@github.com:jana017/NivXRay_NivXForge.git /opt/nivxray`
- [ ] `cd /opt/nivxray`
- [ ] Copy `.env.example` → `.env` and fill all values
- [ ] `docker compose up -d --build`
- [ ] Wait 60s, check `docker compose ps` → all healthy

## 🔐 TLS
- [ ] Caddy auto-provisioned Let's Encrypt cert (check `docker compose logs caddy`)
- [ ] `curl https://app.nivxforge.com/api/health` → `{"status":"ok"}`
- [ ] Browser hits `https://app.nivxforge.com` → NivXRay login screen

## ✅ Smoke tests
- [ ] Login with `ADMIN_EMAIL` + `ADMIN_INITIAL_PASSWORD`
- [ ] Change admin password (first-login prompt)
- [ ] Paste a known-good payload → decode succeeds
- [ ] AI DESCRIBE returns a verdict
- [ ] SAVE CASE → visible in workspace history
- [ ] `Admin → Threat Intel` → paste VT + OTX + AbuseIPDB keys → toggle ON → save
- [ ] Re-run investigation → TI-HITS panel populated
- [ ] Golden Vault visible at `Admin → Golden Vault`

## 💾 Backups
- [ ] Nightly cron installed: `0 3 * * * /opt/nivxray/scripts/backup.sh`
- [ ] Backup script tested manually → tarball in `/backups/`
- [ ] Off-site push (B2 / S3) configured
- [ ] Restore drill scheduled for next Sunday

## 📊 Monitoring
- [ ] UptimeRobot ping on `/api/health` every 5 min → Slack/email alert
- [ ] Disk-full cron alert (80% threshold)
- [ ] Log rotation (`/etc/logrotate.d/nivxray`)

## 🎯 Go-live gate
Once every box above is ticked:

- [ ] Update DNS TTL to normal (e.g. 300s → 3600s)
- [ ] Announce to team / customers
- [ ] Update pitch deck with new `app.nivxforge.com` URL

Total setup time (following top to bottom, no distractions): **~90 minutes**.
