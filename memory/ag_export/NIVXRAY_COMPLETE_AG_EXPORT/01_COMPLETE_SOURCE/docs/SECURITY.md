# NivXRay · Security & Data Safety

> Customer-facing content — use this in your pitch deck, security review
> responses, and enterprise procurement questionnaires.

## Data Sovereignty at a Glance

**Where your data lives**: On your NivXRay tenant, hosted on infrastructure
you choose (self-hosted VPS in your region of choice, or NivX-managed
hosting in Falkenstein / Ashburn / customer-elected region).

**What leaves your tenant, and when**:

| Action | Data leaving tenant | When |
|--------|---------------------|------|
| Payload decoding | Nothing | Never — pure Python runs locally |
| MITRE / IOC / LOLBAS mapping | Nothing | Never — deterministic rules run locally |
| Layer integrity validation | Nothing | Never — local math |
| AI narrative / verdict | Decoded payload + IOCs → Anthropic Claude | **Opt-out available** (`Local-only` mode) |
| Threat Intel enrichment | IOCs (IPs / domains / hashes) → VT / OTX / AbuseIPDB | **Opt-in per investigation** |
| Report export | Nothing | Never — local generation |

## Three Privacy Tiers

### Tier 1 · Default (out-of-box)
- ✅ AI DESCRIBE ON — every investigation gets a Claude-powered narrative
- ✅ Deterministic decoder ON
- ⭕ Threat Intel: opt-in per investigation (analyst clicks "Enrich OSINT")

### Tier 2 · Tenant-admin override
- Tenant admin can flip `local_only_mode: true` globally → **all LLM calls disabled fleet-wide**
- Tenant admin can set `ti_default_enabled: false` → analysts must explicitly toggle TI per case
- Useful for regulated industries (banking, government, healthcare)

### Tier 3 · Per-case sensitive flag
- Analyst can toggle **🔒 SENSITIVE** on any single investigation
- Forces: no LLM, no TI, hashed-IOC-only mode
- Verdict card shows: `"Processed local-only · no AI or TI queried"`

## Data at Rest

- **MongoDB**: TLS-in-transit enforced, encryption-at-rest via Atlas (AES-256)
  or self-hosted with LUKS-encrypted volume
- **Backups**: encrypted tarballs, off-site push via `rclone crypt` remote
- **Secrets**: env vars only, never in code, never in git

## Data in Transit

- **HTTPS everywhere** (TLS 1.3 via Caddy / Let's Encrypt auto-renew)
- **HSTS** with `max-age=63072000`
- **CORS** locked to configured `CORS_ORIGINS` — no wildcards in prod
- **Emergent LLM Key** → transmitted only in Authorization header, TLS-protected

## Access Controls

- **JWT-based auth** with 30-min access token + 7-day refresh
- **Role hierarchy**: `admin` / `analyst` / `viewer`
- **Bcrypt password hashing** (cost factor 12, verified via `integration_playbook_expert_v2`)
- **First-login forced password change** for seeded admin accounts
- **Brute-force protection**: 5 failed logins → 15-min lockout
- **Audit trail**: every privacy setting change written to `privacy_audit`

## Detection Engine (Technical Differentiator)

- **100+ deterministic decoding archetypes** — base64, hex-family (KHEX/XHEX),
  LOLBAS unwraps, XOR, GZip, UTF-16LE, reversed-base64, JSON-escape, and more
- **Golden Vault** — every analyst-saved case becomes a permanent regression
  fixture; no deploy can silently break behaviour a customer validated
- **Learner engine** — analyst-approved payloads auto-propose new archetypes
  with confidence breakdown (Regex / Entropy / Charsets / Decode-path / Corpus)
- **Layer Integrity Validator** — verifies each decode transition
  mathematically (base64 length % 4, UTF-16 nibble parity, entropy floor)
- **63+ pytest fixtures** — hard regression gate before any deploy
- **MITRE ATT&CK auto-mapping** — LOLBAS attribution, YARA-lite scanning,
  behaviour pattern detection (defense evasion + credential access +
  security-software-discovery)

## Compliance Alignment

| Framework | NivXRay position |
|-----------|------------------|
| **GDPR** | Local-only mode + TTL auto-purge + audit log + export-my-data endpoint |
| **SOC 2 Type I** | Alignment path — audit log, access controls, encryption ready |
| **SOC 2 Type II** | Requires 6-month operational evidence — path clear on Hetzner or AWS |
| **ISO 27001** | Alignment path — controls documented, audit log operational |
| **HIPAA** | Achievable on AWS w/ BAA; self-hosted VPS is customer-managed |
| **PCI-DSS** | NivXRay doesn't handle cardholder data → out of scope |
| **NIS2 (EU)** | Well-suited — audit log, incident response docs, DR plan |

## Data Retention

- **Default TTL**: 30 days for investigations, indefinite for workspace-cases
- **Configurable per tenant** via Admin → Privacy Settings
- **Right to be forgotten**: delete-my-data endpoint (planned Q2 2026)
- **Export-my-data**: GDPR data-portability endpoint (planned Q2 2026)

## Incident Response

If NivXRay experiences a security incident:
- Notification within 72 h to affected customers
- Root-cause analysis published within 14 days
- Public status page (planned): `status.nivxforge.com`

## Third-Party Sub-processors

Only used when a customer explicitly enables them:

| Provider | Purpose | Data shared |
|----------|---------|-------------|
| Anthropic (Claude) | AI narrative | Decoded payload text + IOC list |
| VirusTotal | IOC reputation | IPs, domains, file hashes only |
| AlienVault OTX | IOC reputation | Same |
| AbuseIPDB | IP reputation | IPs only |
| Emergent Labs | LLM key routing | Same as Anthropic |

Each is documented in the customer DPA (Data Processing Agreement).

## Contact

- Security: security@nivxforge.com
- Data protection / GDPR requests: privacy@nivxforge.com
- Vulnerabilities: security@nivxforge.com (PGP key on request)

---

*Last updated: Feb 2026*
