# ADR-0011 — TweetFeed Evaluation (Read-Only)

**Status**: Owner-directed evaluation · 2026-08-11 · Session-9-post
**Rule**: read-only. No code changed. The P0 Security Hardening Gate directive at PRD.md head remains the next implementation move.
**Baselines used**: ADR-0007 §15, ADR-0010 §17 (existing 8 providers + iocs collection reality).

---

## §1 · What TweetFeed Actually Is

TweetFeed aggregates IOCs shared publicly on Twitter/X by ~95 security researchers, normalises them, adds tag + reporter + tweet-source metadata, and serves them via a free, unauthenticated REST/TAXII/CSV/RSS/MISP API. Data is CC0. Updates every ~15 minutes. Rolling windows: `today` / `week` / `month` / `year(CSV)`. Hard cap 10,000 rows per JSON response (truncated oldest-first, header-flagged).

### IOC types covered

| Type | Present? |
|---|---|
| URL | ✅ |
| Domain | ✅ |
| IP | ✅ |
| SHA-256 | ✅ |
| MD5 | ✅ |
| SHA-1 | ❌ |
| Email | ❌ |
| Registry key / mutex / YARA | ❌ |

### API surface (unauthenticated)

| Endpoint | Purpose |
|---|---|
| `GET /v1/{time}/{filter1}/{filter2}` | Window + optional type/tag/user filters (JSON) |
| `GET /v1/since/{ISO8601}/{filter1}/{filter2}` | **Delta since a timestamp** (oldest-first, pageable via `X-Result-Window-End`) |
| `GET /v1/ioc?value={ioc}` | **Exact-match IOC lookup** — returns first/last seen, count, reporters, tags, source tweets |
| `GET /v1/campaigns` | **AI-clustered campaigns** — related IOCs, tags, reporters, targeted brand, confidence, anchors |
| `GET /v1/counts` · `GET /v1/trends` | Aggregate analytics + TLD abuse + novelty rate |
| `GET /v1/blocklist/*.txt` | Ready-made DNS/host/URL blocklists |
| `GET /taxii2/…` | **TAXII 2.1** collection (STIX 2.1 indicators + TLP:CLEAR) |
| `GET /feeds/month.csv` · `rss.xml` · `misp/*` · `stix/*` | CSV / RSS / MISP / STIX exports |

### Confidence guarantee (from provider)

> "The confidence of the shared IOCs is not always 100% so it is strongly recommended NOT adding them to a blocklist directly. These could potentially be used for **Threat Hunting** and could be added to a **Watchlist**."

This is a hunting/watchlist feed, **not** a block-list feed. That is architecturally important.

---

## §2 · Overlap With NivXRay's Existing 8 Providers

Cross-check against `backend/feeds.py` (defined fetchers) plus the actual `iocs` collection contents (session-9 probe):

| Provider | IOC kinds it contributes today (row-count in `iocs`) | Overlap with TweetFeed? |
|---|---|---|
| AbuseIPDB | IPs (via `blocklist.de` proxy → 30,700 rows) | High for IPs |
| URLhaus (abuse.ch) | URLs, domains (18,780 + 6,403) | High for URLs / domains |
| CINS Army | IPs (4,985) | Medium for IPs |
| OTX (AlienVault) | Mixed (4,002 + 497) | Medium for URLs / IPs |
| CISA KEV | Vulnerabilities & IPs (215) | Low — different intel type |
| SANS DShield | IPs (50) | Medium for IPs |
| Feodo Tracker (abuse.ch) | Botnet C2 IPs (5 + 5) | Medium for IPs |
| ThreatFox (abuse.ch) | Multi-type (row-count 0 in DB — probably enabled but not synced today) | Medium |
| MalwareBazaar (abuse.ch) | Hashes (row-count 0 in DB — same) | **Complementary — TweetFeed hashes fill this** |
| MalwareBytes | Multi-type (row-count 0 in DB) | Low |
| Talos | Reputation IPs (0 in DB) | Medium |

### Where TweetFeed adds intelligence the others don't

1. **Researcher-attribution** — every IOC carries `user` (Twitter handle) + source tweet URL. Our existing feeds provide provider-level attribution only.
2. **Human-generated context tags** — `#CobaltStrike`, `#GootLoader`, `#phishing`, `#LockBit`, `#RansomHub`, etc. Machine-parseable malware-family / campaign hints. **URLhaus and ThreatFox have tags**, but TweetFeed's are broader (targeted phishing brands, dark-web onion domains, novel families before they hit MB/URLhaus).
3. **AI-clustered campaigns** — the `campaigns` endpoint gives an already-grouped view of "this cluster of IOCs is the same operator" with a name, context prose, targeted brand, confidence, and anchors. No other current provider offers this shape.
4. **Onion / dark-web domains** — visible in the live sample (`ethics67vxjomvlcugjovv…onion`). Our current 8 providers largely skip Tor domains.
5. **Freshness with delta sync** — the `/v1/since/{ISO8601}` endpoint means we can incrementally sync every 15 min without re-pulling the full window. Existing providers vary.
6. **Novelty rate + trends** — `/v1/trends` publishes `pct_new` (95%+ typical), most-abused TLDs, tag movers. Useful signal for the Analyst Practice Lab and the Threat-Hunting UI.

### Where TweetFeed does NOT help

1. **Not authoritative** — the community caveat is explicit.
2. **No SHA-1**, no email, no YARA, no registry — same as our current 8.
3. **10,000-row cap** on JSON windows.
4. **No SLA** — Cloudflare Workers project, ~45 K req/day zone budget.
5. **X/Twitter dependency** — if Twitter API/embed changes, TweetFeed's ingestion could degrade.

---

## §3 · Three Candidate Uses (evaluated separately)

### A. As a 9th IOC provider in `feeds.py`
- **Effort**: small — one new `fetch_tweetfeed()` function, one row in `ti_source_meta`, uses `/v1/since` for incremental sync + `ETag/If-None-Match`.
- **Value**: **medium-high** — meaningful hash + tag + reporter dimensions our current 8 largely lack.
- **Risk**: low — CC0 licence, no auth key, watchlist semantics fit our evidence-driven model.
- **Verdict**: ✅ WORTH INTEGRATING once P0 gate closes.

### B. As a Threat-Hunting / Query-Hunt corpus source
- **Effort**: medium — Query/Hunt panel would need a "hunt against TweetFeed live tags" toggle, and Timeline would need a `provenance` chip.
- **Value**: **high** — the tag + reporter + tweet columns give an analyst something to pivot on that URLhaus / AbuseIPDB do not.
- **Risk**: medium — the platform must NOT auto-trust these IOCs; every hit must render the "community-reported" caveat.
- **Verdict**: ✅ HIGH-VALUE FIT — matches NivXRay's evidence-provenanced philosophy exactly.

### C. As a campaign-context enrichment source
- **Effort**: small-medium — new `/api/threat-intel/campaigns` route that mirrors `/v1/campaigns` and caches for 24 h; a new Workspace panel `CampaignContextPanel.jsx` that shows "this IOC belongs to campaign X".
- **Value**: **high** — this is arguably the most differentiated capability TweetFeed offers. Our current 8 providers do NOT ship named campaign clusters.
- **Risk**: medium — the AI-generated campaign names & prose must be labelled as advisory, not authoritative. Same evidence-chain discipline as everything else.
- **Verdict**: ✅ HIGH-VALUE FIT.

### D. As an Analyst Practice Lab corpus feed
- **Effort**: small — a lab challenge generator that samples recent TweetFeed tags (`#CobaltStrike`, `#AsyncRAT`, `#LockBit`, `#Phishing`) and asks the analyst to classify the payload.
- **Value**: **medium** — fresher, richer corpus than the static `sample_library` (18 rows today).
- **Risk**: low — Lab is already isolated from Workspace.
- **Verdict**: ⚙️ NICE-TO-HAVE, not strategic.

---

## §4 · Recommendation

### Decision: **BACKLOG (multi-use, high priority)** — do NOT integrate now.

TweetFeed is genuinely differentiated on **three** dimensions (researcher-attribution + campaign clusters + delta sync with 15-min freshness) and complements — rather than duplicates — the existing 8 providers. It fits NivXRay's evidence-provenanced philosophy because it explicitly disclaims 100% confidence and pushes consumers toward hunting/watchlist semantics.

However, integrating it now would:
- Contradict the locked P0 Security Hardening Gate directive at PRD.md head.
- Increase the untrusted-input surface (TweetFeed URLs / hashes / IPs will be lookup-triggered by analysts) **before** the archive-bomb, CORS, and login-throttle protections close the boundary.

### Priority ranking of the four candidate uses

1. 🥇 **B. Threat-Hunting corpus** (highest value / lowest risk pattern-fit)
2. 🥈 **C. Campaign-context enrichment** (most differentiated capability)
3. 🥉 **A. 9th IOC provider** (baseline coverage improvement; hashes + attribution)
4. **D. Practice Lab corpus** (nice-to-have)

### Correct sequencing

```
P0 Security Hardening Gate     ← in progress / next
        │
        ▼
P1 Server-Side File Mode
        │
        ▼
P2 Real Telemetry Adapter (Sysmon / EVTX)
        │
        ▼
Shadow-pipeline replay / promotion decisions
        │
        ▼
TweetFeed integration — implement A + B + C together in one focused session:
        · fetch_tweetfeed() in feeds.py
        · new /api/threat-intel/campaigns route
        · CampaignContextPanel.jsx
        · Query/Hunt "TweetFeed watchlist" toggle
        · IOC lookup enrichment via /v1/ioc?value=…
        · TAXII pull as an alternative
```

### Non-negotiable integration rules (locked here, for the future session)

1. **Watchlist semantics only** — a TweetFeed hit MUST NOT elevate a NivXRay verdict on its own. It contributes to `contributors[]` with `source="tweetfeed"` and a "community-reported" flag.
2. **Provenance mandatory** — every TweetFeed-derived IOC carries reporter Twitter handle + source tweet URL + first_seen + last_seen. No de-provenanced propagation.
3. **Delta sync via `/v1/since`** — never full-pull the month window on a cron; use `X-Result-Window-End` paging + `If-None-Match` conditional requests.
4. **Rate discipline** — respect the ~45 K req/day zone budget; cache campaigns + trends 24 h; cache IOC lookups 1 h.
5. **CORS boundary** — TweetFeed calls are backend-outbound only, never proxied through the analyst's browser.
6. **Feature-flag** — introduce ONE new `NIVX_FLAG_TI_TWEETFEED=disabled|shadow|enabled` per ADR-0008 §4.6 governance.
7. **Determinism** — TweetFeed responses feed into the same canonical event bag; they must survive the P0.2 evidence chain (every emitted MITRE technique still needs its own evidence, not "TweetFeed said so").

---

## §5 · Final Verdict

**INTEGRATE**: yes — but only after P0 Security Hardening Gate + P1 Server-Side File Mode close.

**When integrated**: implement uses A + B + C in one focused session; leave D as opt-in Lab enrichment.

**When NOT to integrate**: any time before the ingestion boundary is hardened, or any time we would use TweetFeed to drive verdicts directly.

**Documentation trail**: this ADR + a follow-up ADR-0012 at the moment of integration.

*End of ADR-0011.*
