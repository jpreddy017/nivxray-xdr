# NivXRay · Pre-Seed Fundraising Pack
### For solo founder · No revenue yet · Product-first pitch

**Target raise: $150K – $500K pre-seed**
**Runway target: 12–18 months to first paying customers**

---

## Slide-by-slide pitch (12 slides, ~10 min pitch)

### Slide 1 · Cover
```
NivXRay
Deep-Decode Intelligence for SOCs
[Your name] · Founder & Engineer
[Your email] · [Your LinkedIn]
```

### Slide 2 · Problem (30 seconds)
> **SOC analysts spend 15+ minutes per obfuscated alert.**
> Multi-layer obfuscation (base64 → UTF-16 → format-string → XOR) is now standard in 40% of real attacks. Splunk sees gibberish. CrowdStrike sees intent but not semantics. Analysts paste into CyberChef, then manually lookup MITRE, then manually check IOCs against VirusTotal.
>
> **The average enterprise SOC handles 4,500 alerts/day. This translates to ~$2M/year in analyst time wasted on decode-and-classify workflows.**

### Slide 3 · Solution (30 seconds)
> **NivXRay turns 15 minutes of analyst work into 200 milliseconds of automated attribution.**
> - Multi-layer decode (up to 6 nested archetypes)
> - MITRE ATT&CK auto-mapping (230 heuristics, 102 unique T-IDs)
> - IOC extraction + local threat-intel cache (8,915 IOCs, 6 sources)
> - AI narrative layer (explains every decision in plain English)

### Slide 4 · Product demo (2 min · LIVE if possible)
> Live-decode a real Meterpreter stager. Show the 6-layer unwrap.
> Show the MITRE Heatmap. Show the Practice Lab.
> **Product URL:** https://nivxray.nivxforge.com

### Slide 5 · Why now?
> - LLM-driven obfuscation is exploding (2025 saw 3× YoY growth in multi-layer attacks per CrowdStrike GTR)
> - SOC alert fatigue at all-time high (Ponemon 2024: 55% of alerts ignored)
> - SIEM licensing costs forcing detection engineering to move UPSTREAM of ingest
> - MITRE ATT&CK is now the universal detection language (adopted by 85% of Fortune 500 SOCs)

### Slide 6 · Product traction (be brutally honest)
> **What's built:**
> - 43,395 LoC production code · 1,559 passing tests
> - 6 archetype families · 230 MITRE heuristics
> - Deployed at nivxray.nivxforge.com
> - Practice Lab · Heatmap · Corpus Validator · Batch API
> - macOS decoder · Cobalt Strike / MSFvenom signatures
>
> **What's NOT yet:**
> - Zero paying customers today
> - Zero external beta users today
> - Solo founder (bus-factor 1)
> - Not multi-tenant (blocks enterprise SaaS)
>
> **Why we haven't sold yet:** deliberately built product-first for 9 months. Now ready for GTM.

### Slide 7 · Market
> **Total Addressable Market (TAM):** $6.4B (Global Threat Intelligence Platforms · Gartner 2024)
> **Serviceable Available Market (SAM):** $850M (SOC enrichment/automation subset)
> **Serviceable Obtainable Market (SOM):** $50–150M (mid-market SOCs · MSSPs · IR retainers)
>
> **Target segments (year 1):**
> 1. Mid-market SOCs (50-500 analysts) — $30K–$60K ACV
> 2. MSSPs / MDR providers — $50K–$150K ACV
> 3. IR retainer firms — $15K–$40K ACV per engagement

### Slide 8 · Business model
> **Pricing tiers:**
> - **Community**: Free — Practice Lab, 100 decodes/day, public IOCs
> - **Team**: $299/user/month — unlimited decodes, private IOCs, AI narrative
> - **Enterprise**: $30K–$60K/year — SSO, multi-tenant, SLA, SOC2, on-prem
> - **MSSP**: $80K–$200K/year — reseller license + white-label
>
> **Unit economics (Year 1 target):**
> - CAC (via content-led inbound): ~$3K per Team, ~$15K per Enterprise
> - LTV (assuming 3-year retention): ~$10K Team, ~$150K Enterprise
> - Gross margin (post-LLM costs): 78%

### Slide 9 · Competition
```
                Deep decode | MITRE tags | Deterministic | Multi-tenant | Free tier
CyberChef            ✓            ✗             ✓              n/a          ✓
any.run             partial       ✓             ✗              ✓            ✓
Recorded Future      ✗            ✓             ✓              ✓            ✗
Splunk ES            ✗          rules           ✓              ✓            ✗
Detection Studio    ✓           ✓              ✓              ✓            ✗
NivXRay              ✓            ✓             ✓          in-progress      ✓
```
**Our wedge:** the only tool that does DETERMINISTIC deep-decode + MITRE + free tier. Others are either shallow or expensive.

### Slide 10 · Team (be honest)
> **[Your name]** — Founder & Engineer
> - [X] years in [DFIR / SOC / detection engineering]
> - Built NivXRay solo over 9 months
> - Deep hands-on with real incident response
>
> **Advisors** (pending): looking to add 2-3 CISO-level advisors post-raise.
> **Hiring plan post-raise:** 1 senior engineer (Month 3) + 1 founding AE (Month 6).

### Slide 11 · Ask & use of funds
> **Raising: $250K pre-seed (SAFE, $2.5M post-money cap)**
>
> **Use of funds:**
> - 40% ($100K) · Engineering hire (senior Python/DFIR) for 12 months
> - 25% ($62K) · Multi-tenancy retrofit + SOC2 Type-1 audit
> - 20% ($50K) · GTM: content marketing, Splunkbase launch, conference booths (BSides, ShmooCon)
> - 15% ($38K) · Runway buffer + legal (Delaware C-Corp, IP assignment, standard docs)
>
> **Milestones (12 months):**
> - Month 3: Multi-tenant SaaS live · 10 paid beta users at $299/mo
> - Month 6: First $30K Enterprise contract signed
> - Month 9: $10K MRR · 3 Enterprise contracts · 20 Team accounts
> - Month 12: $30K MRR · seed-ready (Series A preparation)

### Slide 12 · Contact
> **Try the product:** https://nivxray.nivxforge.com
> **See the code (once open-sourced):** [GitHub link]
> **Deep-dive blog:** https://nivxmachines.com/blog
> **Email:** [your email]
> **Calendly:** [your calendly for follow-up meeting]

---

## Where to look for the money (prioritized)

### Tier 1 · Cyber-specific accelerators (no dilution guaranteed BEFORE demo day, cash post)
| Program | Amount | Batch cadence | Fit |
|---|---|---|---|
| **Merlin Cyber Fund** | $500K–$2M seed | Rolling | Perfect fit — they only invest in cyber |
| **DataTribe** | $500K–$2M seed | Rolling | Very strong for security tooling |
| **CyberFund** | $100K–$500K pre-seed | Quarterly | Solo founders welcome |
| **Y Combinator (S26 batch)** | $500K std | Twice/year | Longshot but massive network |
| **Techstars Global Cyber** | $120K | Quarterly | Solo-founder friendly |
| **Mach37 (Virginia)** | $50K–$150K | Quarterly | Cyber-only, sales-focused |

### Tier 2 · Angel investors (former CISOs, security founders)
- **Alex Stamos** (former Facebook/Yahoo CISO) — angel-invests in cyber tools
- **Wendy Nather** (Cisco/Duo) — active angel
- **Rich Mogull** (Securosis founder) — invests + advises
- **Robert Herjavec** — Herjavec Group founder, angel investor
- **Nir Zuk** (Palo Alto Networks co-founder) — occasional cyber angel

**How to reach them:** cold DM on Twitter/LinkedIn with a 60-second product demo video. That's it.

### Tier 3 · Grants (dilution-free)
- **NSF SBIR Phase 1** — up to $275K, non-dilutive
- **DoD SBIR** (cyber topics) — up to $150K
- **NATO Innovation Fund** — cyber-focused, EU-based
- **DARPA SBIR** — cybersecurity topics, non-dilutive
- **HHS Cybersecurity SBIR** — healthcare-focused SOCs

### Tier 4 · Strategic angels (SIEM/EDR vendor former execs)
- Former Splunk / CrowdStrike / SentinelOne / Elastic execs know the pain, buy early
- LinkedIn: search "Former VP Engineering [Vendor]" + "angel investor"
- Warm intro via mutual LinkedIn connections beats cold every time

### Tier 5 · Community round (crowdfunding)
- **Republic / WeFunder** — cyber projects have raised $500K–$2M via community rounds
- Requires viral content first (see LAUNCH_CONTENT_PACK.md)
- 12-16 week campaign — start ONLY if warm intro list is exhausted

---

## What to prepare before your first pitch (72 hours)

### Absolute must-haves
- [ ] **Deck PDF** — this document, exported as 12-slide PDF
- [ ] **60-second demo video** — screen-recording of the 6-layer AMSI decode. Loom is fine.
- [ ] **Public product URL** — nivxray.nivxforge.com works today
- [ ] **Founder profile** — LinkedIn updated with "Founder, NivXRay"
- [ ] **Data room** — Google Drive folder with: this deck, financials (even if $0), architecture doc, product roadmap
- [ ] **SAFE template** — YC standard post-money SAFE ($2.5M cap suggested)

### Nice-to-haves (raise more if you have these)
- [ ] 5 emails from potential customers saying *"I'd pay for this"* (LOIs)
- [ ] 1 signed pilot letter (even unpaid)
- [ ] 500+ product signups / downloads
- [ ] Twitter thread with 10K+ impressions

### DON'T do these before pitching
- ❌ Don't spend money on Delaware C-Corp until AFTER you have term sheet interest (~$500)
- ❌ Don't pay for pitch coaches — free advice from Twitter is 90% of the value
- ❌ Don't hire a lawyer before term sheet — YC's Post-Money SAFE is free
- ❌ Don't build multi-tenancy UNTIL money is committed — waste of time

---

## Realistic timeline

| Week | Action |
|---|---|
| **1** | Update LinkedIn · publish blog post + Twitter thread from LAUNCH_CONTENT_PACK.md · record demo video |
| **2** | Apply to Merlin Cyber + DataTribe + Techstars Cyber (form submissions, ~2 hours each) |
| **3** | Cold DM 20 cyber angels with 60-second video · warm-intro any you can |
| **4** | First calls (expect 30% response rate = 6 calls) |
| **5-8** | Pitch iterations · improve based on feedback · target: 3 termsheet conversations |
| **9-12** | Sign SAFE with lead angel/fund · close round · begin hiring engineer #2 |
| **12-16** | Multi-tenancy sprint · SOC2 audit kickoff · GTM hire |

**Realistic outcome:** $150K–$400K raised at $2.5M–$4M post cap in 12-16 weeks IF product demo is compelling and founder story is honest.

---

## Emotional reality check

**Fundraising is hard. Solo cybersecurity founders raise less than solo AI founders. Expect 50 no's before 1 yes.**

But — here's the honest advantage you have:
1. Real product, not a slide deck
2. Real technical depth (43K LoC beats 90% of pitches)
3. Real market pain (every CISO knows this problem)
4. Emergent platform gives you enterprise-grade product without enterprise-grade cost
5. Public deployment (nivxray.nivxforge.com) is unusual for pre-seed — signals seriousness

**Your pitch differentiator:** *"I already shipped it. I just need capital to sell it."*

That story resonates. Founders who ship in silence for 9 months before raising are considered 3× more capital-efficient than those who raise on decks.

---

*Save this file. Print the pitch section. Rehearse it 10 times. Then go raise.* 🫡
