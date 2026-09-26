# STANDING ENGINEERING STANDARD · industry benchmark (owner, 2026-06)

**Rule.** NivXRay XDR decisions must be benchmarked against current
industry-leading XDR/EDR architecture and operational workflows. Match or
exceed established practice where appropriate, while preserving NivXRay's
evidence/provenance, tenant-isolation, deterministic-analysis and
verification invariants. **Do not invent a NivX-specific mechanism merely
because it is easier to implement.**

## Benchmark set
Cisco XDR / Secure Endpoint · Palo Alto Cortex XDR / XSIAM · Microsoft
Defender XDR / MDE · CrowdStrike Falcon · SentinelOne · and where relevant
Elastic Security and Splunk.

For anything current or implementation-specific, research the latest public
vendor documentation **before** giving the architecture recommendation.

## Scope — the full lifecycle
endpoint/device onboarding → identity/enrolment → local telemetry
acquisition → buffering/retry → authenticated transport → tenant binding →
parsing/normalization → canonical evidence → detection/correlation →
investigation → hunting → response → verification → fleet
upgrades/health.

## The qualifier that matters
Copy proven industry **architecture patterns**; do not copy a vendor
**limitation**. Where vendors differ, state the approaches and then
recommend the pattern that best fits NivXRay's evidence-driven
architecture.

## Non-negotiable UI truth states
`INSTALLED ≠ ENROLLED ≠ CONNECTED ≠ RECEIVING ≠ HEALTHY`

## Applies to (open work)
Windows onboarding · Event Explorer · Defender integration · RBAC / access
management · Command Intelligence · detection coverage · response · the
remaining XDR UI/UX work.

## Where this has already been applied
* **Coverage Impact · potential vs effective (2026-06)** —
  *Industry pattern:* Elastic Security publishes `required_fields` and
  `related_integrations` per prebuilt rule; DeTT&CT separates data-source
  visibility from detection coverage; Sentinel/Defender present
  coverage per data connector.
  *Alternatives:* (a) coverage-by-log-source — rejected, it is the
  documented failure mode "assuming coverage based on log presence" when
  the fields a rule cites were never normalized; (b) coverage-by-firing —
  rejected by the owner, it would report a new customer with 500 valid
  rules as having no coverage.
  *NivX decision:* two independent claims — POTENTIAL (content that could
  use the source) and EFFECTIVE (source receiving · parser · normalization
  · required fields **measured** · rule deployed · rule applicable). A rule
  that declares no required fields cannot be verified and is BLOCKED.
  *Security implication:* an operator is never told they are protected by
  content whose required fields have never been observed, and is never
  told they are unprotected merely because nothing has attacked them yet.
* **Windows channel truth model (Lane G)** — separating *connector /
  ingestion* health from *content coverage* follows the established pattern
  (Defender XDR data-connector health; Cortex XDR data-source ingestion
  states). NivXRay then goes further than the common vendor presentation by
  refusing a composite HEALTHY roll-up and by keeping Detection
  **Capability** apart from Detection **Activity**.
* **Device identity (Lane G)** — leading products key assets on an
  agent/sensor-minted device id with hostname as an alias, precisely
  because hostnames are reused, renamed and reimaged. NivXRay therefore
  records `origin_computer` as *evidence of origin* and declares the
  canonical asset identity NOT ESTABLISHED rather than promoting a
  hostname to a primary key.
* **Event Explorer (Lane H)** — a single source-agnostic event schema with
  per-source enrichment is the Elastic/Splunk/Cortex pattern; NivXRay adds
  the stage-by-stage transformation chain with evidence references, which
  those products do not expose to the analyst.
