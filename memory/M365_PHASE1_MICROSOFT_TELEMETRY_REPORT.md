# Microsoft Security Telemetry Domain · Phase 1 — COMPLETION REPORT
_preview only · no merge · no production deployment_

This is a telemetry **domain**, not a rule parser. DET-PS-004 is its first
consumer; the same DSM already evidences Entra directory operations and
Audit.General workloads that no rule reads yet.

## ACCEPTANCE STATES (read these before quoting anything)

| Stage | State |
| --- | --- |
| Declared source + DSM + canonical evidence + provenance (1a) | **IMPLEMENTED** |
| End-to-end chain through the real NivX HTTP pipeline (1a) | **SYNTHETIC/REPLAY PROVEN** |
| Acquisition connector: OAuth2, subscriptions, pagination, blobs, checkpoint, dedup (1b) | **IMPLEMENTED** |
| Acquisition → DSM → evidence → detection (1b, against a local stub) | **SYNTHETIC/REPLAY PROVEN** |
| Telemetry actually obtained from Microsoft | **EXTERNAL_ACCESS_BLOCKED** |
| Certificate (private_key_jwt) client authentication | **NOT IMPLEMENTED — declared, not faked** |

Records in Microsoft's documented shape delivered through NivX's own real
HTTP route are **not** a live Microsoft source proof, and are never reported
as one.

## SOURCE
Office 365 Management Activity API (`https://manage.office.com/api/v1.0`).
Content types subscribed: **Audit.Exchange**, **Audit.AzureActiveDirectory**,
**Audit.General**. `DLP.All` / `ActivityFeed.ReadDlp` deliberately NOT
requested. Microsoft Graph sign-in/directory-audit acquisition deliberately
NOT added — a possible complementary identity source later.

## ACQUISITION
`apps/nivxray-xdr-collector/framework/m365_activity.py` —
`M365ManagementActivityConnector`, built on the **existing** framework
(`Connector`, `Envelope`, `Checkpoint`, scheduler, dedup cache, durable
outbox). No second acquisition framework was created. Microsoft's real model
is followed: token → `POST /subscriptions/start` (idempotent; `AF20024`
"already enabled" is success) → `GET /subscriptions/content` → follow the
`NextPageUri` response header → `GET` each `contentUri` blob → one envelope
per audit **record**. `PublisherIdentifier` is sent on every feed call.
Throttling (`429` + `Retry-After`), an expired blob (`404/410` with
`contentExpiration` quoted), a rejected credential, and an unreachable
endpoint are four distinct reported states.

Smallest gate-local prerequisites, both inside the existing framework:
* `framework/oauth2.py` — `oauth2_client_credentials` token provider
  (also wired into the existing `RestPollerConnector` as a new auth mode).
  A token response without `expires_in` is treated as immediately stale
  rather than valid forever.
* `framework/base.py` — `Envelope.declared_source`. **This was a real
  latent defect**: since D15 the ingest boundary refuses an undeclared
  delivery, and the collector's envelope had no way to declare, so every
  delivery from this service would have been blocked with
  `DECLARATION_REQUIRED`. Optional field, emitted only when set, so the
  generic transports are unchanged.

## AUTHORITY
One declaration per connector: `declared_source = "m365-unified-audit"`.
Content never selects — a CloudTrail record declared as M365 is refused with
`SOURCE_FORMAT_MISMATCH` (proved live). The declared source maps to exactly
one DSM in `SOURCE_CATALOG`; aliases (`m365`, `o365`, `office365`,
`microsoft-365`, `m365-management-activity`,
`office365-management-activity`) all resolve to the same key and cannot
widen it.

## TENANT BINDING
`OrganizationId` is preserved as `cloud.provider_tenant_id` and in
`additional_fields.provider_tenant_id` with the basis string
"NOT the NivX tenant". The NivX tenant remains whatever the authenticated
delivery established (D14); a payload-named tenant is recorded as a claim
and not believed. `microsoftTenantId` and `publisherIdentifier` travel with
the acquisition metadata for source binding.

## CHECKPOINT / REPLAY
Per content type: `window_start`, `next_page_uri`, and a bounded
`seen_content_ids` list, all in `Checkpoint.vendor_state`, restorable via
`restore_checkpoint()`. The window advances **only** after a page run
completes; throttling, auth failure and transport failure all keep the page
and the window, so nothing is lost on restart. `contentId` replay protection
lives in the collector because the API performs no server-side dedup and
does not guarantee ordering.

## CANONICAL EVIDENCE
`backend/detection_content/telemetry/m365_unified_audit_dsm.py` — one parser
+ normalizer for the common schema plus the Exchange/Entra/General
workload schemas. Microsoft's vocabulary survives: `Operation`, `Workload`,
`RecordType`, `ResultStatus`, `UserType`, `Parameters`. Numeric codes
resolve to Microsoft's **published** names; an undocumented code is reported
as `RecordType:9999` / `UserType:77`, never guessed. Exchange
`Parameters [{Name,Value}]` is flattened into `cloud.request_parameters` for
citation while the verbatim list is kept in
`additional_fields.parameters_verbatim`; the whole record stays in
`raw_ref`. A record missing the common schema is refused
(`MISSING_M365_AUDIT_MARKERS` / `MISSING_M365_TENANT_BINDING`), not guessed.

Minimal model additions, each directly evidenced by Microsoft:
`CloudContext.provider_tenant_id`, `.workload`, `.record_type`,
`.result_status`, `.application_id`, `.session_id`.

## PROVENANCE
`CreationTime` is the **activity** basis (`m365:CreationTime`), per D11/D12.
`contentCreated` is blob availability and is delivered as
`additional_fields.m365_acquisition` with the explicit basis string
"contentCreated is when the blob became available, not when the activity
happened". A record without `CreationTime` stays `NOT_OBSERVED` with the
reason. The Management Activity API is a service log, so no
`sensor_observed_at` is invented.

## ENTITY IDENTIFIERS (for future cross-domain correlation)
Preserved where Microsoft records them: acting principal (`UserId` /
`UserKey` / Entra `Actor`), UPN, `ClientIP` / `ClientIPAddress` /
`ActorIpAddress`, `ApplicationId` (service principal), `SessionId`,
`ObjectId` / `MailboxOwnerUPN` / Entra `Target` (as `resource_ids`),
`ClientInfoString`. **Device identity does not exist in this source** and is
declared as such in the DSM capability block — no correlation is fabricated
where the identifiers are insufficient.

## DETECTIONS
DET-PS-004 declared only after the evidence existed:
`cloud.action` (contains_any_ci) + `cloud.request_parameters`
(serialized_contains_any_ci). Removed from `DECLARATION_DEBT` and
`TELEMETRY_GAPS`; recorded in `CLOSED_TELEMETRY_GAPS`. Declaration coverage
**27/37 → 28/37**, zero contract problems, zero declared-but-unexplained.
Citations verified `DECLARED` + `CITED` on live-pipeline evidence.

**Standing finding, deliberately not "fixed":** the rule advertises
*external* forwarding but its predicate only tests that a forwarding-style
parameter is present, so an internal `ForwardTo` matches too. Recorded in a
new `PREDICATE_COVERAGE_FINDINGS` ledger (surfaced by
`declaration_contract.report()`). Narrowing it changes what the rule
matches, which belongs to a detection-content gate — and Phase 1a now
preserves the recipient address and `ExternalAccess` so that gate can do it
on real evidence.

## BENIGN / NEGATIVE TESTS
Benign inbox rule (`MoveToFolder`), other Exchange admin operations
(`Set-Mailbox`, `Get-InboxRule`), Entra role assignment and Audit.General
anti-phishing policy change all produce evidence and **no** detection.
Non-Microsoft payload declared as M365 → `SOURCE_FORMAT_MISMATCH`. Record
missing the common schema → refused. Missing actor / IP / session / status
stay empty rather than invented. Absent `ResultStatus` is never read as
success.

## LIVE SOURCE PROOF
**EXTERNAL_ACCESS_BLOCKED.** Owner-side setup required (printed by the 1b
script, repeated here):

| What | Detail |
| --- | --- |
| Microsoft service | Office 365 Management Activity API |
| App registration | one application in your Microsoft tenant |
| API permission | Office 365 Management APIs → **APPLICATION** permission `ActivityFeed.Read` (delegated cannot do unattended collection; `ActivityFeed.ReadDlp` NOT requested) |
| Admin consent | tenant administrator must grant consent |
| Tenant identifier | Microsoft directory (tenant) GUID — used in the API path and as `PublisherIdentifier` |
| Credential | client secret (implemented) or certificate (preferred for production; recognised and reported as NOT IMPLEMENTED) |
| Microsoft audit config | unified audit logging enabled, or the feed is legitimately empty |
| Where to configure | connector config `microsoft_tenant_id`, `content_types`, `publisher_identifier`; secret in the collector's server-side credential store |
| NivX expects | collector with `authorized_sources: ["m365-unified-audit"]` + ingest key scoped `collectors.enroll` |

No secret, token or certificate was requested in chat, and none is stored in
any file, fixture, report or log.

## TENANT ISOLATION
Unchanged and still enforced: the authenticated delivery decides the NivX
tenant; the Microsoft tenant is provider metadata only. Phase 1 deliveries
are visible on the D21 routing surface under the delivering tenant's scope,
and the D21 isolation proof was re-run **50/50 PASS** after these changes.

## PRE-EXISTING PARALLEL FABRIC (reported, untouched)
`backend/services/telemetry_adapters/` (router `telemetry_adapters.py`,
adapters `entra_signin_log.py`, `okta_system_log.py`, `aws_cloudtrail.py`)
defines its **own** `CanonicalEvent`/`Provenance` dataclasses. It does not
pass through declared-source routing, produces no `xdr_canonical_evidence`,
and cannot be cited by D8 — so it is **non-authoritative for the canonical
XDR evidence path**. Nothing was deprecated, migrated or deleted, and no
consumer was modified. There must ultimately be one authoritative
canonical-evidence path; deciding its fate needs its dependencies mapped
first, which is not this gate.

## REGRESSION
* Phase 1a + D21 + D15–D19 suites: **283 passed**.
* Collector service suite: **61 passed** (17 new Phase 1b tests). One
  pre-existing catalogue assertion updated because the source-types list
  legitimately grew by one entry.
* Three D17/D19 assertions updated to the new truth (coverage 28/37;
  DET-PS-004 off the ledger because its **source** now exists — the ledger
  only shrank).
* Known pre-existing failures unchanged: **12 failed / 16 passed** in
  `test_xdr_content_pipeline.py` + `test_xdr_detection_consolidation.py`.
  Not touched.
* Note for the next agent: running the full backend suite under xdist
  leaves orphaned workers that exhaust MongoDB's connection limit and make
  unrelated tests error out. Kill stray `pytest` processes and restart
  `mongodb` before judging a regression.

## REMAINING GAPS
1. **Live Microsoft acquisition** — blocked on owner-side app registration
   and admin consent.
2. **Certificate client authentication** — the production-preferred mode;
   abstraction present, flow not implemented.
3. **Persistent connector checkpoints** — `restore_checkpoint()` exists and
   is proven, but the collector's state store does not yet mirror
   `vendor_state` to disk, so a process restart currently resumes from the
   configured lookback rather than the exact window.
4. **Mailbox-audit (`ExchangeItem`) and Entra sign-in lanes** — evidenced by
   the DSM but no rule consumes them yet.
5. **DET-PS-004 predicate coverage** — internal vs external forwarding
   (standing finding above).
6. **DLP.All** and **Microsoft Graph** — deliberately out of Phase 1 scope.
7. **No cross-domain correlation yet** — identifiers are preserved for it;
   the correlation itself is a later gate.

## BOUNDARIES HONOURED
Production unchanged. No merge, no deployment. Work Mode / control-plane
untouched. NivXForge EDR untouched. D11–D21 invariants preserved (the D21
proof was re-run green). No broad infrastructure audit was started.

**STOPPED for owner review. No next gate started.**
