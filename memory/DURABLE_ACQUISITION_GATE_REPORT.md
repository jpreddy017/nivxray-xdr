# Durable Acquisition Gate — COMPLETION REPORT
_preview only · no merge · no production deployment_

The invariant this gate exists to protect:

> A collector restart must neither silently SKIP an uncollected window nor
> produce UNCONTROLLED DUPLICATE evidence.

Four states are now kept distinct everywhere, and the collection window may
only advance on the last one:

    ACQUIRED   the vendor handed us the batch
    QUEUED     its records are in the durable outbox
    DELIVERED  the authoritative ingest returned 2xx per record
    COMMITTED  every record of the batch was accepted

"Microsoft returned it" is never treated as "NivX accepted it".

## ACCEPTANCE STATES

| Stage | State |
| --- | --- |
| Durable acquisition primitive (generic) | **IMPLEMENTED** |
| Outbox `declared_source` correction | **IMPLEMENTED** |
| Ingest credential header correction | **IMPLEMENTED** |
| M365 connector on durable windows + boot reconciliation | **IMPLEMENTED** |
| Restart / duplication / throttle / crash / tenant scenarios | **SYNTHETIC/REPLAY PROVEN** (real SQLite state file, **real** authoritative ingest, stubbed Microsoft) |
| Telemetry actually obtained from Microsoft | **EXTERNAL_ACCESS_BLOCKED** |
| Preflight validator | **IMPLEMENTED** (reports `CONFIGURATION_INCOMPLETE` today — no credentials exist) |

## FILES CHANGED
* `framework/acquisition_state.py` (new · the generic primitive)
* `framework/outbox.py` — `declared_source` column + additive migration +
  `statuses_for()`
* `framework/delivery.py` — credential presented as `X-XDR-API-Key`
  (`NIVX_INGEST_AUTH_MODE=bearer` opt-out) + `auth_mode` in status
* `framework/m365_activity.py` — durable claims/windows, deterministic
  record references, release/forget paths
* `framework/runtime.py` — one `AcquisitionState` sharing the outbox's own
  SQLite connection, boot + post-delivery reconciliation, M365 lifecycle
* `tests/test_acquisition_durability.py` (new · 21 tests),
  `tests/test_m365_preflight.py` (new · 6 tests)
* `scripts/p0_m365_durable_acquisition_proof.py` (new · 20 checks),
  `scripts/m365_preflight.py` (new)
* `memory/M365_REAL_SOURCE_ONBOARDING.md` (new · owner runbook)

Backend: only `m365_unified_audit_dsm.py` (carries the record-reference
basis into provenance). Work Mode, control-plane and NivXForge EDR
untouched.

## STORAGE (no new database)
Acquisition state lives in the **existing** outbox SQLite database
(`${XDR_STATE_DIR}/outbox.db`), via the Outbox's own connection, in two new
tables: `acquisition_batch` and `acquisition_window`. Acquisition state and
delivery acknowledgement therefore share one durability boundary — which is
the only way "advance only after acceptance" can be checked without
trusting memory.

## THREE LATENT DEFECTS FOUND AND FIXED (smallest gate-local fixes)
1. **`Envelope.declared_source` did not exist** (found in Phase 1b). Since
   D15 the boundary refuses an undeclared delivery, so every collector
   delivery would have been blocked `DECLARATION_REQUIRED`.
2. **The durable outbox dropped the declaration.** Even with the envelope
   field, the declaration did not survive the store, so any real
   (worker-driven) delivery would still have been refused. Fixed with an
   additive column + migration; proven to survive a reopen.
3. **The collector presented its ingest credential as `Authorization:
   Bearer`**, but the boundary authenticates a collector with
   `X-XDR-API-Key`; a bearer value goes down the JWT path and can only
   fail, and sending both is rejected as ambiguous. Without this, no
   delivery could ever be ACCEPTED — the exact condition the commit rule
   depends on. Now proven with a real `200 OK` from the live ingest.

## GENERIC BY DESIGN
`AcquisitionState` is vendor-neutral: `(tenant_id, connector_id, stream,
batch_id)` with `claim_batch / record_batch_keys / release_batch /
forget_batch / set_pending_window / reconcile / status / prune_committed`.
A test drives it as a DNS export connector (`stream=zone-transfer-logs`,
`declared_source=dns-query-log`) to keep that honest. Microsoft is its
first consumer, not its reason for existing.

## RECORD IDENTITY
`Id` present → the Microsoft event id is the idempotency key
(`recordReferenceBasis: MICROSOFT_EVENT_ID`). `Id` absent → NivX mints the
deterministic transport reference `m365:<contentId>:<ordinal>`, labelled
`NIVX_ACQUISITION_REFERENCE`, with `microsoftEventId: NOT_OBSERVED`
preserved as a source fact and carried into canonical provenance. It is
never presented as a Microsoft field, and re-acquiring the same blob yields
the same keys (proven).

## SCENARIOS PROVEN (all 11 required, plus 10 more)
| Scenario | Result |
| --- | --- |
| restart during collection (pagination interrupted) | stored page resumed; window held |
| restart after retrieval, before delivery | re-acquired (no skip); one outbox row only (no duplication) |
| restart after successful delivery | committed; blob never re-read |
| duplicate contentId | `ALREADY_COMMITTED`, skipped and counted |
| pagination interruption | `next_page_ref` persisted and reused |
| throttling (429 + Retry-After) | page + window preserved across restart, `RATE_LIMITED` |
| expired blob (410) | reported with `contentExpiration`; does not hold the window open |
| temporary backend failure (`retrying`) | commit withheld, then commits on acceptance |
| collector crash | claim lease expires → re-claimable by a new owner |
| concurrent collectors | second owner gets `CLAIMED_ELSEWHERE`; connector skips and counts it |
| cross-tenant checkpoint isolation | tenant A's reconciliation does not advance tenant B; claims and status are tenant + connector scoped |
| dead-lettered record | window explicitly `BLOCKED_BY_DEAD_LETTER_RECORDS` |
| missing outbox row | never assumed accepted |
| declaration through the durable hop | survives a reopen |

**NO SILENT SKIP · NO UNCONTROLLED DUPLICATION · TENANT ISOLATED ·
RECOVERABLE AFTER RESTART** — proven, not asserted.

## LIVE PROOF (end to end, real boundary)
`scripts/p0_m365_durable_acquisition_proof.py` — **20/20 PASS**: real
SQLite state file, real outbox, real `IngestClient`, **real** NivX ingest
over HTTPS (`200 OK`), canonical evidence produced, DET-PS-004 cited,
commit only after acceptance, no re-read after commit. Microsoft itself is
stubbed, so this remains SYNTHETIC/REPLAY PROVEN.

## PREFLIGHT VALIDATOR
`scripts/m365_preflight.py` — reproducible acceptance instead of a human
opinion. Reads configuration from the environment and **never** prints,
logs or stores secret material (asserted in tests). Reports exactly one
final state: `CONFIGURATION_INCOMPLETE`, `CONFIGURATION_VALID`,
`SOURCE_REACHABILITY_FAILED`, `AUTHENTICATION_FAILED`,
`PERMISSION_OR_CONSENT_FAILED`, `SUBSCRIPTION_FAILED`,
`RETRIEVED_NO_CONTENT`, `RETRIEVED_BUT_NOT_ACCEPTED`, `REAL_SOURCE_PROVEN`.
`REAL_SOURCE_PROVEN` requires records retrieved from the configured
Microsoft service **and** accepted by the authoritative ingest — a test
asserts that OAuth success alone cannot reach it. Sovereign-cloud endpoints
(`M365_BASE_URL`, `M365_AUTHORITY`) are overridable.

Today it reports `CONFIGURATION_INCOMPLETE`, naming the unset variables.

## OWNER PROCEDURE
`memory/M365_REAL_SOURCE_ONBOARDING.md` — app registration, the single
APPLICATION permission `ActivityFeed.Read`, admin consent, tenant GUID,
credential options (certificate recognised and declared not implemented),
the Microsoft audit prerequisite, the NivX collector + key, every
environment variable including a persistent `XDR_STATE_DIR`, how to run the
preflight, and the day-one limits. No secrets anywhere.

## REGRESSION
* Collector suite **88 passed** (27 new).
* Backend Microsoft/D-series suites **220 passed**.
* Live proofs re-run: durable **20/20**, Phase 1a **40/40**, Phase 1b
  **23/23**.
* Known pre-existing failures unchanged: **12 failed / 16 passed** in
  `test_xdr_content_pipeline.py` + `test_xdr_detection_consolidation.py`.

## REMAINING RELIABILITY GAPS (reported, not silently handled)
1. **A permanently rejected record holds its batch — and therefore its
   collection window — open indefinitely**, reported as
   `BLOCKED_BY_DEAD_LETTER_RECORDS` in both `reconcile()` and `status()`.
   No automatic release policy was invented, per instruction. Closing it
   needs an owner decision on terminal-record policy (drop with evidence,
   quarantine, or operator release).
2. **Certificate (private_key_jwt) client authentication** is still not
   implemented — the production-preferred credential mode.
3. **Live Microsoft acquisition** remains blocked on owner-side app
   registration and consent.
4. **The generic primitive is not yet adopted by the other transports**
   (`rest`, `webhook`, `syslog` still rely on the in-memory dedup cache).
   Deliberately out of scope here; it is why the primitive is vendor-neutral.
5. `prune_committed()` exists but is not scheduled, so the batch table
   grows until something calls it.

**STOPPED for owner review. Identity Lane Rules and Mailbox Audit Lane NOT
started. No next gate selected.**
