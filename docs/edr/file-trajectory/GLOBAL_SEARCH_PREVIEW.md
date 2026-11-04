# Global file search candidate — production promotion pending user review

The Files landing page searches all authorized customer devices by filename,
path, SHA-256, SHA-1 or MD5. No directory enumeration or endpoint selection is
required. Device counts deduplicate source event identity. Device drill-down
reuses the existing File Trajectory and links each indexed event to Device
Trajectory with endpoint, source reference and both supported time formats.

The new `GET /api/edr/files/search` is classified TENANT_SCOPED and reuses
`edr_tenant`, `edr_scope`, and the current endpoint resolver. Cross-customer and
unresolved identities fail closed. Legacy endpoint-only search remains available.
The index distinguishes target-file operations from observed executable images;
process-image hashes never become the hashes of written files. Unavailable
signer, verdict, provenance and sandbox data are not invented.

## Candidate backend setup

Apply the service, script and additive route/classification changes to the
candidate backend baseline, preserving its existing services. Do not replace
the deployed backend wholesale with this frontend branch.

With the candidate environment's configured database and runtime dependencies:

```
PYTHONPATH=backend python backend/scripts/edr_file_search_index.py --tenant REGISTERED_TENANT_ID --follow
```

This creates `edr_file_search_v2` and `edr_file_search_checkpoints_v2`, indexes
500 source documents per batch and polls every five seconds once caught up.
Run a supervised worker for each tenant. MongoDB leases reject competing workers; expired leases permit restart recovery. Transient database failures retry with bounded backoff. It writes no source telemetry. Checkpoints
advance after durable upserts; reprocessing uses deterministic IDs. Backfill
requires existing authoritative endpoint mappings. Unresolved records are
counted, never reassigned by hostname. A fresh backfill is required after fixing
historical unresolved mappings. The source is append-only; late insertion with
older ObjectIds, historical updates/deletions and retention synchronization need
an explicit rebuild/operational retention policy before promotion.

The API returns 503 (not an empty result) until this customer's first successful checkpoint exists.
Coverage includes checked time, caught-up status and unresolved source count. The API reports current, partial, catching_up, stale (over 60 seconds since a successful poll), or error; it never treats an old checkpoint as current.
Counts are exact over the indexed source-event identities, not a live disk
inventory or proof of full telemetry coverage. Search aggregation has a 5-second
limit; timeouts are 503, not zero matches. Pagination is ordered by endpoint/id
and not a point-in-time database snapshot.

## Verification and release gate

- Unit tests: execution-only evidence, hash provenance, malformed and foreign
  records, auto-detection, deduplication, per-device counts/pagination, current
  authorization, event-link parameters.
- Existing FileEvidence React regressions plus new Chromium synthetic tests:
  global search, multiple devices, selected events, links and tenant reset.
- Real MongoDB isolated tests passed: resume after lease expiry, competing-worker exclusion, new-record pickup, per-device counts, tenant denial and IXSCAN.
- Preview tenant backfill processed 15,333 records with zero unresolved identities. A 30-day wevtutil.exe search returned 6,141 evidence events on one endpoint in 66 ms (one measured query, not a load benchmark).
- Authenticated browser navigation, exact-event selection, source retention/rebuild policy and production worker provisioning remain release gates.
- Production remains unchanged. The preview FastAPI instance has the additive route and a supervised candidate indexer. This feature branch may opt into NIVX_EDR_INTEGRATION_PREVIEW=1 only for the EDR preview target; production builds still reject that flag.

The index schema v2 uses observation identity (not event content fingerprints) for distinct-event counts and carries the trajectory presentation identity. File links open the device workspace, and the preview enables V3 to match production. Legacy V2 links resolve their lane before selection.
