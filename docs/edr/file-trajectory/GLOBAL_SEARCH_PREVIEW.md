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

This creates `edr_file_search_v1` and `edr_file_search_checkpoints_v1`, indexes
500 source documents per batch and polls every five seconds once caught up.
Run ONE worker for each tenant. It writes no source telemetry. Checkpoints
advance after durable upserts; reprocessing uses deterministic IDs. Backfill
requires existing authoritative endpoint mappings. Unresolved records are
counted, never reassigned by hostname. A fresh backfill is required after fixing
historical unresolved mappings. The source is append-only; late insertion with
older ObjectIds, historical updates/deletions and retention synchronization need
an explicit rebuild/operational retention policy before promotion.

The API returns 503 (not an empty result) until this customer's checkpoint exists.
Coverage includes checked time, caught-up status and unresolved source count.
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
- Candidate Mongo index backfill, real query explain/performance, live endpoint
  navigation and authenticated customer evidence remain release gates.
- Production remains unchanged. Vercel previews alone do not deploy FastAPI or
  start the indexer; configure a candidate backend before live-data acceptance.
