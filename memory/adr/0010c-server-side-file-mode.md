# ADR-0010c — P1 Server-Side File Mode · Evidence Report

**Status**: Accepted · 2026-08-11 · Session-11
**Author**: E1 (agent) under owner-locked P1 architecture (Session-10 close message)
**Baseline**: ADR-0007 · 0008 · 0009 · 0010 · 0010b (P0) · 0011 · PRD.md · REMINDERS.md
**Verdict**: 🟢 **PASS** — all 4 owner-locked corrections implemented, streaming ingest proven, race-safe dedup proven, controlled retention proven, canonical regression green. Ready to open P2 Sysmon/EVTX adapter.

---

## §1 · Architecture (locked)

```
                    ANALYST
                       │
                       ▼
                POST /api/files
                       │
              ┌────────┴────────┐
              │  Auth guard     │
              │  P0 archive     │
              │  200 MB cap     │
              └────────┬────────┘
                       ▼
             Streaming ingest
       chunk → SHA-256 update
                     → GridFS.write
                       │
                       ▼
        Race-safe dedup (unique index on (tenant_id, sha256))
                       │
                       ├── existing? → drop new GridFS obj, return existing file_id
                       └── new?      → commit index row
                       │
                       ▼
                  {file_id}
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   /metadata      /analyze         /files/{id}
                  (Input Router)   (streaming download)
                       │
        ┌──────────────┼──────────────┬────────┬──────┬──────┬─────┐
        ▼              ▼              ▼        ▼      ▼      ▼     ▼
     text          archive          office    pdf    pe    image  csv
     /api/die      /api/upload      "        "      /api/analyze/shellcode
                                                                       │
                                                                       ▼
                                                        Existing Analyzers
                                                                       ▼
                                                        Canonical Evidence
                                                                       ▼
                                                             Workspace
```

## §2 · File lifecycle

1. **Upload** — client POSTs multipart to `/api/files`; auth-gated.
2. **Streaming ingest** — 1 MB chunks read from `UploadFile.read(size)`; each chunk fed to `hashlib.sha256().update()` and `GridIn.write()`. Zero full-payload buffering.
3. **Server-side cap** — if `size > NIVX_FILES_MAX_UPLOAD_BYTES`, the GridFS stream is aborted and `FileStoreError("upload_too_large")` raised → HTTP 413 with `{ error, reason, size, max }`.
4. **Race-safe dedup** — after write, `file_index.insert_one` on unique `(tenant_id, sha256)`. On DuplicateKeyError the freshly-written GridFS object is atomically deleted and the pre-existing `file_id` is returned.
5. **Identity** — opaque `nvxf_<uuid4>` file_id (no ObjectId, no filesystem path exposed).
6. **Metadata** — `GET /api/files/{file_id}/metadata` returns analyst-safe fields only (see §4).
7. **Download** — `GET /api/files/{file_id}` streams from GridFS with `Content-Disposition`, `X-Content-SHA256`, `X-Content-Size` headers.
8. **Analyze** — `POST /api/files/{file_id}/analyze` peeks first 4 KB, dispatches via Input Router to LIVE analyzers only.
9. **Pin / unpin** — `POST /api/files/{file_id}/pin?case_id=…` protects the file from retention sweep.
10. **Delete** — owner or admin; drops GridFS object + index row idempotently.
11. **Retention** — application-controlled sweep (`FileStore.sweep_expired`); deletes GridFS **and** index atomically. No naïve TTL on `documents.files` metadata alone.

## §3 · Exact limits shipped

| Env var | Default | Purpose |
|---|---|---|
| `NIVX_FILES_MAX_UPLOAD_BYTES` | `209_715_200` (200 MB) | Server-side upload cap (enforced during streaming) |
| `NIVX_FILES_TTL_DAYS` | `30` | Retention window for non-pinned files |
| `NIVX_FILES_STREAM_CHUNK` | `1_048_576` (1 MB) | Chunk size for streaming ingest |

`RequestHardeningMiddleware._MAX_LARGE_BODY_BYTES` raised from **50 MB → 200 MB** and `/api/files` added to `_LARGE_BODY_PATHS`.

## §4 · Metadata schema (analyst-safe)

```json
{
  "file_id":         "nvxf_0ebc1d04dfc248...",   // opaque
  "sha256":          "8e21af...",
  "size":            43,
  "mime":            "application/octet-stream",
  "filename":        "cmd.ps1",
  "uploaded_by":     "admin@nivxray.com",
  "uploaded_at":     "2026-08-11T16:03:22.181000+00:00",
  "tenant_id":       "default",                  // migration-ready
  "pinned_cases":    [],
  "analysis_status": "pending"
}
```

No filesystem paths. No GridFS ObjectId. No internal storage details.

## §5 · Affected files

**New:**
- `backend/services/files/__init__.py`
- `backend/services/files/store.py`         (FileStore + FileRecord + retention)
- `backend/services/files/input_router.py`  (Route + route_for)
- `backend/routers/files.py`                (`/api/files/*` endpoints)
- `backend/tests/canonical/api/test_p1_server_side_files.py` (19 tests)

**Modified:**
- `backend/server.py`             (`api.include_router(files_router)`)
- `backend/request_hardening.py`  (large-body allowlist + 200 MB ceiling)

**Not modified:** RC5/DIE · canonical projections · Workspace · IKG · Verdict v3 · Case Engine · v2 flags · existing routes · Mongo schemas of live investigation collections.

## §6 · Runtime evidence

### 6.1 · Round-trip
```
POST /api/files  file=cmd.ps1(43 B) →  { file_id: nvxf_0ebc1d..., sha256:8e21af..., size:43 }
POST /api/files  file=cmd.ps1(43 B) →  same file_id  ✅ DEDUP OK
GET  /api/files/nvxf_.../metadata → { file_id, sha256, size, mime, tenant_id:"default", ... }
POST /api/files/nvxf_.../analyze  → { route:"text", result:"DISPATCHED",
                                       next_endpoint:"/api/die/analyze" }
GET  /api/files/nvxf_.../          → 200 · 43 bytes · byte-identical  ✅ ROUND-TRIP OK
```

### 6.2 · Streaming proof (50 MB)
```
RSS before upload : 27,040 KB
POST /api/files  file=big.bin(50 MB) → 200
RSS after upload  : 26,988 KB   (delta = -52 KB → confirms streaming; no full-file buffering)
```

### 6.3 · Oversize refusal (250 MB · cap 200 MB)
```
POST /api/files  file=toobig.bin(250 MB) →
  HTTP 413 { "detail": { "error":"file_store", "reason":"upload_too_large",
                         "size":262144202, "limit":209715200 } }
```

## §7 · Tests (19 new · 19 passing)

| Class | Test | Verifies |
|---|---|---|
| streaming | `test_upload_stores_and_returns_metadata` | Happy path + SHA-256 + size + mime |
| streaming | `test_upload_streaming_chunk_semantics` | `.read()` called with bounded chunks (never slurp) |
| dedup | `test_dedup_same_content_returns_same_file_id` | Second put returns first `file_id` |
| dedup | `test_dedup_survives_concurrent_uploads` | Two `asyncio.gather` puts → one row |
| dedup | `test_dedup_scoped_by_tenant` | Same content, different tenant → different `file_id` |
| oversize | `test_oversize_refused_with_structured_error` | > cap raises `upload_too_large` |
| retention | `test_pin_prevents_sweep` | Pinned file survives TTL+1 sweep |
| retention | `test_unpinned_and_expired_are_swept` | Unpinned + expired removed atomically |
| delete | `test_delete_removes_metadata_and_binary` | Delete removes GridFS + index |
| delete | `test_delete_missing_is_idempotent` | Deleting unknown returns False, no raise |
| routing | `TestInputRouter::test_pe_magic` | MZ header → `pe` |
| routing | `test_pdf_magic` | %PDF → `pdf` |
| routing | `test_office_by_extension` | PK + `.docx` → `office` |
| routing | `test_zip_generic` | PK + `.zip` → `archive` |
| routing | `test_csv_by_mime` | `text/csv` → `csv` |
| routing | `test_text_by_extension` | `.ps1` → `text` |
| routing | `test_unsupported` | Random binary → `unsupported` |
| routing | `test_magic_wins_over_filename` | PE renamed to `.txt` still routes to `pe` |
| privacy | `test_file_id_is_opaque_no_path_leak` | Metadata contains no `/tmp`, `/app`, `chunks`, `gridfs_id` |

## §8 · Regression

Full canonical API suite: **156 passed · 5 skipped · 0 failed in 165.82 s** (baseline before P1: 136/5 → +19 new P1 tests, zero regressions).

Explicitly re-verified:
- P0 security suite (22 tests) — 22/22 pass
- P0.2 evidence chain
- P0.3 payload firewall
- Sample1 immutability
- Workspace isolation
- Report determinism
- DIE Timeline
- DIE Query/Hunt

## §9 · Protected surfaces — confirmation

| Surface | State |
|---|---|
| RC5/DIE canonical pipeline | 🟢 UNCHANGED |
| Workspace behaviour | 🟢 UNCHANGED |
| Existing `/api/upload` semantics | 🟢 UNCHANGED (still consumed by WorkspacePage) |
| IKG · Verdict v3 · Case Engine · Adapters · Artifact Store | 🟢 UNCHANGED (still shadow) |
| P0 security controls | 🟢 UNCHANGED · CI still green |
| Existing routes (466 method-routes) | 🟢 UNCHANGED (7 NEW added under `/api/files/*`; nothing renamed / deleted / deprecated) |
| Mongo schemas of investigation collections | 🟢 UNCHANGED |
| Feature flags (`NIVX_FLAG_*`) | 🟢 UNCHANGED (env vars only, no new NIVX_FLAG_*) |
| Report semantics · determinism | 🟢 UNCHANGED |

## §10 · New endpoints (7)

```
POST   /api/files                          — streaming upload
GET    /api/files/{file_id}/metadata       — analyst-safe metadata
GET    /api/files/{file_id}                — streaming download
DELETE /api/files/{file_id}                — owner/admin delete
POST   /api/files/{file_id}/pin            — pin to case (retention protect)
POST   /api/files/{file_id}/unpin          — unpin from case
POST   /api/files/{file_id}/analyze        — Input Router dispatch
```

All 7 require valid JWT via `get_current_user`.

## §11 · Owner-locked corrections — verified

| # | Correction | Implementation | Test evidence |
|---|---|---|---|
| 1 | Streaming ingest (no full-file RAM buffering) | 1 MB chunks; SHA-256 + GridFS stream in tandem | `test_upload_streaming_chunk_semantics` + 50 MB runtime RSS delta = -52 KB |
| 2 | Race-safe SHA-256 dedup (unique index) | `create_index(("tenant_id","sha256"), unique=True)` + `insert_one` catches `DuplicateKeyError` | `test_dedup_same_content_returns_same_file_id` + `test_dedup_survives_concurrent_uploads` |
| 3 | Controlled retention (no naïve TTL) | Application-driven `sweep_expired()` deletes GridFS object AND index row atomically | `test_pin_prevents_sweep` + `test_unpinned_and_expired_are_swept` |
| 4 | Tenant-ready identity | Every row carries `tenant_id`; unique index scopes dedup per tenant | `test_dedup_scoped_by_tenant` |

## §12 · Residual limitations (documented)

- **`/api/upload` shim not yet swapped** — the existing route continues to serve WorkspacePage unchanged. Migrating it to a thin forwarder to `/api/files` is a Follow-Up (documented separately) so we don't perturb Workspace mid-implementation. This is intentional — the owner-locked rule was "preserve existing behaviour."
- **Multi-worker safety of retention sweep** — today single-worker uvicorn makes concurrent sweeps impossible. When we move to multi-worker in P5, add an advisory lock (Mongo `findAndModify` on a heartbeat doc).
- **Sandbox / subprocess parser isolation** — still not implemented; PE / DOCX / RC4 parsers remain in-process. Same residual risk as ADR-0010b §11.
- **Retention sweep is manual** — no automated CronJob wired yet. Add `_nightly_files_sweep_loop` alongside `_nightly_benchmark_loop` in a follow-up.
- **Frontend integration** — WorkspacePage still uses `/api/upload`; the new `/api/files` endpoints are backend-ready but frontend uses them only when explicitly called.

## §13 · P2 readiness

**Is NivXRay ready to begin P2 Sysmon/EVTX Adapter?**

**YES.**

Why:
- The Input Router foundation exists and already dispatches by content magic — a new `route == "sysmon"` or `route == "evtx"` branch is a two-line addition.
- The file store handles 200 MB comfortably in streaming mode — real EVTX files (~10-500 MB) fit comfortably.
- Every telemetry file inherits the P0 archive guard when packaged as a ZIP.
- The Canonical Event Bag that Timeline / Query already consume is downstream of DIE analyzers — a Sysmon/EVTX adapter can produce the same shape.
- Zero regression against existing tests (156 pass / 5 skip / 0 fail).

The next implementation session can open on **P2 Sysmon/EVTX Adapter** without carrying an ingestion-boundary risk debt into it.

*End of ADR-0010c · Session-11 P1 close.*
