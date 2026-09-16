# ADR-0010d · P1.1 · Close the Bridge — `/api/upload` → FileStore

**Status:** ✅ IMPLEMENTED · owner sign-off 2026-08-11
**Scope:** P1.1 close-the-bridge · Automated retention sweep
**Predecessor:** ADR-0010c (P1 Server-Side File Mode foundation)
**Constraint envelope:** Preserve legacy Workspace response contract; no
frontend rewrites; no shadow promotion; no P2 work.

## 1 · Objective

The Workspace UI depends on the legacy `POST /api/upload` endpoint. The
P1 foundation built a canonical `FileStore` (GridFS + race-safe dedup +
200 MB streaming cap + Input Router), but the legacy upload path still
read the whole file into RAM and bypassed the store entirely. P1.1
closes this gap by forwarding every legacy upload through the new
FileStore **before** any analysis buffer, while preserving the exact
external JSON contract used by the Workspace.

## 2 · What changed

### 2.1 · `POST /api/upload` bridge

Before:

```
UploadFile → raw = await file.read()        # unlimited RAM
          → hash md5/sha1/sha256 (recomputed)
          → detect + analyse + respond
```

After:

```
UploadFile → FileStore.put()                 # streaming SHA-256, 200 MB cap
          → returns FileRecord{file_id,sha256,size,mime}
          → open_read() → analyse (bounded by 200 MB cap)
          → respond
```

Additive-only response fields (safe for legacy consumers that ignore
unknown keys):

* `file_id` — opaque server-side id (`nvxf_*`)
* `route` — content-magic classification from Input Router
* `dedup` — `True` when this content already existed under the same
  tenant SHA-256

Legacy contract preserved: `filename`, `size`, `hashes` (md5/sha1/sha256),
`file_type`, `text`, `hex_dump`, `strings`, `content`, `archive_refused`.

### 2.2 · Automated retention sweeper

New module `backend/services/files/retention_sweeper.py`:

* Idempotent asyncio background task started at FastAPI startup
* Invokes `FileStore.sweep_expired()` every
  `NIVX_FILES_SWEEP_INTERVAL_S` (default 86 400 s, floored at 60 s)
* Disabled via `NIVX_FILES_SWEEP_ENABLED=0`
* Fault-tolerant: sweep exceptions are logged and swallowed; the next
  tick still runs
* Cancelled cleanly at FastAPI shutdown

Design constraints (owner-locked):

* **No naïve GridFS TTL** — a Mongo TTL on `fs.files` would leave orphan
  `fs.chunks`. We use application-controlled sweeps via
  `FileStore.sweep_expired`.
* **Pinned files survive** — sweep only touches rows whose
  `pinned_cases` list is empty.
* **Multi-worker** — at current single-worker scale no advisory lock is
  needed. Documented residual limitation for P5 if we scale out.

### 2.3 · `init_database()` resilience

Under pytest-xdist loadscope, a FastAPI TestClient module-scope teardown
would close the shared Motor client, invalidating it for any subsequent
module on the same worker (`InvalidOperation: Cannot use MongoClient
after close`). `init_database()` now detects a closed pymongo topology
and rebinds a fresh Motor client transparently. This restores the
canonical suite's per-worker isolation without asking every test module
to defensively rebind.

## 3 · Files touched

* `backend/routers/ops.py` — `/api/upload` rebuilt on top of FileStore
* `backend/services/files/retention_sweeper.py` — new (background loop)
* `backend/server.py` — startup/shutdown wire-in for retention sweeper
* `backend/deps.py` — resilient rebind in `init_database`
* `backend/tests/canonical/api/test_p11_upload_bridge.py` — 11 tests
* `backend/tests/canonical/api/test_p11_retention_sweep.py` — 7 tests
* `backend/tests/canonical/ssot/test_ssot_isolation.py` — Phase 5.1
  allow-list updated for the 3 files above

## 4 · Streaming + dedup evidence

Live smoke against the pod backend (`admin@nivxray.com` on
`test_database`, 2026-08-11):

```
--- LIVE UPLOAD ---
keys:            ['archive_refused', 'content', 'dedup', 'file_id',
                  'file_type', 'filename', 'hashes', 'hex_dump',
                  'route', 'size', 'strings', 'text']
archive_refused: None
file_id:         nvxf_a80dd57c41da4837a3556ab8701fd5a7
route:           text
dedup:           False
sha256:          aee1ec8f85d7373a4ba82b3d756161b225116d5fce301754b89fc1f24601bdab
size:            38

--- LIVE DEDUP (identical bytes) ---
file_id:         nvxf_a80dd57c41da4837a3556ab8701fd5a7   ← same id
dedup:           True                                     ← flag flipped
```

## 5 · Test suite deltas

**Before P1.1 (canonical/api/):** 156 passed · 5 skipped · 0 failed
**After P1.1 (canonical/api/):** 174 passed · 5 skipped · 0 failed
**Delta:** +18 new tests · 0 regressions

**Full canonical suite (against pod `test_database`):** 393 passed ·
3 skipped · 0 regressions from P1.1 changes.

The 4 pre-existing `Sample1 fingerprint` failures in `nivxray_ci_local`
are a data-seed issue unrelated to P1.1 (they pass against the pod DB
which has Sample1 seeded).

## 6 · Response-contract compatibility matrix

| Field            | Legacy present | Post-P1.1 present | Semantics preserved |
|------------------|:--------------:|:-----------------:|:-------------------:|
| filename         | ✓              | ✓                 | ✓                   |
| size             | ✓              | ✓                 | ✓ (from FileStore)  |
| hashes.md5       | ✓              | ✓                 | ✓                   |
| hashes.sha1      | ✓              | ✓                 | ✓                   |
| hashes.sha256    | ✓              | ✓                 | ✓ (authoritative)   |
| file_type        | ✓              | ✓                 | ✓                   |
| text             | ✓              | ✓                 | ✓ (64 KB cap held)  |
| hex_dump         | ✓              | ✓                 | ✓                   |
| strings          | ✓              | ✓                 | ✓                   |
| content          | ✓              | ✓                 | ✓ (64 KB cap held)  |
| archive_refused  | ✓              | ✓                 | ✓ (P0 guard held)   |
| file_id          | ✗              | ✓ (additive)      | new                 |
| route            | ✗              | ✓ (additive)      | new                 |
| dedup            | ✗              | ✓ (additive)      | new                 |

## 7 · Protected surfaces verified untouched

* RC5/DIE canonical pipeline — unchanged
* IKG (shadow) — unchanged
* Verdict v3 (shadow) — unchanged
* Case Engine (shadow) — unchanged
* No new `NIVX_FLAG_*` introduced
* No Mongo schema redesign
* No shadow → live promotion
* No P2 work (Sysmon/EVTX adapter deferred pending Real Investigation Proof)

## 8 · Residual risks

* **Multi-worker retention** — at scale-out we will need an advisory
  lock (Mongo `findAndModify` with a lease document) to serialise the
  sweep across workers. Documented for P5.
* **Same-process parser isolation** — unchanged from ADR-0010b. The PE
  / DOCX / shellcode parsers still run in the API worker. Backlog.
* **Response-payload size for large text uploads** — the 64 KB output
  cap remains; upload storage cap is 200 MB. No unbounded response
  growth introduced.

## 9 · Decision

**PASS.** P1.1 is complete. The legacy Workspace upload path now
routes through the canonical FileStore + Input Router while preserving
its external JSON contract. Automated retention is armed and idempotent.

Next: the owner is running the Real-Investigation Proof experiment
against the LIVE product before authorising P2 (Sysmon/EVTX).
