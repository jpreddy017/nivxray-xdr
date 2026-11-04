# B3 · SENSOR-SIDE FILE CONTENT HASHING — DESIGN FOR OWNER REVIEW

**Status: DESIGN ONLY. NOT IMPLEMENTED. NOT DEPLOYED. No endpoint was
changed by this document.**

Why it is needed, measured — not assumed:

| measurement | value | source |
|---|---|---|
| canonical `file_create` observations (real corpus) | **107** | `xdr_canonical_evidence`, `ten_f1a5479243e901cf159e230fa0` |
| of those carrying ANY file hash | **0** | `file.hashes` non-empty = 0 |
| of those carrying a file SIZE | **0** | `file.size_bytes` non-null = 0 |
| of those naming the WRITING process | **107** | `WRITER_SOURCE_STATED` |
| process-image SHA-256 present | **16 / 16 `process_create`** | `process.hashes.sha256` |

So: *we know which process wrote which path, and we know the hash of the
EXE that ran. We do not know the bytes that were written.* Sysmon
EventID 11 (`FileCreate`) carries no hash and no size, by design.

`PROCESS_IMAGE_HASH` ≠ `FILE_CONTENT_HASH`. The first is already
preserved end-to-end (B1/B3 regressions pin it). The second does not
exist in this telemetry and **must not be manufactured from the first**.

---

## 1 · THE PIPELINE BEING PROPOSED

```
FILE EVENT (source-stated: path + writer + time)
        ↓
AUTHORITATIVE FILE IDENTITY / PATH          (already exists, B3)
        ↓
SAFE ACQUISITION ELIGIBILITY                (new · policy gate)
        ↓
CONTENT ACQUISITION                         (new · bounded read)
        ↓
SHA-256                                     (new · streamed digest)
        ↓
PROVENANCE                                  (new · who/when/how/version)
        ↓
CANONICAL FILE OBSERVABLE                   (already exists, B3)
        ↓
REPUTATION / RETROSPECTIVE CONSUMERS        (already exists, B4)
```

Only the three middle stages are new. The identity contract and the
observable contract are already built and under regression, so the
acquisition layer plugs into them without a second file model.

---

## 2 · THE NON-NEGOTIABLE SEMANTIC PROBLEM

A hash computed *after* an event is a fact about **the bytes at hash
time**, not about the bytes at event time. The proposal therefore never
emits a bare `file.sha256`. It emits a **content acquisition record**:

```
file_content_acquisition = {
  path,                        # the path acquired, verbatim
  file_identity_at_event,      # path + writer + event time (B3)
  acquisition_state,           # see §3 — the authority of this record
  sha256,                      # ONLY when acquisition_state = ACQUIRED
  hash_algorithm: "SHA-256",
  hash_algorithm_version,      # the implementation identity
  size_bytes,                  # size AT HASH TIME
  event_observed_at,           # when the write was observed
  acquired_at,                 # when the bytes were read
  acquisition_latency_ms,      # acquired_at - event_observed_at
  content_version_state,       # see §5 — is this the written content?
  mtime_at_acquisition,        # OS-stated, for change detection
  ctime_at_acquisition,
  acquirer,                    # sensor id + sensor version
  policy_id,                   # which eligibility policy admitted it
  provenance                   # field → wire/syscall origin
}
```

`sha256` without `acquisition_state = ACQUIRED` and without
`content_version_state` is **forbidden by contract**: it would be a hash
whose subject is unknown.

---

## 3 · ACQUISITION STATES (the honest outcomes)

Every attempted acquisition resolves to exactly one:

| state | meaning |
|---|---|
| `ACQUIRED` | bytes were read to completion and hashed |
| `NOT_ELIGIBLE_BY_POLICY` | excluded path / extension / size / rate class — a POLICY fact, not a gap |
| `FILE_ABSENT_AT_ACQUISITION` | deleted / moved before we could read (very common for droppers) |
| `ACCESS_DENIED` | ACL or integrity level refused the read |
| `LOCKED_OR_SHARING_VIOLATION` | opened exclusively by another process |
| `SIZE_LIMIT_EXCEEDED` | larger than the configured ceiling |
| `TIMEOUT` | read exceeded the per-file deadline |
| `IO_ERROR` | device/filesystem error |
| `RATE_LIMITED` | the endpoint's hashing budget was exhausted |
| `HASH_NOT_ATTEMPTED` | hashing disabled for this endpoint/policy |

**None of these is `HASH_NOT_OBSERVED` by accident.** They are distinct
causes, and every one of them maps to the existing B3 vocabulary as
`hash_state = HASH_NOT_OBSERVED` **plus** a stated reason. A consumer can
therefore tell "we chose not to hash" from "the file vanished" from "we
were refused", which a single `HASH_NOT_OBSERVED` cannot.

---

## 4 · ELIGIBILITY GATE (evaluated BEFORE any read)

Ordered, cheap-first, all from the event alone:

1. **Operation class** — CREATE and WRITE/MODIFY are eligible. DELETE is
   not (there is nothing to read). RENAME/MOVE is eligible only at the
   DESTINATION path (see §6).
2. **Exclusion list** — page/hibernation files, volume shadow devices,
   `\\Device\\`, named pipes, the sensor's own directories, and
   operator-declared excluded paths. Reading these is either meaningless
   or a stability risk.
3. **Privacy exclusions** — operator-declared sensitive trees (user
   documents, mail stores, DB data files). Hashing does not transmit
   content, but a hash IS a content identifier, so a hash of a private
   document is still a privacy-relevant artefact and must be an explicit
   operator decision. Default: **excluded**.
4. **Extension/type policy** — default allow-list posture: executables,
   scripts, archives, LNK, macro-bearing documents. Everything else
   requires an explicit operator opt-in.
5. **Size ceiling** — default **64 MiB**. Above it: `SIZE_LIMIT_EXCEEDED`
   (never a partial hash presented as a hash).
6. **Dedup / cache** — `(volume_guid, file_id, mtime, size)` already
   hashed within the cache window ⇒ reuse, recorded as
   `cache_state = CACHE_HIT` with the original `acquired_at`. A reused
   hash never claims a fresh acquisition time.
7. **Rate budget** — see §8.

Every refusal is recorded with the `policy_id` that caused it. An
operator can then answer "why was this file not hashed" without guessing.

---

## 5 · TOCTOU / CONTENT VERSION (the core integrity problem)

Between the event and the read, the file may have been rewritten. The
proposal does not pretend otherwise; it MEASURES it.

Acquisition sequence:

1. open with read-only, **backup-semantics, no write-share request**;
2. capture `pre = (file_id, size, mtime, ctime)`;
3. stream-hash the content (fixed 1 MiB buffers, no full-file mapping);
4. capture `post = (file_id, size, mtime, ctime)`;
5. classify:

| `content_version_state` | condition |
|---|---|
| `STABLE_DURING_ACQUISITION` | `pre == post` and `file_id` unchanged |
| `CHANGED_DURING_ACQUISITION` | `pre != post` — the hash describes a torn read and is **discarded**, state becomes `IO_ERROR`/retry |
| `CHANGED_SINCE_EVENT` | `mtime_at_acquisition > event_observed_at` — the hash is valid for the bytes we read, but they are **not provably the bytes the event described** |
| `CONSISTENT_WITH_EVENT` | `mtime_at_acquisition <= event_observed_at + tolerance` and no intervening write event was observed |

`CHANGED_SINCE_EVENT` is still useful intelligence (it is a real content
identity of a real file), but it may **never** be presented as the hash
of the observed write. Retrospective hunting must be able to filter on
this field.

**Repeated writes**: a file written N times produces N events. Hashing
every one is both wasteful and misleading. Proposed behaviour:
**coalesce** writes to the same `(volume_guid, file_id)` inside a short
settle window (default 2 s, max 30 s), hash ONCE after the window, and
attach the acquisition record to **all** coalesced events with
`coalesced_event_refs[]`. The count of coalesced writes is preserved —
the events are not merged, only the acquisition is shared.

---

## 6 · RENAME / MOVE / DELETE

* **RENAME/MOVE**: the source path ceases to exist; the destination is
  the live object. Acquire at the destination, and record
  `renamed_from` from the source event. The FILE identity (content) is
  unchanged by a rename — which is exactly why content identity, not
  path, is the identity.
* **DELETE before acquisition**: `FILE_ABSENT_AT_ACQUISITION`. This is
  the single most common outcome for real droppers and it must be a
  first-class, countable state, not a silent absence. (Optional future:
  acquire from the delete event's own captured content where the OS
  offers it — **out of scope**, listed only so it is not forgotten.)
* **Deleted-then-recreated at the same path**: `file_id` differs, so the
  cache key differs and a fresh acquisition is performed. Path-keyed
  caching would have returned the WRONG hash; hence the `file_id` in the
  key.

---

## 7 · PERFORMANCE / ENDPOINT SAFETY

Hard requirement: **the sensor must never be the reason a workstation
stutters.** Proposed defaults, all operator-tunable, all reported in the
sensor's health telemetry:

* hashing runs on a **bounded worker pool** (default 1 worker), never on
  the event-delivery path;
* a **bounded queue** (default 512) with an explicit `DROPPED_QUEUE_FULL`
  outcome — a dropped acquisition is recorded, not lost;
* **per-file deadline** 5 s; **per-minute budget** default 120 files;
  **per-minute byte budget** default 512 MiB;
* **I/O priority**: `FILE_FLAG_SEQUENTIAL_SCAN`, background I/O priority
  on Windows (`SetThreadInformation`/`THREAD_MODE_BACKGROUND_BEGIN`);
* **never** hash on battery below an operator threshold (laptop rule);
* self-measurement: acquisitions attempted / acquired / refused by
  cause, bytes hashed, p50/p95 latency, queue depth, drops — emitted as
  sensor health so the cost is visible rather than assumed.

## 8 · RATE LIMITING AND CACHE

* cache key: `(volume_guid, file_id, size, mtime)` → `sha256`, with
  `acquired_at`, `sensor_version`, `policy_id`;
* default cache TTL 24 h, bounded entry count, LRU;
* a cache hit carries `cache_state` and the ORIGINAL acquisition
  provenance. Freshness is explicit; a stale hit is served as stale, the
  same rule B4's reputation cache already enforces;
* rate-limit exhaustion is `RATE_LIMITED`, never a silent skip.

## 9 · SECURITY OF THE ACQUIRER ITSELF

* read-only; the sensor never writes, moves or quarantines during
  acquisition;
* no content ever leaves the endpoint — **only the digest and the
  metadata above**. This is a hashing design, not a file-collection
  design. (File collection, if ever wanted, is a separate owner
  decision with its own privacy review.)
* reparse points / symlinks / junctions are NOT followed by default
  (`FILE_FLAG_OPEN_REPARSE_POINT`), so an attacker cannot aim the
  acquirer at a device or a network path;
* hard limits are enforced in the sensor, not in the server, so a
  compromised server cannot instruct an endpoint to hash the world;
* the acquirer runs with the sensor's existing privileges only — no new
  privilege is requested.

## 10 · CANONICAL CONTRACT CHANGES THIS WOULD REQUIRE

Additive only, and each one is a NEW field — no existing field changes
meaning:

| canonical field | meaning |
|---|---|
| `file.hashes.sha256` | already exists; populated only on `ACQUIRED` |
| `file.size_bytes` | already exists; size at hash time |
| `file.content_acquisition` | the record in §2 |
| `file.field_provenance["hashes.sha256"]` | `sensor:content_acquisition(SHA-256)` — never `sysmon:*`, because Sysmon did not state it |
| `file.hash_state` | existing B3 vocabulary; `HASH_NOT_OBSERVED` keeps its `acquisition_state` reason |

B3's `from_canonical()` already reads all of these; no read-model change
is needed beyond carrying `content_acquisition` through the projection
(one more preserved block, one more regression).

## 11 · WHAT I AM NOT PROPOSING

* no content upload, no quarantine, no file deletion, no blocking;
* no hashing of every file on disk (no "scan" posture);
* no ML, no static classification;
* no change to `PROCESS_IMAGE_HASH` semantics;
* no inference of a file hash from a process-image hash, ever.

## 12 · OWNER DECISIONS REQUIRED BEFORE ANY IMPLEMENTATION

1. Is sensor-side hashing authorised **in principle** on the acceptance
   endpoint only?
2. Default posture: allow-list by extension (proposed) or all-files with
   exclusions?
3. Privacy trees: excluded by default (proposed) or operator-declared
   per tenant?
4. Size ceiling (proposed 64 MiB) and per-minute budget (proposed 120
   files / 512 MiB).
5. Settle window for coalescing repeated writes (proposed 2 s).
6. Is `CHANGED_SINCE_EVENT` acceptable as retained intelligence, or must
   such acquisitions be discarded?

Nothing in this document runs until those six answers exist.
