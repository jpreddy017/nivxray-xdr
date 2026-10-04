# B5-3 · SENSOR CONTRACT · FILE-CONTENT HASHING

**DESIGN ONLY. NOT IMPLEMENTED. NOT DEPLOYED. The endpoint was not
changed.** This is the contract the approved B3 defaults become before
any sensor code exists.

Owner-approved defaults, acceptance endpoint only:
controlled file-type allow-list · privacy-sensitive trees excluded ·
64 MiB ceiling · 120 acquisitions/minute · 2 s settle window ·
changed content retained explicitly as `CHANGED_SINCE_EVENT`.

## 0 · THE TWO SUBJECTS NEVER MERGE

```
PROCESS_IMAGE_SHA256     the hash of the EXE that RAN
        ≠
FILE_CONTENT_SHA256      the hash of the BYTES that were WRITTEN
```

They are different observable SUBJECTS (`SUBJECT_PROCESS_IMAGE` /
`SUBJECT_FILE_CONTENT`, already enforced in
`edr_plane/reputation/contract.py`) and are carried in different
canonical blocks (`process.hashes` / `file.hashes`). A file never
inherits its writer's image hash, and nothing in this contract may
introduce a path by which it could. Measured today: process-image
SHA-256 16/16 present; file-content SHA-256 **0/107**.

## 1 · STATE MACHINE

```
FILE_CREATE / FILE_WRITE observed          (source-stated: path, writer, time)
        │
        ├─ ELIGIBILITY  ──► NOT_ELIGIBLE_BY_POLICY        (terminal, reasoned)
        │                   UNSUPPORTED_TYPE              (terminal, reasoned)
        │                   EXCLUDED_PRIVACY_PATH         (terminal, reasoned)
        │                   HASH_NOT_ATTEMPTED            (terminal, policy off)
        ▼
   ACQUISITION_SCHEDULED        (queued · queue bounded · never on the event path)
        │
        ├─ RATE_LIMITED / DROPPED_QUEUE_FULL              (terminal, counted)
        ▼
   SETTLE (2 s, max 30 s)       (coalesces a write burst into ONE acquisition)
        │
        ▼
   IDENTITY REVALIDATION        (volume_guid + file_id + size + mtime re-read)
        │
        ├─ FILE_ABSENT_AT_ACQUISITION   (deleted/moved — the common dropper case)
        ├─ IDENTITY_CHANGED             (file_id differs ⇒ a DIFFERENT file now)
        ├─ CACHE_HIT                    (same identity already hashed — reuse)
        ▼
   HASH ATTEMPT                 (streamed 1 MiB buffers · background I/O priority)
        │
        ├─ ACCESS_DENIED · LOCKED_OR_SHARING_VIOLATION
        ├─ SIZE_LIMIT_EXCEEDED (>64 MiB) · TIMEOUT (5 s) · IO_ERROR
        ▼
   CONTENT VERSION CLASSIFICATION
        │
        ├─ CHANGED_DURING_ACQUISITION   (torn read — hash DISCARDED, retry once)
        ├─ CHANGED_SINCE_EVENT          (valid hash · NOT the observed version)
        └─ CONSISTENT_WITH_EVENT
        ▼
   SHA-256 + PROVENANCE ──► canonical FILE observable ──► reputation / hunt
```

Every terminal state that is not `ACQUIRED` maps to the existing B3
`hash_state = HASH_NOT_OBSERVED` **plus its own `acquisition_state`
reason**. One vocabulary; a cause is never collapsed into a silence.

## 2 · CONTRACT FIELDS (additive; nothing existing changes meaning)

```
file.hashes.sha256                     only when acquisition_state = ACQUIRED
file.size_bytes                        size AT HASH TIME
file.hash_state                        HASH_OBSERVED | HASH_NOT_OBSERVED
file.field_provenance["hashes.sha256"] "sensor:content_acquisition(SHA-256)"
                                       — never "sysmon:*": Sysmon did not
                                         state it
file.content_acquisition = {
  acquisition_state, acquisition_reason,
  content_version_state,
  hash_algorithm: "SHA-256", hash_algorithm_version,
  volume_guid, file_id, size_at_acquisition,
  mtime_at_acquisition, ctime_at_acquisition,
  event_observed_at, acquired_at, acquisition_latency_ms,
  settle_window_ms, coalesced_event_refs[], coalesced_write_count,
  cache_state, cache_source_acquired_at,
  policy_id, acquirer: {sensor_id, sensor_version},
  renamed_from
}
```

A `sha256` without `acquisition_state = ACQUIRED` **and**
`content_version_state` is forbidden by contract: it would be a hash
whose subject is unknown.

## 3 · EVERY CASE THE OWNER LISTED

| case | behaviour | why |
|---|---|---|
| **deletion before hash** | `FILE_ABSENT_AT_ACQUISITION`, counted, with the writer and path preserved | the most common real dropper outcome; it must be a first-class huntable state, not a silence |
| **rename / move** | acquire at the DESTINATION; `renamed_from` records the source path; content identity is unchanged by a rename | content identity is the identity precisely because paths move |
| **repeated writes** | coalesced inside the 2 s settle window into ONE acquisition; `coalesced_event_refs[]` + `coalesced_write_count` attach it to every write event | the events stay individual — only the acquisition is shared |
| **locked / access denied** | `LOCKED_OR_SHARING_VIOLATION` / `ACCESS_DENIED`; no retry storm (one retry after settle) | an unreadable file is a fact about our access, not about the file |
| **oversized** | `SIZE_LIMIT_EXCEEDED` at 64 MiB — never a partial hash presented as a hash | a padded payload is an attacker-visible evasion, so the state must be LOUD and huntable |
| **rate limiting** | `RATE_LIMITED` / `DROPPED_QUEUE_FULL`, both counted in sensor health | a skipped acquisition is recorded, never lost |
| **TOCTOU / content changed** | `CHANGED_DURING_ACQUISITION` ⇒ hash discarded; `CHANGED_SINCE_EVENT` ⇒ hash retained and LABELLED, filterable, never presented as the observed version | a hash is a fact about the bytes read at hash time, and the contract says so |
| **unsupported type** | `UNSUPPORTED_TYPE` with the allow-list `policy_id` | a policy decision, visible as one |
| **excluded / privacy path** | `EXCLUDED_PRIVACY_PATH` with the `policy_id`; the path is recorded, the content is never read | a SHA-256 is a content identifier; hashing private documents must be an explicit operator decision |

## 4 · NON-NEGOTIABLES

* read-only: the acquirer never writes, moves or quarantines;
* **no content leaves the endpoint** — digest and metadata only. This is
  a hashing design, not a file-collection design;
* reparse points / symlinks / junctions NOT followed
  (`FILE_FLAG_OPEN_REPARSE_POINT`), so the acquirer cannot be aimed at a
  device or a network path;
* limits are enforced IN THE SENSOR, so a compromised server cannot
  instruct an endpoint to hash the world;
* no new privilege is requested;
* cache key is `(volume_guid, file_id, size, mtime)` — a path-keyed cache
  returns the WRONG hash after delete-and-recreate;
* hashing runs on a bounded worker pool, never on the event-delivery
  path; acquisitions attempted/acquired/refused-by-cause, bytes hashed,
  p50/p95 latency, queue depth and drops are emitted as sensor health so
  the cost is measured rather than assumed;
* never on battery below an operator threshold.

## 5 · ACCEPTANCE (when implementation is authorised)

Positive: a known file written by a known process yields
`ACQUIRED` + `CONSISTENT_WITH_EVENT` + SHA-256 + provenance.
Negative, one test each: delete-before-hash · rename · 5 rapid writes
(one acquisition, five events) · locked file · 65 MiB file · excluded
path · unsupported type · rate-limit exhaustion · content modified
between event and hash. Plus: the process-image hash of the writer never
appears in `file.hashes` in ANY of them, and endpoint CPU/I-O stays
within the declared budget for a measured hour.

**Implementation is NOT authorised by this document.**
