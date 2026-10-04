# E1 PERMANENT INVARIANT · CANONICAL NORMALIZATION AUTHORITY

Recorded 2026-06 by owner direction, as an architectural record. **No implementation now.** Nothing
in this document authorizes a new subsystem, a rewrite, or any change to working components. It
exists so that future work can be classified against a stated authority instead of rediscovering it.

## The pipeline

```
source / raw evidence
  → preserve immutable raw representation          (raw is never edited in place)
  → source adapter / Universal Decoder
  → CANONICAL NORMALIZATION BOUNDARY               (the single authority)
  → canonical evidence
  → downstream EDR engines
```

## The rule

Canonical normalization must ultimately provide **one authoritative normalized representation** for
each of:

| domain | authority must cover |
|---|---|
| temporal semantics | comparable instant, ordering, windowing |
| endpoint / host identity | endpoint_id, hostname, device identity |
| user identity | principal, SID/UPN, domain |
| process | pid/ppid lineage, image path, command line |
| file / hash | path normalization, hash algorithms |
| network | IP, port, direction, protocol |
| DNS / URL | name, registrable domain, URL parts |
| registry | hive, key, value |
| event type | activity classification |
| provenance | collector, trace, authority, state |
| canonical types / enums | severity, verdict, state vocabularies |

**Downstream consumers — Device Trajectory, Behavior, Investigation, correlation, TI and ML — must
consume canonical normalized fields and must not independently interpret heterogeneous source
representations.** Every place a downstream component re-parses a source representation is a second
temporal-string-sorting defect waiting to be found.

## Why this invariant exists — the G-41 lesson

G-41 is the temporal instance of exactly this principle, and it is worth recording what the defect
actually was. Chronological ordering was performed by **string** comparison over `event_time`, whose
production population turned out to hold two different representations — 43,521 space-separated and
78,956 trailing-`Z` — which do not sort consistently against each other. The ordering of evidence was
therefore wrong, silently, and every downstream consumer inherited it.

The fix was not to rewrite normalization. It was to establish ONE authoritative derived
representation (`observation_us`, signed integer UTC epoch microseconds), produce it at the single
canonical writer boundary, and make paging and windowing consume only that. `event_time` is
preserved untouched: the raw representation remains immutable, and the normalized value is additive.

**`observation_us` is the current temporal implementation of this invariant.** It is not a prototype
for a new framework.

## Deferred — bounded inventory AFTER G-41 closes

After G-41 closes, and without interrupting the Production V1 critical path, classify each existing
normalization capability as exactly one of:

* **KEEP** — already a correct single authority.
* **EXTEND** — correct, but missing an invariant (as temporal was, before `observation_us`).
* **CONSOLIDATE** — a duplicate normalization authority exists; two components interpret the same
  source representation independently.
* **REPLACE** — only where fundamentally unsafe or wrong.

An inventory classifies; it does not implement. Any REPLACE finding becomes its own owner-authorized
decision with its own gates, exactly as G-41 did.

## Explicitly out of scope of this record

No normalization rewrite. No new subsystem. No E3 involvement. No KUSHU / DESKTOP sensor state
change. No V3 / frontend enablement. No deletion or abandonment of the 122,477 historical canonical
evidence records — they are to be migrated additively, never discarded.
