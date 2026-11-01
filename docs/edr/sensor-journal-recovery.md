# Windows sensor journal recovery — 2026-11-01

## Observed production evidence

KUSHU's sensor-reported integrity snapshot, reported 2026-11-01 11:54:04 UTC and received 11:54:06 UTC, recorded a local delivery backlog of 248,455 records, 482,553,096 live journal bytes and 1,042,497,536 physical journal bytes. Sysmon had committed record 85,684,777, while its reported source oldest/newest were 85,688,682 / 85,773,003. This establishes a reported continuity gap before the surviving source tail and acquisition lag; it does not date or quantify a month-wide loss. The snapshot reports 1,738 acquisition-gap declarations, not 1,738 missing events.

The reported ACQUISITION_HALTED_JOURNAL_FULL flag was latched in source code. Its presence did not prove acquisition was still halted at snapshot time: the reported live payload size was just below the default 90% critical threshold. Historical halt gauges remain important evidence and must not be erased.

Server receipt and processing have their own backlog. A previously traced October 31 sample was received November 1 and remained PENDING at the time of that read. Cumulative delivery counters are not daily coverage. A historical receipt filter did not return a validated filtered result, so no missing-day receipt counts are asserted.

## Corrections

- Record a server-acknowledged batch in one SQLite BEGIN IMMEDIATE / COMMIT with synchronous=FULL unchanged. Autocommit executemany previously committed each row separately. On a write error, rollback leaves the batch deliverable for retry. No unacknowledged evidence is reclaimed.
- Clear the current halt latch and reason when capacity admission succeeds, both immediately and after reclaim. Preserve historical halt counter, timestamp and reason gauges.
- After a successful delivery cycle with remaining backlog and zero delivery failures, wait one second before the next bounded cycle. Idle, refused and zero-progress cycles retain the existing normal interval. Acquisition and delivery retain their per-cycle bounds, normal identity, policy and per-row server acceptance rules. This is a single serial loop; no parallel uploads or extra workers are introduced.
- Identify this candidate as sensor 0.3.1-windows / journal 1.0.1, schema unchanged. Run the seven recovery regressions in the existing Windows installer workflow before building.

## Validation

Seven synthetic recovery tests reproduced four failures on the old source and all pass on the candidate. Tests cover durable acknowledgement/reopen, write rollback/retry, capacity recovery without evidence or cursor loss, productive backlog scheduling and refusal/no-progress/idle backoff.

Isolated existing paging + journal durability suites, plus the new regressions: 59 passed in 7.60 seconds. Source acquisition was synthetic, HTTP was disabled and the fixture's sensor path was explicitly redirected to the candidate. No production database, endpoint journal or installed service was modified.

A separate local synthetic 2,500-row / 50-batch acknowledgement experiment took 0.7738 seconds on baseline and 0.0346 seconds on candidate. This is a local disk experiment, not a measured Windows or production throughput improvement. The acceptance criterion is correct transaction boundaries and retained evidence, not that ratio.

## Storage and flow

The backend already durably stores received raw logs before queue processing. An extra cloud bucket does not repair sensor upload lag. A collector must stay available, accept authenticated batches, persist them before acknowledgement and let processing run independently. Local sensor storage still needs finite bounds and visible pressure. Sustainable delivery and processing must exceed sustained incoming volume; larger storage only extends outage tolerance.

No capacity limit is raised, no evidence is purged, no bookmark is reset and no host security setting is weakened by this patch. Existing source rollover cannot be reconstructed from this patch. Preserve available EVTX and journal evidence before a canary upgrade.

## Release and acceptance

Source validation is complete; installed-endpoint recovery is NOT yet verified. The existing GitHub Windows workflow builds the PE and exercises its frozen SQLite/WAL/restart and service gates. A web/backend deployment does not update an installed sensor.

Before KUSHU canary: require successful Windows build/gates; record installer and service-host hashes and exact build commit; preserve the current service configuration, identity, journal/WAL and bookmarks using a consistent backup; use the supported update path without re-enrolment or cursor reset. Verify that the installed build is 0.3.1-windows and retains the endpoint and tenant.

Measure repeated integrity reports: live journal bytes, backlog and oldest pending time; accepted-record rate versus incoming rate; Sysmon committed cursor versus surviving source tail; refusal/timeouts; server queue lag; latest canonical event and trajectory visibility. A decreasing backlog and advancing current activity over repeated samples are required before declaring recovery. Historical coverage requires a separate day-by-day reconciliation of source availability, raw receipt, processed activity and query visibility.

If delivery remains slower than acquisition, profile network/batch ingest next. Keep server ACK after durable raw storage and scale measured collector/processing bottlenecks without bypassing durability. KUSHU native filesystem/service access has not been established in this session; source merge or an available installer is not an installed fix.

Rollback only the sensor binaries through a supported stopped-service update, preserving state, identity, bookmarks and evidence. This patch has no schema migration to reverse.
