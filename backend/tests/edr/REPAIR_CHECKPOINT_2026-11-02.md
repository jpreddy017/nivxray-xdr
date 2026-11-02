# Repair checkpoint — 2026-11-02

Deployment status: HOLD. No merge, deployment, production replay, or existing-data cleanup performed.

Base reviewed: 210a51816e456759c9852769ba3e1847d2509c36.

Completed bounded repairs:
- a700ddbc: constrain trajectory fast-path clock values to hours 00–23 and minutes/seconds 00–59; use ASCII digits. Five invalid-clock regressions failed before repair. Nine added cases cover those clocks and four non-string types. Focused result: 61 passed.
- c5e6418f: repair three stale worker fixtures (claim attempt token) and startup test (validated worker count). Assert lease token forwarding and bounded configuration. 41 passed.
- Current completion guard: preserve bridge stage outcomes; refuse DONE unless canonicalization, parser, evaluation, durable finding state, and stage outcomes report success. Six regression cases fail with the old process_one loaded in memory and pass with the repaired implementation. Combined queue/ownership/bridge/findings: 98 passed.

Full trajectory: 545 passed, 23 skipped. Skips include HTTP auth unavailable (401), unmounted preview adapter, unresolved endpoint fixture. These are not passes. Database tests used loopback 27019 on separate /tmp/reaudit-20261102 storage. Some HTTP integration tests inspect local preview and skipped; no production replay.

Remaining blockers:
- Stage-aware recovery/idempotency after partial pipeline success: completion guard prevents false DONE but does not complete recovery. Duplicate observation path may bypass unfinished downstream stages.
- Historical 1725eef not recovered; its separate checkout and relocated snapshot directory were absent in this runtime. Do not infer entire historical repair restored from this bounded guard.
- Seven iteration_82 failures remain unclassified live integration tests; test file hardcodes environment-specific credentials and fixture assumptions. No credentials included here.
- Production 504 cause, database-upgrade completion, deployment source baseline unresolved.
- Candidate history includes unrelated executions.db change inherited from E3 checkpoint; a clean release diff is still required.
- Original working changes in apps/nivxray-xdr/yarn.lock and rocket-p0/a3 preserved.

Storage last checked: shared /app /root /data/db 9.8G total, 2.4G available, 77% used. No full repository copies created. Test logs remain temporary under /tmp/reaudit-20261102; this checkpoint and committed tests preserve essential evidence in Git.
