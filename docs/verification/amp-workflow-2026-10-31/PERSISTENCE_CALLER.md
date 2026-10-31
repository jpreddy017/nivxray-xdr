# Persistence caller repair

The fresh-decode caller previously logged artifact write failure and returned a successful decoded report. Removed that catch so failure reaches the existing job worker, which records failed and emits failed rather than complete. Cache-hit writes already propagated errors. Serialization errors also propagate.

Six isolated tests execute the actual source functions with controlled decoder/store boundaries: fresh write failure, cached write failure, success report parity, cancellation, no-report behavior, and actual worker failed-not-complete handling. They do not certify MongoDB runtime or production deployment.

Stale-cache deletion before replacement remains an unresolved recoverability problem; this patch does not change identity, schema, tenant scoping or replacement semantics. Independent review and backend deployment verification remain pending.
