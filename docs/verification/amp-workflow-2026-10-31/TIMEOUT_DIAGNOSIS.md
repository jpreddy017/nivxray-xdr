# Trajectory timeout: confirmed evidence and bounded UI repair

Live authenticated candidate96ff8c1 returned the browser error: Trajectory read failed: timeout of 30000ms exceeded. Computers and Events loaded KUSHU telemetry during the same session. This proves the client deadline was reached, not a CPU or hosting diagnosis.

Source trace at production35d47cc: trajectory_v3/amp/TrajectoryPage always sends time_start and time_end. backend/edr_plane/trajectory_window.py query_window sets wants_complete if either time bound exists; _projected then receives docs_limit=None. Its endpoint-history find has no window filter/limit in that mode. Projection, detection attribution, evaluation and lane building occur before viewport filtering. The 500 requested rows do not bound this work. Additional e3 and v3 response representations are constructed by the route. Runtime CPU/RAM, database explain plans, actual serving backend revision and stage timings are not yet verified; the exact dominant runtime stage remains unproven.

Do not remove time bounds merely to trigger the bounded path: it may omit events in the requested window and change history/lane semantics. Do not increase timeout and call the root cause fixed. Need bounded window reads and a stable lane-index design, compared for full evidence and pagination parity before backend rollout.

## Implemented presentation repair
The primary read now retains an accessible error with Retry rather than showing a transient toast then an apparently empty graph. New reads clear obsolete evidence; the status distinguishes loading, unavailable and genuinely empty successful responses. Retry issues a new request; canceled/stale effects cannot commit after cleanup. No timeout increase, backend mutation, evidence truncation or production deployment.

Actual component test uses deferred API doubles: timeout remains visible, failure is not zero evidence, retry issues a fresh request, success clears failure. This is not a live backend performance repair or independent release approval.
