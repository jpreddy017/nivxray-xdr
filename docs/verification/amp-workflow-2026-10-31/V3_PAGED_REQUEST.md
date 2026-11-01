# Opt-in V3 paged trajectory

V3 uses the separate paged E3 evidence contract, yet previously waited for unused legacy whole-history projection. Added presentation=v3 on its two evidence reads; backend skips legacy V1/dt2 only when explicitly requested. Default combined behavior remains. Identity resolution, tenant scoping, E3 paging and findings joins are unchanged. Whole-history header aggregates are explicitly null/NOT_REQUESTED, not invented zeros.

Three actual-route tests with controlled dependencies pass: V3 avoids legacy projection while preserving E3 scope/time parameters; default retains legacy/dt2; invalid presentation is refused. Actual frontend timeout/retry regression also passes. No populated database performance or full presentation parity certification.

Independent review, real Mongo parity/performance, backend deployment access and authenticated checks remain required. No production deployment. Frontend alone cannot deliver this backend optimization. Against an old backend the new parameter is ignored and the timeout risk remains.
