# A–I PRODUCTION ENFORCEMENT ACCEPTANCE — RUN SHEET (awaiting republish)

Owner authorization received: re-publish only, to activate the already-configured
deployment secret `NIVX_TENANT_REGISTRY_ENFORCE=true` on
`https://nivxray.nivxforge.com`.

## AUTHORIZED SCOPE (frozen)
- Accepted application code: `e2d8f54` · previous publish 100 · rollback ref `8e473e4`
- Authoritative org: `org_55f6dc202dbf8995369db989ad`
- Authoritative tenant: `ten_e759b7288598bd882e3dcac49d` (ACTIVE · XDR, EDR)
- Read-only probes + two deliberately-rejected negatives (D, E/G) only.
- Zero persistent mutation. No collector, API key, endpoint, enrollment token,
  telemetry, forwarder.json/ingest.key/bookmark change, production legacy
  adoption, org/tenant creation, UI or enhancement work.
- No production-owner credential is taken from `/app/memory/test_credentials.md`,
  the pod, source, or environment. Authenticated probes are owner-executed with
  the owner's own in-session `$tok`.
- HARD STOP after A–I. W1 stays paused.

## STATE
- [ ] Owner presses Republish
- [ ] Owner reports production healthy + new publish/build identity
- [ ] Agent runs unauthenticated baseline recheck (agent-side, no credential)
- [ ] Owner runs authenticated A–I block, returns non-secret outputs
- [ ] Agent writes acceptance/failure evidence report

## ON UNEXPECTED FAILURE
STOP. No compensating tenant creation or adoption. No enforcement weakening.
No automatic rollback. Classify the evidence as: deployment/build ·
enforcement secret · tenant data/authority · authentication/RBAC · stale test
expectation. Build rollback and enforcement rollback remain independent
decisions (secrets are not versioned; a build rollback does NOT clear the flag).

## AUTHENTICATED A–I BLOCK
Canonical source: `/app/memory/W1_PHASE3_ENFORCEMENT_ACTIVATION_PROCEDURE.md` §4.
The consolidated single-paste version will be handed to the owner once the new
deployment reports healthy (so the block can be stamped with the new build id).
