# EDR timeout repair: frozen review and deployment handoff

Current candidate: 3bbc5c89b6c5de2f4339778868e082501c47d052.
Independent copy: 21e58614a1f4600d538c5bd11fd4fff8e0d4c595.

Independent bounded code review PASS. Reviewer did not author changes. Production release remains unverified.

## Implemented
Opt-in presentation=v3 bypasses unused whole-history legacy projection while retaining the existing scoped endpoint resolver and E3 read arguments. Default combined responses remain unchanged. No truncation to 4000 rows or removal of requested time bounds.
Primary read failures and explicit unavailable envelopes persist with retry. Older-page failures retain prior evidence and cursor, expose retry and ignore obsolete completion.
Fresh artifact persistence failures propagate to the job worker's failed outcome.
Unwanted XDR and NivXMachines header launch controls removed.

## Validation
19 backend tests passed: 9 artifact acknowledgement, 6 pipeline/worker, 4 trajectory route/presentation.
Component adverse-response suite passes: timeout, unavailable primary and older-page HTTP200 envelopes, retained cursor retry, PAGE_READY/TIE_OVERFLOW acceptance, obsolete page failure isolation.
Independent reviewer reran relevant changed suites.
Populated parity uses actual V3 presentation over controlled E3 fixtures. It is not live MongoDB, full authentication or capacity certification.
Authenticated preview before final pagination patch showed persistent timeout and removed header controls. Backend optimization is not deployed; timeout remains.

## Supplied runtime evidence
User relayed resolve about2s, projection31–56s, tail under1s, total33–59s, observations107245, and application504 timeout_ms30000. These support prioritizing the whole-history projection. Raw runtime logs and image/source binding were not independently accessed.
Claim that background warm lacks thread offloading conflicts with repository source: production branch35d47cc96352f492bd4c603a2f2f1b65afb4119f, backend/edr_plane/trajectory_window.py648–692, blob e63846e985c40b56e0bcbb8030356f92aea38db0, uses await asyncio.to_thread(_project_all_sync,...) inside create_task(run()). A different deployed image could explain this mismatch.
Health-check failures alone do not establish VPA eviction causality; pod events are required. Resource utilization, query explain plans and worker count remain unverified.

## Deployment handoff
Obtain the actual Emergent project/Manage Publishes URL for the backend serving edr.nivxforge.com through nivxray.nivxforge.com. Runtime hostname alone is not a deployment management surface.
Bind the zipped /app source tree to reviewed candidate3bbc5c8 using a source manifest; record resulting image digest and retain previous successful image. Do not equate matching health JSON to source identity.
Validate populated tenant-scoped V3 query, paging, unavailable behavior and job persistence failure, measuring total and stage timings. Verify tenant isolation and legitimate empty versus unavailable responses.
Deploy reviewed backend through authorized Emergent workflow with recoverable rollback, then verify the frontend candidate and publish it. Frontend-only promotion cannot install Python repairs.
Do not change Mongo indexes, scale tier or extend deadlines as substitutes for measured repair. Database rollback is separate from image rollback.

Missing VM and full functional separation/Cisco AMP parity remain unresolved.
