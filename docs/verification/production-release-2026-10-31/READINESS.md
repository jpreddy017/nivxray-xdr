# Production release verification — 31 October 2026

Owner requests production updates. Authorization is recorded; release remains blocked by incomplete verification, not missing owner consent.

## Exact candidate and target
- Current-product candidate: jpreddy017/nivxray-xdr@84c43bbff3745155768c8d6055548e97e0d3d911.
- Vercel project: nivxray-edr-production (prj_KrtnUHko9opTWHv0cbXS1a2EAKV4).
- Team: team_GpHdVK9BbLH0warYc4OXARGa.
- Candidate deployment: dpl_Ca4CpEhH289K3fUTt7RTo7ZNTrWK, READY.
- Preview: https://nivxray-edr-production-426dkn7j2-jpreddy017.vercel.app.
- Verified production domain: edr.nivxforge.com.
- Current production deployment: dpl_GnXW5Y5qwss3858hd1jJdrabxXME.
- Current production commit: 35d47cc96352f492bd4c603a2f2f1b65afb4119f.
- Current production URL: nivxray-edr-production-7qp4ja2zg-jpreddy017.vercel.app.
- Vercel lists current production as a rollback candidate. No rollback drill performed.

## Additional evidence
Using connected Vercel access without weakening deployment protection:
- Candidate /edr returns HTTP 200 application HTML.
- /edr/computers, /edr/device-trajectory, /edr/computers/release-check/trajectory,
  /edr/events and /edr/audit return HTTP 200 application HTML.
- Main JavaScript asset index-C94kzseZ.js returns HTTP 200.
- Its discovered NivX backend origin is https://nivxray.nivxforge.com;
  no preview/emergent origin was found in that main asset.
- DeviceTrajectoryEntry-DzZr7u3y.js, EdrDevicePage-CCP8B3r2.js and
  EdrTrajectoryResolver-H4aZy4YL.js return HTTP 200 JavaScript.
- Device workspace chunk imports the shared DeviceTrajectoryEntry chunk.
- GitHub check-runs reports only Vercel Preview Comments success; that check
  means no unresolved preview comments, NOT independent functional approval.

HTTP SPA shell delivery is not proof of authenticated route execution or correct
tenant data. No live response action, policy/exclusion mutation, enrollment,
credential change, deployment, domain change or branch promotion was performed.

## Release blockers and precise handoff
1. Independent G3 review of the exact candidate. The author cannot certify
   their own independence. Review all changes versus production baseline,
   including trajectory identity/context handling and legacy artifact writes.
2. Authenticated preview verification with authorized representative data:
   correct tab versus selected-computer trajectory, device switching, conflicting
   query identity, legacy toggle, all sidebar destinations, denied/empty/error
   states and absence of console/network regressions.
3. Production configuration comparison: confirm API origin, product scope,
   renderer flags and build settings; preview settings are not assumed equivalent.
4. Backend repair deployment ownership/access: Vercel frontend promotion does
   not deploy backend/v2/decoded_artifacts/__init__.py to the shared API host.
   Establish the actual backend deployment and frozen baseline, independently
   review and test it before release. Do not retarget the shared backend.
5. Independent-copy runtime remains lab-only and is excluded from replacement
   of production. Login/session, end-to-end endpoint flows, migration and other
   documented separation gates are unfinished.

After passing gates, promote the verified frontend artifact (or a production-
configured build verified equivalently), verify actual domain/deployment binding
and authenticated smoke behavior, and retain the recorded previous production
artifact for rollback. Backend promotion is a separate controlled operation.
Do not infer G3/G4 success from READY or HTTP 200.
