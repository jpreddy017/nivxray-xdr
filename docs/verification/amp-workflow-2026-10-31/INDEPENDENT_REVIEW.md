# Exact-candidate review and release status — 2026-10-31

Candidate: 96ff8c1bda8819766982b38c1fdabaaa10c44111
Tree: 735b37177332a8eae14d8fbdb2a2ab5db70fb96f
Baseline production: 35d47cc96352f492bd4c603a2f2f1b65afb4119f
Independent copy: cc5e8d565165809f15f18693b80e28c7d0a3fed6

## Independent bounded G3
Separate read-only reviewer declared no authorship or modifications and verified six changed production code blobs. Original e84090b FAILED due to out-of-order saved-view requests and missing URLSearchParams in its VM harness. Both corrected in successor.
Reviewer verified successor Events blob c29ba48954c91e58a66ee0d0c7b49a53dc655e36 and test blob d3235319588f9755f069f57a70c0b8185a413a97.
Verdict: PASS for bounded code review, not full product release.
Independent tests: Events regression; trajectory scope/entry/reset/shell; 17 route resolution/unavailability; 12 enabled clicks/five disabled; nine artifact acknowledgement tests. Separate stateful-router reproduction confirmed B remains selected after late A.

## Build / authentication
Vercel candidate dpl_FovLRkMeeRAp4ABDMdzjVLhGkVLG READY, preview target, exact successor SHA.
Production renderer flag VITE_E3_DT_V3=1 verified. Added branch-only preview override =1 before this build.
Authenticated browser candidate verification blocked: secure sign-in submitted and application displayed Invalid credentials. Existing production sign-in does not transfer to preview origin. No password, token or session was extracted or copied.
Production remains unchanged; no promotion or backend deployment.

## Remaining backend and VM risks
Unchanged backend pipeline.py:181–197 still catches fresh artifact persistence errors. Frontend rollout cannot deploy this backend repair.
Separate read-only VM investigation found CPU-based identity collision risk: EndpointIdentity.mint prioritizes processor_id and ignores differing MachineGuid/hostname; Windows supplies hashed wmic CPU ProcessorId; enrollment upserts same tenant/endpoint, replacing hostname and credential. Exact algorithm reproduced same ID for distinct machine attributes sharing CPU signature.
This is NOT proof of the missing VM cause. Guest non-secret status (enrolled, endpoint_id, tenant_id, sensor version, credential-present boolean), guest hostname, backend origin and enrollment outcome are needed.
Inventory lists authorized enrolled endpoints without time/status suppression; 500-row cap cannot explain a two-row estate.
Do not change identity precedence without versioning/collision handling and migration design.
