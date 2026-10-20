# Read-only production count inventory

DB: greeting-app-5782-test_database (run 4067c54d-e252-4243-a214-27a9f17715bc)
TENANT: ten_e759b7288598bd882e3dcac49d
Mode: READ-ONLY (count / find / distinct only). No writes, no deletes, no deploy, no secret change.
collStats/dbStats NOT available via tooling -> byte sizes skipped; counts are complete.

## EP (edr_endpoints endpoint_id list)
- ep_1989031c8c1d0085812f  host=DESKTOP-A9HGFJJ  state=REVOKED   event_count=157226
- ep_a67be48d5b4e01d4d9e8  host=KUSHU            state=ENROLLED  event_count=34488

## A) count {tenant_id: TENANT}
edr_raw_events=1877149
edr_processing_queue=1718750
edr_rejected_telemetry=25750
edr_acquisition_gaps=2786
edr_acquisition_integrity=3
edr_delivery_counters=6
edr_findings=0
edr_finding_evaluations=301539
edr_compromise_events=absent
edr_endpoint_address_observations=29
edr_response_commands=0
edr_policy_endpoint_state=2
edr_endpoint_exclusion_enforcement=0
edr_endpoints=2
edr_agent_credentials=2
edr_agent_sessions=0
edr_enrollment_tokens=0
edr_policies=1
edr_groups=1
edr_policy_versions=1
edr_exclusions=0
edr_exclusion_sets=0
edr_isolation_policy=absent
edr_tenant_boundary=absent
edr_connector_deployments=absent
edr_saved_views=0
edr_enrollment_audit=14
edr_policy_audit=4426

## C) xdr_canonical_evidence
C1 {tenant}=149166
C2 {tenant, provenance.source_kind=sensor}=149161
C3 {tenant, EP via collector_id/additional_fields.endpoint_id/host.host_id}=149161
C4 {} all tenants=149166
Note: C1==C4 -> whole collection is this tenant's; 5 docs not EP-attributed.

## D) v2_shadow_observations
D1 {tenant}=149178
D2 {tenant, collector_id/connector_id in EP OR event.raw.raw_evidence_ref.collection=edr_raw_events}=149174
D3 {} all tenants=149187
Note: D3-D1=9 docs belong to OTHER tenants (out of scope); 4 tenant docs not matched by D2 refs.

## E) workspace_cases
E1 {tenant, doc_type=xdr_incident}=0
E2 {tenant, xdr_incident, endpoint_campaign.endpoint_id in EP}=0
E3 find (same)=0 rows -> INC=[] (empty)
E4 {} all tenants=48

## F) dependents (incident_id in INC)
INC empty -> all of xdr_investigation_activity, xdr_investigations, xdr_investigation_findings,
xdr_iue_understanding, xdr_framework_mappings, xdr_response_timeline, xdr_intelligence_overlays,
xdr_intelligence_overlay_audit = 0 by construction; paired cross-tenant anomaly sub-counts = 0/not computable.
Not executed (a $in:[] match is trivially empty). No incident ids to join on -> no isolation anomaly evaluable.

## G) distinct edr_raw_events.endpoint_ref {tenant}
["ep_1989031c8c1d0085812f","ep_a67be48d5b4e01d4d9e8"] (2) -> telemetry attributed only to EP.

## Owner flags before approving scope
- E1=0: no xdr_incident docs exist for this tenant; entire E/F incident branch is empty.
- v2_shadow_observations contains 9 docs from OTHER tenants (D3-D1) -> must NOT be touched.
- Absent collections: edr_compromise_events, edr_isolation_policy, edr_tenant_boundary, edr_connector_deployments.
