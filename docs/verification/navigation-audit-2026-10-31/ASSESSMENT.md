# Current EDR tab and navigation assessment — 31 October 2026

Scope: source/component evaluation of all 17 sidebar entries and seven computer
lenses at current-product repair parent d0613a642cae3668a824582774b4d624cfdd33e7.
Independent copy parent: 55368425f07fa21c83ebcd9684c1ce0144908234.
This is not a claim that the deployed revision or every tab works end to end.
No production writes, endpoint actions, policy changes or deployments performed.

## Tab inventory and functional requirements

| Tab | Destination | Usage and dependencies | Assessment / remaining validation |
|---|---|---|---|
| Dashboard | /edr | Capability registry, context and telemetry freshness; capability-gated investigation cards | Registered; cards depend on server grades; live grade/available-route consistency unverified |
| Computers | /edr/computers | Authorized fleet, status, search, time window, context pane; onboarding/computers API | Registered; device, trajectory, commands and process-tree links present; live freshness/count accuracy unverified |
| Detections | /edr/detections | Incident or endpoint detection projections; event pivots to trajectory | Registered; endpoint_id/device accepted; empty and populated contexts require live verification |
| Events | /edr/events | Raw events, filters, paging, detail, saved views | Registered; managementApi calls exist; filter/request race and saved-view transitions require regression coverage |
| Device Trajectory | /edr/device-trajectory | Shared feature selector, V3/legacy canvas and endpoint evidence | Correct reference retained; computer path uses same selector after prior repair; live flags/data still unverified |
| Process Tree | /edr/process-tree | Endpoint or incident ancestry; authorized device picker; graph/list, time window, trajectory/command pivots | Registered; device and hours query supported; full populated graph interactions require browser/API tests |
| Campaign Story | /edr/campaign-story | Incident-scoped campaign projection and investigation pivots | Registered but bare sidebar entry requires incident context; currently instructs user to open from incident or provide ID; launcher usability gap remains |
| Hunt | unavailable; direct /edr/hunting reserved | Future endpoint telemetry hunting | Disabled with reason; no hunting functionality claimed |
| Files | unavailable; direct /edr/files reserved | Future endpoint file evidence | Disabled; dashboard explicitly distinguishes XDR-hosted capability from unavailable EDR surface |
| Network | unavailable; direct /edr/network reserved | Future endpoint network/DNS evidence | Disabled; direct route is a reserved page |
| Forensics | unavailable; direct /edr/forensics reserved | Future evidence collection with provenance | Disabled; no collection capability claimed |
| Live Query | unavailable; direct /edr/live-query reserved | Future approved endpoint execution | Disabled; no execution capability claimed |
| Response | /edr/response | Endpoint action lifecycle; catalogue/health/approval APIs still use /xdr/respond | Registered native page, not the similarly named unused reserved export; shared authority dependency remains; no real action executed |
| Policies | /edr/policies | Create/version/assign policies, groups, deployment/audit projections | Registered; server enforcement and actual sensor delivery/apply/verification require lab tests |
| Exclusions | /edr/exclusions | Sets, entries, approvals/revocation and enforcement proof | Registered; permission/approval/enforcement correctness requires backend and endpoint tests |
| Downloads | /edr/management/downloads | Release catalogue, artifacts, deployment groups, onboarding links | Registered; package availability/signatures and install/enrollment require lab verification |
| Audit | /edr/audit | Existing EDR lifecycle audit aggregation, category/actor/time/search/paging | Registered; this is not the new independent edr_identity audit UI; request ordering requires regression coverage |

All 12 enabled sidebar targets exist in App.jsx. Five unavailable entries prevent
navigation and state why. The actual sidebar component was clicked in a React
test for every entry; this checks dispatch, not backend behavior.

## Selected-computer lenses

| Lens | Usage/status |
|---|---|
| Overview | Device identity, health, telemetry, detection summary and pivots; implemented source |
| Trajectory | Same renderer selector as top-level tab; endpoint prop authoritative over conflicting device query; component-tested |
| Command Intelligence | Observed command evidence and decoded reports; independent evidence API is not yet wired to this legacy consumer |
| Files | Explicit not-implemented explanation |
| Network | Explicit not-implemented explanation |
| Response | Explicit not-implemented explanation; directs user conceptually to product Response |
| Forensics | Explicit not-implemented explanation |

Unknown /edr/computers/:endpointId/:tab previously rendered no lens. This repair
adds an explicit unavailable-view message while retaining the device tabs.

## Confirmed navigation repairs

Trajectory resolver previously selected first matching hostname/incident, fell
back to an incident after a supplied device failed, discarded event/time/tenant
and other query context, and could render a previous resolved state after inputs
changed. It now requires one unambiguous match, does not fall back from an
explicit device, retains navigation context and hash, removes conflicting identity
aliases and guards rendering with the request identity. IID inputs only match
IIDs; generic device inputs also accept endpoint_id. Destination APIs remain the
authority: these browser hints never grant tenant or endpoint access.

## Coupling and remaining gaps

- Current shell relies on shared authentication, tenant authority, product-origin
  routing, XDR context/error components and session-context API. Copying these
  files does not establish independent runtime wiring.
- Command Intelligence retains legacy decoded-artifact dependencies; Response
  retains shared approval authority. Preserve these contracts until separately
  adapted and verified.
- Campaign Story without incident context is an onboarding dead end rather than
  a wrong route. A supported incident selector requires a scoped data contract;
  no fabricated selector or cross-product redirect was introduced.
- Events/Audit loaders lack request-order guards in reviewed source. Overlapping
  filter/page requests need reproduced race tests and a separate repair.
- Console navigation carries only selected incident context keys; tab-specific
  endpoint_id/time/filter persistence is inconsistent and needs an explicit
  per-surface navigation contract, not indiscriminate copying of every filter.
- Full click paths, keyboard/accessibility, loading/error states, real permissions,
  customer switching, populated/empty data, paging, download integrity, state
  changes and backend/agent effects remain unverified live.

## Evidence and release status

Source inventory JSON records paths/blobs, imports and API/navigation references.
Navigation tests cover all sidebar route registrations, disabled reasons, sidebar
click dispatch, resolver ambiguity/refusal/context retention and existing
trajectory component parity plus the new unknown-device-tab message. Syntax
transforms cover the materialized source. No full frontend build or whole-product
test certification is claimed. Author validation is not independent G3 review.
Changes are saved on repair/engineering branches only; production/main/preservation
remain unchanged. Further functional testing is required before release.
