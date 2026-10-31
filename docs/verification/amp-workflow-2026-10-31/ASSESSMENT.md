# AMP workflow comparison and bounded implementation

Research date: 2026-10-31. This is a partial comparison, not a certification of Cisco parity.

## Primary references
- Cisco Secure Endpoint Best Practices Guide (updated 2024-08-26): https://www.cisco.com/c/en/us/products/collateral/security/fireamp-endpoints/secure-endpoint-og.html
- Cisco Identify Detection Engine, console v5.4.2025030619 (2025-03-18): https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/222850-identify-detection-engine-in-secure-endp.html
- Secure Endpoint User Guide: https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf

Cisco documents endpoint-specific trajectory, event-origin selection, graph-to-details interaction, and combined filtering/search. These are behavioral comparison targets. Different published versions must not be treated as one pixel-identical reference.

## Comparison and implementation sequence
| Priority | Requirement | Evidence / status |
|---|---|---|
| 1 | Same trajectory from computer and main entry | Prior candidate unifies renderer and explicit endpoint scope; authenticated candidate verification outstanding |
| 1 | Correct evidence after filter changes | Events loader lacked response ordering; fixed in this checkpoint |
| 1 | Reopen saved investigation filters | Initial saved-view state prevented URL resolution; fixed in this checkpoint |
| 1 | Honest empty/loading/error states | Removed unsupported never-reported/enrollment claims derived from window facets |
| 2 | Event opens exact selected trajectory activity | Cisco documented; NivX raw-event-to-canonical-event mapping must be traced before adding links |
| 2 | Graph selection and activity detail synchronization | Main trajectory remains user-approved reference; populated live comparison still required |
| 3 | Filter categories, search, timeline navigator, IOC highlighting | Compare cloud-guide reference and approved implementation; do not add fabricated evidence or status |
| 3 | Visual spacing, icons and interaction parity | Requires screenshot-level comparison; not established by this text research |

## Changes
Events request generation rejects obsolete success, error, cursor and loading updates. New replacement queries clear obsolete rows and selected evidence. Unmount/effect cleanup invalidates outstanding work. Saved URL starts unresolved and loads server-authorized view filters. Empty-state messaging waits for successful data and never infers historical reporting or enrollment from an empty window.

## Verification
Actual EdrEventsPage rendered with React test renderer and controlled deferred API promises. PASS: saved URL resolves; endpoint and time filters apply; old response cannot replace newer rows or cursor; loading and failure do not claim no events. Reintroducing original saved-link initialization makes the test fail (0 versus 1 view fetch).

This is component-level verification with doubles, not real authenticated API or browser certification. Rapid saved-view selection ordering, saved-view URL back/forward semantics and audit-page ordering remain separate checks.

## Production and VM
Observed production customer Internal Validation lists two computers, KUSHU and DESKTOP-A9HGFJJ. Missing VM is unresolved. Historical Hyper-V VM name NivX-Win11-G4-01 is a lead, not proof of guest hostname or enrollment. Earlier VM connectivity/enrollment failures must be checked against current endpoint/service evidence. Do not synthesize an inventory row.

No production promotion in this checkpoint. G3 independent review, matching preview configuration, authenticated candidate tests and applicable G0-G6 gates remain required. Frontend promotion alone does not deploy the backend repairs.

## Independent-review correction
The first candidate e84090b failed independent review: saved-view requests could complete out of order, and the test VM omitted URLSearchParams, masking a caught error. The successor invalidates saved-view requests on newer selection, clear and unmount. The harness now supplies URLSearchParams and asserts URL, active view, absence of refusal, B-before-A completion, and clear while C is pending. All four frontend suites and the reviewer-run nine backend acknowledgement checks pass. Independent exact-SHA successor verification remains required.

Production VITE_E3_DT_V3=1 was verified through the single-variable API. A branch-scoped preview flag now matches it; e84090b was rebuilt successfully. The candidate reaches application login; production login is not shared across origins. Authenticated candidate verification remains blocked on secure sign-in.
