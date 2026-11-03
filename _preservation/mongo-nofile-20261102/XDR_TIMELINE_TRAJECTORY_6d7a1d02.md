# Timeline → Open Device Trajectory · acceptance evidence

Review stack (each commit stands on the one above it):

    e934e8c7  Open the EDR trajectory in a new tab, keeping the XDR incident open
    57051d74  State an instant as an instant, and use a link range whole or not at all
    7e40b040  Make the Timeline trajectory button open THIS incident's endpoint
    6d7a1d02  Name the path the Timeline control actually opens   ← served preview

Branch: `fix/xdr-timeline-trajectory-context` (local). Production promotion remains on hold.

## The defect this closes

The orange **Open Device Trajectory** button on the incident Timeline tab
(`ActivityTab.jsx`) was the last trajectory control that had never been brought
onto the cross-product pivot contract. It ran:

    window.open(productHref("edr", "/edr/trajectory"), "_blank", "noopener,noreferrer")

— a context-free canvas: no endpoint, no customer, no incident reference, no
time range, offered on every incident including records that name no endpoint.
The header link and this button could therefore disagree about the whole
investigation.

It now renders the same `OpenInEdr` link as the header. The endpoint is resolved
once by `incidentEndpointId()`, so the two controls can never name different
devices. The Endpoints domain page (`XdrIncidentDomainPage.jsx`), which
navigated **in-tab** to the same context-free path, was corrected the same way.

## Case 1 · endpoint present, authorized, with visible events

Incident `inc_664ddf5212194bfcb94a` · `INC000003569` · customer `default`
· device `ep_2d57cbe6f80152062109` (`agent-env-630704a1-621f-478b-9b86-a321772d01bf`)
· range `2026-10-17T23:34:25.827681+00:00` → `2026-10-18T05:07:43.292002+00:00`

    https://greeting-app-5782.preview.emergentagent.com/xdr/incidents/inc_664ddf5212194bfcb94a?tab=timeline

Observed on the shared preview:

| check | result |
|---|---|
| control is a real link | `A` · `target="_blank"` · `rel="noopener noreferrer"` |
| href | `/edr/device-trajectory?device=ep_2d57cbe6f80152062109&incident_id=inc_664ddf5212194bfcb94a&time_start=2026-10-17T23%3A34%3A25.827681%2B00%3A00&time_end=2026-10-18T05%3A07%3A43.292002%2B00%3A00&tenant=default` |
| tabs | 1 → 2 |
| tab 1 after the click | still `/xdr/incidents/inc_664ddf5212194bfcb94a?tab=timeline`, header still *Execution from a world-writable directory — ep_2d57cbe6f80152062109* |
| tab 2 header | `agent-env-630704a1-621f-478b-9b86-a321772d01bf` |
| tab 2 context banner | OPENED FROM INCIDENT **INC000003569** · CUSTOMER **default** · VERDICT suspicious · DETECTIONS 62 · EDR-LNX-002 · DEVICE ep_2d57cbe6f80152062109 · *Return to NivXRay XDR incident* |
| tab 2 window | **2026-10-17 23:34 – 2026-10-18 05:07 UTC** — the incident's own range, not "last 24h" |
| tab 2 events | visible: `dash [ELF]`, `cron`, `find`, `tar` lanes with markers; Activity panel `dash · python3.11 · git · 10.22.5.137` |
| access | no "Access denied", no "Select a computer", no "No activity was recorded" |

Backend cross-check for the same window (`X-Tenant-Id: default`):

    GET /api/edr/endpoints/ep_2d57cbe6f80152062109/trajectory
        ?time_start=2026-10-17T23:34:25.827681+00:00
        &time_end=2026-10-18T05:07:43.292002+00:00
    → returned 6 · matched_in_time_range 7559 · observations_all_time 85791

Screenshot: `screenshots/timeline-edr-events-6d7a1d02.png` (EDR tab, events visible)

## Case 2 · no endpoint on the record

Incident `inc_46286baa72db4b1583c5` · customer `p0f-c00c9ffe`

    https://greeting-app-5782.preview.emergentagent.com/xdr/incidents/inc_46286baa72db4b1583c5?tab=timeline

| check | result |
|---|---|
| link present | **0** |
| refusal present | 1 · `data-reason="NO_ENDPOINT"` |
| text | ◇ no endpoint on this record |
| title | "This record names no endpoint, so there is nothing to open." |
| clicking it | tabs 1 → 1, URL unchanged |

Screenshot: captured in the browser run, not written to this folder — only the
Case 1 EDR screenshot was retained on disk. The assertions above are the
run's own output, not a reading of an image.

## Case 3 · ambiguity — still test-verified only

No incident in this environment carries two conflicting endpoint identities, so
the ambiguity path has never been exercised on real data. `resolveEndpoint()`
returns `AMBIGUOUS_ENDPOINT` with both candidates named, the link is withheld and
the UI reads "more than one endpoint on this record"; that is covered by
`openInEdr.test.jsx` only.

Note on `incidentEndpointId()`: it is **precedence**, not arbitration —
`endpoint_id → device_ref → device_iid → hostname → ssot host`. An authoritative
endpoint id outranks a projected hostname for the same machine. It does not
compare rival devices, so it cannot mask the ambiguity case above.

## Builds

| | value |
|---|---|
| served preview | `https://greeting-app-5782.preview.emergentagent.com` |
| source sha | `6d7a1d027b089a732d07a95d4e72cf25f484d4a8` |
| branch | `fix/xdr-timeline-trajectory-context` |
| product scope | `""` — combined, read back out of the compiled index chunk |
| build command | `VITE_E3_DT_V3=1 npx vite build` (`scripts/vercel-build.sh` refuses unscoped builds) |
| api origin | `https://greeting-app-5782.preview.emergentagent.com` (`REACT_APP_NIVXRAY_API_URL`) |
| EDR destination in this XDR build | **none configured** — `REACT_APP_EDR_URL` is empty, so links are same-origin `/edr/...` |
| tests | 27 files · **386 passed** |
| eligible for production | **no** (`not_eligible_for_production: true`) |

The preview must stay combined for `/` + `/xdr` + `/edr` to all answer; a
scoped EDR artifact was tested separately on `:3101`/`:3103` for `ec498a61`.

## Still open

- No GitHub branch, commit or PR exists for any of these SHAs. Export via
  **Save to Github** to `fix/xdr-timeline-trajectory-context`; Support could not
  confirm whether Emergent preserves workspace SHAs on export, so compare the
  exported code against `review-stack-4-commits.patch` rather than trusting SHAs.
- Vercel `VITE_E3_DT_V3=1` on the EDR project remains unverified.
- Authenticated production-backend compatibility remains blocked.
