# P0-F.13.2 / 2A / 2B — Device Trajectory architecture, visual and shell audit

Machine-readable detail lives in:

* `test_reports/p0_f13_2_device_trajectory_audit.json`
* `test_reports/p0_f13_2a_dual_trajectory_visual_audit.json`
* `test_reports/p0_f13_2b_global_shell_navigation_audit.json`
* `test_reports/iteration_102.json` (verification run: backend 6/6,
  frontend 13/13, 11/11 EDR routes)

Probe instrument: `scripts/p0_f13_2_dual_trajectory_probe.py` (read-only).

## 1. The two nav entries were never two engines

```
                         edr_raw_events
                               │
                      canonical evidence
                   (v2_shadow_observations)
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
   /api/edr/device-trajectory      /api/edr/endpoints/{id}/trajectory
   XDR case/entity context         nivxray::edr_plane::trajectory_window
   58 lifelines grouped by         491 lanes keyed on process_iid
   process NAME, 5 swim-lanes      ENDPOINT_WIDE_INVARIANT_TO_VIEWPORT
                 │                           │
    XdrEntity360Page (Entity 360)   EdrDeviceTrajectoryPage (AMP)
                                          ★ CANONICAL
```

`ARCHITECTURAL_DUPLICATION = NO` at the engine level — one substrate, two
read projections, no second telemetry / evidence / trajectory /
detection store. It was `YES` at the **label** level: two EDR sidebar
entries both called Device Trajectory. Resolved — the operational EDR
sub-nav now has exactly one `Device Trajectory` → the AMP renderer, and
the case-context projection stays where it belongs, on Entity 360.

## 2. Three "defects" from the screenshots were not renderer defects

| Observation | Verdict | Evidence |
|---|---|---|
| dotted lifelines | DATASET / SENSOR | 446 of 446 process lanes are `END_NOT_OBSERVED` — no `process_exit` is collected |
| generic square glyphs | DATASET | this host's whole vocabulary is `network_connect` 3731, `process_create` 262, `detection` 4, `file_write` 3 |
| Files & Network missing | OBSERVED | present at rows 453-488: 41 network + 3 file lanes with real peers |

Making the lifelines solid would assert a process lifetime the sensor
never observed. That is the one thing this product must never do.

## 3. Genuine gaps — proven by DOM assertion, then fixed

* **Main-canvas visibility hatch** — was `0` pattern fills inside
  `amp-canvas`. Now `amp-canvas-hatch-before/after` hatch the part of the
  window that lies outside the endpoint's observed evidence range and
  label it `no sensor coverage`. Note the semantics: the AMP plot area
  *is* the selected window, so "outside the window" cannot exist inside
  it; what can be stated honestly is "outside what was ever observed".
* **Selected-event temporal guide** — selection drew only a glyph ring.
  Now `amp-temporal-guide` drops a dashed guide with an `hh:mm:ss` chip
  at the observation's exact timestamp.
* **No global shell** — the AMP route rendered an EDR-only application:
  `xdr-shell 0`, `xdr-topbar-search 0`, no Administration. Now the EDR
  plane renders inside `XdrShell` and owns only its endpoint sub-nav.
* **The customer name was a lie** — the pill printed
  `user.tenant || user.email`. It now shows the server-resolved customer
  with a dropdown of the authorised customers, in the Cisco position
  (icon · customer over principal · chevron). The initials chip is gone;
  Sign out moved into that dropdown. The decorative notification bell was
  removed rather than left ringing at nothing; Help opens the real
  Knowledge Base.

## 4. Entry context — tenant context ≠ investigation context

`GET /api/edr/context?endpoint_id=&incident_id=` ·
`nivxray::edr_plane::entry_context`

```
DIRECT_EDR                         XDR_PIVOT
  principal → authorised tenants     server reads the incident,
  active_customer.basis =            checks resolve_tenant_scope,
    SINGLE_AUTHORIZED_TENANT |       INHERITS its tenant
    CROSS_TENANT_ROLE_NO_SINGLE_…    basis = INHERITED_FROM_INCIDENT
  investigation = null               investigation = {number, verdict,
                                       detections, rule_ids,
                                       endpoint_reference}
```

* The browser may **name** an incident and an endpoint. It may never
  assert a tenant: `?tenant=EVIL` is ignored and never echoed.
* `endpoint_reference.state` comes from
  `workspace_cases.endpoint_campaign.hostname / endpoint_id` — never a
  name or PID guess. States include `REFERENCES_THIS_ENDPOINT` and
  `ENDPOINT_NOT_REFERENCED_BY_INCIDENT`, and the banner says so.
* Cross-tenant attempts fail closed: a `nivx-live` analyst asking for a
  `default` incident gets `INCIDENT_TENANT_OUT_OF_SCOPE`.
* While an investigation context is held, the response states that
  switching customer would create `tenant B + incident from tenant A`
  and that the context must be left first.

## 5. Disclosed limitation (not a defect, not hidden)

`device_identity.list_devices` returns `[]` for any principal without a
cross-tenant role, because `v2_shadow_observations` carries no
`tenant_id` and no enrolment-time customer attribution exists. So a
customer-scoped login sees an empty endpoint inventory. The Device
Trajectory now says exactly that instead of rendering a silent void —
and shows nothing rather than another customer's endpoints.

**Next real work for per-customer EDR:** attribute endpoints to a
customer at enrolment (`edr_enrollment`) and carry that attribution into
the observation envelope, then relax `list_devices` to that attribution.
