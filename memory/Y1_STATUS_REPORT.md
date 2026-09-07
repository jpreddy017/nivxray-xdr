# Y1 · STATUS REPORT — product separation + rail information architecture

Scope executed: **only the surfaces the supplied captures authorise**
(decision C). Every unseen surface stays `REFERENCE_CAPTURE_REQUIRED` and
is **not** visually accepted. Overall "Cisco XDR 100 % observable parity"
is **NOT** declared.

## A · Delivered

| Item | What changed | Status |
|---|---|---|
| **D-1 · product separation** | `NivXForgeConsole` no longer renders `XdrShell`. NivXForge EDR now has its own product console (`data-product="NIVXFORGE_EDR"`): own topbar with product mark + tagline, server-resolved customer pill, light/dark toggle, user, sign-out, and an explicit **`Investigate in NivXRay XDR`** product pivot | `REAL_RUNTIME_VERIFIED` |
| **D-2 · permanent deep-link route** | `/xdr/edr/device-trajectory` → `/edr/device-trajectory` via `EdrTrajectoryRedirect`, carrying the **entire** query string and hash. Verified live: `?device&raw_event_id&incident_id` all survived and the handoff still resolved `evt_0b5121e3924461c7#7dd36299ea` with Activity Details and rule attribution intact | `REAL_RUNTIME_VERIFIED` |
| **D-3 · two logins, one auth engine** | `/login` → NivXRay XDR · `/edr/login` → NivXForge EDR. Same `POST /api/auth/login`; each screen carries unmistakable product identity; a product login never lands the analyst in the other product (`returnTo` is honoured only when it belongs to that product) | `REAL_RUNTIME_VERIFIED` |
| **V-1/V-2/V-14 · rail correction** | The 45-item / 8-uppercase-group rail is replaced by the observed structure: **8 primary destinations with indented, expandable children** — `Control Center · Incidents · Investigate · Intelligence · Automate · Assets · Client Management · Administration`. Children are **reused by key** from the existing definitions: no route, label, icon or capability state was retyped or invented | `REAL_RUNTIME_VERIFIED` |
| **D-4 (partial)** | The cross-product `Computers → /xdr/endpoints` row added earlier was **removed** from the EDR rail rather than shipping a nav item that leaves the product. The real move is owned by Y4 | `NOT_IMPLEMENTED` (deferred, by design) |
| Search hrefs | now emit the canonical `/edr/device-trajectory` | `REAL_RUNTIME_VERIFIED` |

## B · Defects I introduced and fixed inside this pass
1. `expanded` state declared inside `useActiveKey()` instead of the
   component → **blank XDR console**. Caught by console log
   (`expanded is not defined`), fixed, re-verified.
2. `/edr/login` landed on `/xdr/incidents` because `returnTo` defaulted to
   `/xdr`. Fixed with a per-product destination guard.

## C · Regression (gate for this phase)
`x1_x3_xdr_integration_proof` **17/17** · `p0_detection_attribution_proof`
**12/12** · `p0_f13_5_detection_handoff_proof` **25/25** · `tests/edr`
**330 passed** (same 3 pre-existing, unrelated
`test_p0_f4_endpoint_process_tree.py` failures, reproduced on a clean
tree). Live UI checks: XDR login identity · EDR login identity · rail
primaries = 8 · child expand · EDR product topbar · EDR→XDR pivot ·
redirect fidelity · handoff + detection attribution unchanged.

## D · NOT delivered in Y1 (explicit)
`V-3` two-way theme parity beyond the shell toggle · `V-4` notification
bell / org line · `V-5`+`N-5` ribbon · `V-6…V-8` incident workspace ·
`V-9…V-10` Devices · `V-11` Investigate composition · `V-13` `—` empty
convention · `V-15…V-19` incidents list · `V-20`+`I-12`+`I-13` Control
Center tiles · `I-2`…`I-9` graph/table interactions · `N-1` back links ·
`N-4` Client Management children (currently mapped to existing admin
sections) — all `NOT_IMPLEMENTED` or `IMPLEMENTED_NOT_RUNTIME_VERIFIED`
per the Y0 matrices.

## E · Blocked, named
- `G-16 / FLOW-5 · REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED` — no
  DNS/network/email/identity collector exists; cross-source correlation
  will not be simulated.
- `V-10 / V-21` — `Vulnerabilities`, `Cisco Security Risk Score`,
  `Managed`, multi-vendor `Sources` and non-endpoint dashboard tiles have
  no data source. Layout parity is possible; content parity is `BLOCKED`
  and will render capability-honest states.
- Asset-value contribution to priority (`S-7`) — will read
  **"Not Available — no authoritative asset criticality source
  configured"** (decision 3A).

## F · Still `REFERENCE_CAPTURE_REQUIRED` (not visually accepted)
Detection findings · Evidence · Worklog · Report · Intelligence pages ·
Client Management · Administration · expanded ribbon / Casebook ·
observable pivot menu · standalone Global Search results.
