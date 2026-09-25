# NivXForge EDR — next wave · Cisco AMP / Secure Endpoint parity (owner directive, 2026-06)

Owner instruction (intent, verbatim scope): *same working operations,
navigation and UI as Cisco Secure Endpoint (AMP) — colour, tone, SPA, pixel,
interaction, navigation, depth, icons, layout — zero compromise.*

## BLOCKED ON OWNER INPUT — two items, recorded honestly
1. **Reference material.** There is no Cisco console, tenant, screenshot or
   style guide in this workspace, and pixel parity cannot be invented from
   memory. The wave needs owner-attached captures (light AND dark) of:
   Computers list + filter/bulk bar · Computer details (every accordion) ·
   Device Trajectory · Events · Detections views · Outbreak Control ·
   Policies · Download Connector · Accounts / Audit Log.
2. **IP boundary.** Cisco's CSS, fonts, icon files, images and markup are
   proprietary and will not be copied into this repository. Deliverable at
   "same to same" level: identical information architecture, navigation
   model, workflow sequence, layout geometry, density, tone, colour
   semantics, interaction behaviour and iconography, built as original
   NivXForge assets. Owner confirmation requested before the wave starts.

## P0 (once references land)
- **Fleet command centre** — Computers gains Risk · Sensor Health · User ·
  IP · tags, saved views, column chooser, export, and bulk operations
  (assign group, apply policy, isolate, update sensor, tag).
- **Device workspace header** — operational header (OS · sensor · group ·
  policy · risk · isolation · last seen) + action bar (Isolate · Live
  Response · Hunt · Collect Evidence · Scan).
- **Trajectory depth** — ancestry-rendered chronology (parent → process →
  child → command → decoded → file → registry → DNS → network → detection →
  response) with a right-hand investigation drawer per object.
- **Command Intelligence → command investigation** — raw → decoded →
  interpretation → observed effects → detection → ATT&CK → evidence chain,
  plus cross-fleet "same command" pivots.
- **Detections triage queue** — severity/technique/computer/user columns,
  saved views, side-drawer triage without losing position, link-to-incident.
- **Events** — endpoint event workbench over raw + canonical evidence
  (today: NOT_IMPLEMENTED, stated honestly in the console).

## P1
- Hunt (historical evidence search) vs Live Query (current endpoint state)
  as two deliberately distinct planes.
- Files · Network · Forensics device lenses, each gated on the sensor
  actually collecting that telemetry class.
- Policies (authoring + assignment) and EDR-scoped Audit.
- Sensor/fleet health operations (upgrade state, blind endpoints, queue
  depth) as a first-class surface.

## P2
- Exposure: vulnerabilities, software inventory, missing patches, risky
  applications, misconfigurations, internet exposure, security controls.
- Light/dark parity audit + contrast gate across every EDR surface.

## Standing gates (carried)
- No fabricated data: absent evidence renders NOT OBSERVED / NOT AVAILABLE /
  NOT_IMPLEMENTED with the reason.
- CONNECTED requires authenticated telemetry inside the sensor's declared
  cadence; enrolment/heartbeat/install never qualify.
- No N+1 queries on fleet surfaces.
- A frontend wave is not PASS until the real rendered SPA has been visually
  inspected.
- Response actions dispatched BY the platform are never presented as
  observed endpoint execution.
