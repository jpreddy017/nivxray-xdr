# CISCO AMP / SECURE ENDPOINT DEVICE TRAJECTORY — ACTUAL ENGINEERING

Internet research, 2026-09-29. Every claim below is sourced. Anything not
sourced is marked NOT VERIFIED and was NOT implemented.

## SOURCES

| # | Source | Weight |
|---|---|---|
| S1 | Secure Endpoint User Guide pp.401-407 (owner-supplied PDF) | DOCUMENTED |
| S2 | Cisco TAC doc 118711 "File Types That are Scanned by Cisco Secure Endpoint on Public Cloud" (rev 2.0, 2021-09-08; updated 2023-06-28) | DOCUMENTED |
| S3 | Cisco Secure Endpoint Operations/Best-Practices Guide (cisco.com product collateral) | DOCUMENTED |
| S4 | Cisco Live BRKSEC-2072 (2023), TACSEC-2012 (2024) | DOCUMENTED |
| S5 | Secure Endpoint API `GET /v1/computers/{connector_guid}/trajectory` | DOCUMENTED |
| S6 | UW-Madison KB 90059 — analyst walkthrough with console screenshots | PUBLICLY OBSERVED |
| S7 | blogs.cisco.com "Uncover the where, when and how of an attack with Trajectory" | PUBLICLY OBSERVED |

## 1 · INGEST PIPELINE (S3, S4)

```
file accessed / moved / executed
        ↓
connector driver computes SHA-256
        ↓
LOCAL CACHE lookup  ── hit ─→ scan progression TERMINATES EARLY
        ↓ miss
local engines (TETRA/AV, SPERO, ETHOS)
        ↓
CLOUD LOOKUP  (FILE_MULTI message)  ← ONLY for supported file types
        ↓
cloud engines → disposition → event → console + Device Trajectory
        ↓
RETROSPECTIVE re-evaluation for 7 DAYS against new intelligence
        ↓
Cloud IOCs, enriched with MITRE tactics/techniques, shown in the trajectory
```

Telemetry streamed continuously: process, file, command line, network. (S3, S4)

## 2 · WHY A CISCO TRAJECTORY IS NOT A FILE DUMP — the decisive statement

S2, verbatim:

> "There are different levels of reporting between the Cisco Secure Endpoint,
> Event Console, and Device Trajectory. Although a file is scanned at the
> connector level, only certain files are queried against the Public Cloud.
> **This narrowing of events is not to hide visibility, but to accent the more
> important indications of compromise and not weigh down the system with
> inconsequential files.**"

Two independent narrowing mechanisms, both DOCUMENTED:

**(A) File-type narrowing at the cloud query.** S2's Windows set — note these
are TYPE IDENTITIES (content-identified), not extensions:

```
7ZSFX · ELF · ENCRYPTED_SCRIPT · HTML_APP · HWP3 · HWPOLE2 · LNK · MBR ·
MSCAB · MSEXE · MSOLE2 · OOXML_PPT · OOXML_HWP · OOXML_WORD · OOXML_XL ·
PDF · POWERSHELL · REGISTRY · SCRIPT · SETUP_INFO · SWF · WINDOWS_SCRIPT ·
XML_HWP · XML_WORD · XML_XL · ZIP
```

S2 also lists types explicitly **not visible in Device Trajectory**:
`AU3 · XZ · CRYPTFF · MSCHM · RARSFX · ZIPSFX`, and archive types scanned but
not queried (`7Z · 7ZSFX · ARJ · ARFSFX` — contents queried, not the archive).

S1 p.401 states the user-facing display set (executable, PDF, MS Cabinet, MS
Office, archive, Flash, plain text, rich text, script, installer).

**(B) Per-file event cache — repeat suppression.** S1 p.401, verbatim:

> "When a file triggers an event, the file is cached for a period of time
> before it will trigger another event. The cache time is dependent on the
> disposition of the file: Clean files – 7 days · Unknown files – 1 hour ·
> Malicious files – 1 hour"

This is why Cisco never shows 38 writes to the same LevelDB file in ten
minutes. The second through thirty-eighth events do not exist.

**(C) Volume ceilings.** S1 p.401: 30 days of file events retained; "only the
first 500 compromise events are available for a 30-day period".

## 3 · TRAJECTORY VIEW GEOMETRY (S1 p.401, S6)

> "The vertical axis of the Device Trajectory shows a list of files and
> processes observed on the device by the connector and the horizontal axis
> represents the time. Running processes are represented by a solid horizontal
> line with child processes and files the process acted upon stemming from the
> line. A list of file events is displayed on the right side."

S6 adds the console's actual composition, which the guide does not spell out:

- an **upper timeline window** with sliding date/time bars; compromise events
  appear there as **red dots**; clicking a red dot exposes a blue
  **"Compromise Events"** action that jumps the lower graph to that event
- a lower **"Process Detail Graph"**, scrolled SIDE TO SIDE through time —
  clicking a compromise event often lands on only ONE link of the chain, so
  the analyst scrolls forward/back to see the sequence
- an **Event Details** pane on the right, populated by clicking an event icon
- **Filters** used to de-select processes and de-noise the process graph,
  applied with a blue **Apply Filters** button

## 4 · IOC PRESENTATION (S1 p.405)

> "When certain series of events are observed on a single device, they are seen
> by Secure Endpoint as indications of compromise. In Device Trajectory, these
> events will be highlighted yellow… There will also be a separate compromise
> event in the Trajectory that describes the type of compromise. Clicking on
> the compromise event will also highlight the individual events that triggered
> it with a blue halo. A description of the indicator and the tactics and
> techniques will also be displayed in the Event Details pane."

IOCs are CLOUD-side correlations over a 7-day retrospective window, enriched
with MITRE (S3). Contributing factors named publicly: malicious file
detections, dropper infections (one file repeatedly downloading malware),
multiple infected files, executed malware, suspected botnet connections,
application-specific compromises (e.g. a shell launched by a suspicious
process).

**Engineering consequence for DT2-3c:** the blue halo requires a
server-published CONTRIBUTOR SET per compromise. Cisco computes it in the
cloud. NivXForge publishes no such set today, so the halo has nothing
authoritative behind it — it must not be faked from proximity.

## 5 · DATA MODEL (S5)

`GET /v1/computers/{connector_guid}/trajectory` → `data.events[]` carrying
`timestamp`, `event_type`, `file.identity.sha256`,
`file.parent.identity.sha256`, plus detection/network fields. Parent/child is
therefore resolved by **file identity (SHA-256)**, not by PID.

NivXForge resolves it by canonical process identity, and currently downgrades
to a PID-based surrogate (`authority: DERIVED`, `downgraded: true`) because the
sensor does not always send a hash. That is a weaker identity than Cisco's and
the contract already says so.

## 6 · WHAT THIS CHANGES IN NIVXFORGE

| Cisco mechanism | Classification | NivXForge status |
|---|---|---|
| File-type narrowing (A) | DOCUMENTED | IMPLEMENTED as a DISPLAY rule — `dt2/fileType.js`, File Type filter, Cisco's ten classes default. Difference stated: Cisco narrows at ingest by CONTENT identity; we narrow at display by PATH EXTENSION (`CLASS_BASIS = PATH_EXTENSION_DERIVED_NOT_CONTENT_IDENTIFIED`) and keep the evidence. |
| Per-file event cache (B) | DOCUMENTED | NOT IMPLEMENTED — needs an owner ruling. Cisco suppresses at ingest, so the repeats never exist; suppressing at display would hide observations we hold. |
| Volume ceilings (C) | DOCUMENTED | NOT IMPLEMENTED (30-day retention exists; no 500-compromise ceiling). |
| Upper timeline red dots → "Compromise Events" action | PUBLICLY OBSERVED | PARTIAL — navigator carries compromise dots; no blue "Compromise Events" jump action. |
| Lower graph scrolled side-to-side through time | PUBLICLY OBSERVED | MATCH — horizontal time scroll exists. |
| Filters de-select PROCESSES (not just event types) | PUBLICLY OBSERVED | MISSING — our Activity/System filter is by event type; Cisco also de-selects individual processes. |
| Event Details on icon click | DOCUMENTED | MATCH |
| Yellow IOC highlight / compromise event / blue halo / tactics+techniques | DOCUMENTED | DT2-3c, blocked on a server contributor set |
| SHA-256 parent/child identity | DOCUMENTED | PARTIAL — PID surrogate, declared `downgraded` |

## NOT VERIFIED — therefore NOT built

Row grouping or collapsing in the trajectory; a "show more" affordance;
in-trajectory paging; any specific pixel metric (line thickness, glyph size,
row height) — no Cisco source states them, so ours stay as measured from the
owner-supplied screenshots.
