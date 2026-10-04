# DT2-3c · GEOMETRY DIAGNOSTIC (owner-requested, before any visual change)

No timestamp was changed. No fixture time was spread to improve
appearance. Nothing deployed.

## BLACK_BAND_DEFECT = FIXED

Root cause: `RelationshipCanvas` builds its OWN palette from the `theme`
prop and had no `ioc*` / `contributor*` keys, so `C.iocBand` and
`C.iocRow` were `undefined` and SVG `fill={undefined}` renders BLACK.
The tokens are now declared in that palette (and in `ampModel` for the
AMP canvas), so the IOC region is translucent yellow.

## 1 · FIXTURE_TIME_DISTRIBUTION = A. TRUTHFUL FIXTURE TIMING

All six fixture observations really do occur inside **4.8 seconds**
(16:20:00.000 → 16:20:04.800). The default viewport is ~68 s wide, so the
whole story legitimately occupies ~40 px. This is NOT a projection defect
and NOT a rendering defect — the trajectory is drawing a 4.8 s incident
truthfully inside a 68 s window.

**Separate real gap found:** the `?from=…&to=…` deep link did NOT change
the view on first paint (the extracted X values are identical with and
without it), so Cisco-style time focusing cannot currently be reached by
URL on this route. Reported, not yet fixed.

## 2 · FIXTURE_TIMESTAMP_TO_X_PROOF

Extracted from the live DOM (`data-row-start-iso` / `data-row-start-x`,
`data-activity-iso`, halo `cx`/`cy`):

| OBSERVATION | TYPE | PROCESS | TIMESTAMP | X | ROW_Y | CONTRIBUTOR | COMPROMISE_ID |
|---|---|---|---|---|---|---|---|
| obs_5fc9ace224dd | process_create | explorer.exe | 16:20:00.000 | 718.00 | 167 | no | — |
| obs_29fa8bc40c53 | process_create | powershell.exe | 16:20:01.200 | 728.00 | 185 | no | — |
| obs_8ba19b8f9364 | file_create | powershell.exe | 16:20:02.400 | 738.00 | 203 | **yes** | cmp_…:obs_2e325969e1c8 |
| obs_2e325969e1c8 | registry_value_set | powershell.exe | 16:20:03.600 | 748.00 | 185 | **yes** | cmp_…:obs_2e325969e1c8 |
| obs_d8f4384d7970 | registry_value_set (TWIN) | powershell.exe | 16:20:03.600 | 748.00 | 185 | **no** | — |
| obs_bc35b655ed16 | network_connect | updater.exe | 16:20:04.800 | 758.00 | 221 | **yes** | cmp_…:obs_2e325969e1c8 |

**X is a pure function of time:** every 1,200 ms step is exactly 10.00 px
⇒ 8.333 px/s, perfectly linear, monotonic, no snapping and no visual
convenience. The clustering is the 4.8 s incident, nothing else.

## 3 · PROCESS_LIFELINES — DT2-3b NOT REGRESSED

Every row still carries `data-lifeline-semantics="OBSERVED_EVIDENCE_SPAN"`.

| PROCESS_ID | FIRST_EVIDENCE_AT | LAST_EVIDENCE_AT | START_X | END_X | OBSERVED_SPAN_MS |
|---|---|---|---|---|---|
| proc_057afc63b1d… (explorer.exe) | 16:20:00.000 | 16:20:00.000 | 718.00 | 718.00 | 0 |
| proc_a7d350844726 (powershell.exe) | 16:20:01.200 | 16:20:03.600 | 728.00 | 748.00 | **2400** |
| proc_a7d350844726::C:\Users\Public\updater.exe (FILE) | 16:20:02.400 | 16:20:02.400 | 738.00 | 738.00 | 0 |
| proc_c85eb0bc4746 (updater.exe) | 16:20:04.800 | 16:20:04.800 | 758.00 | 758.00 | 0 |

powershell.exe draws a real horizontal lifeline (2.4 s = 20 px at this
zoom). The other three have ONE observation each, so their observed span
is genuinely zero and they are drawn as truthful point glyphs. No process
lifetime is manufactured.

## 4 · CONTRIBUTOR_TIMESTAMP_PLACEMENT — CORRECT

Blue halos sit at their own observation's time and row, NOT at the
compromise time:

```
halo 1  cx=748  cy=185   registry_value_set  16:20:03.600  powershell row
halo 2  cx=738  cy=203   file_create         16:20:02.400  file row
halo 3  cx=758  cy=221   network_connect     16:20:04.800  updater row
```

Three distinct X values — contributors were not collapsed onto
`compromise_event.observed_at`. Exactly 3 halos for 3 proven contributors,
and the content-identical TWIN at the same instant is NOT emphasised.

## 5 · COMPROMISE_EVENT

`data-ioc-iso = 2026-09-22T16:20:03.600000+00:00` → x = 748.

It COINCIDES with the registry contributor's X **because my fixture set
the compromise's `observed_at` to its subject observation's time**. That
is a fixture construction choice, not a renderer defect, and it currently
makes the separate compromise event hard to distinguish from one of its
contributors. Not yet addressed.

## 6 · RELATIONSHIPS — FIXTURE GAP, NOT A RENDERER GAP

| relationship | result |
|---|---|
| PROCESS_FILE | **1 edge**, `dt2-edge-aedge:…:act:file:C:\Users\Public\updater.exe`, basis `CANONICAL_ACTOR_PROCESS_BINDING` |
| PROCESS_PROCESS | **0 edges** |
| PROCESS_REGISTRY | activity attached to its actor process; no edge row emitted |
| PROCESS_NETWORK | activity attached to its actor process; no edge row emitted |

Cause: **my fixture never wrote parent-process fields**, so
explorer.exe → powershell.exe → updater.exe does not exist in the
fixture's evidence. The renderer is correctly drawing nothing, because
inventing those edges from name order or proximity is exactly what the
contract forbids. The fix belongs in the FIXTURE (give it real parent
linkage), not in the canvas.

## 7 · IOC_YELLOW_PRESENTATION_BASIS = **NIVXFORGE DESIGN DECISION**

Honest classification, as asked:

* the diamond IOC marker above the axis and the translucent full-height
  time column are a **NivXForge design decision**;
* they are NOT `DOCUMENTED` and NOT `PUBLICLY OBSERVED`. I have no Cisco
  source establishing that AMP paints a full-height yellow time column
  for an IOC;
* the shape was inherited from the pre-existing NivXForge amber band in
  `AmpCanvas` (`C.band`), which was itself a NivXForge treatment. Turning
  the accidental black column yellow preserved a geometry that was never
  proven against the Cisco reference.

**Therefore the yellow region must not be treated as parity.** It needs
either a cited Cisco reference or a deliberate NivXForge decision
recorded as such.

## STATUS

```
BLACK_BAND_DEFECT              = FIXED
FIXTURE_TIME_DISTRIBUTION      = TRUTHFUL (4.8 s incident, 68 s viewport)
FIXTURE_TIMESTAMP_TO_X_PROOF   = EXACT, LINEAR, 8.333 px/s
PROCESS_LIFELINES              = PRESENT, DT2-3b NOT REGRESSED
PROCESS_FILE_RELATIONSHIPS     = 1 (authoritative)
PROCESS_PROCESS_RELATIONSHIPS  = 0  (FIXTURE GAP)
PROCESS_REGISTRY / NETWORK     = activity attached, no edge row
CONTRIBUTOR_BLUE_EMPHASIS      = 3 of 3 proven, own time + own row
CONTRIBUTOR_TIMESTAMP_PLACEMENT= CORRECT (3 distinct X)
COMPROMISE_EVENT               = rendered, but coincides with a
                                 contributor by fixture construction
IOC_YELLOW_PRESENTATION_BASIS  = NIVXFORGE DESIGN DECISION (uncited)
DT2_3C_FINAL_VISUAL_PARITY     = NOT ACCEPTED
TIME_FOCUSING_DEEP_LINK        = NOT HONOURED (new finding)
DEPLOYED                       = NO
```

## WHAT I HAVE NOT DONE (needs the owner's call)

1. Give the fixture real parent-process linkage so the causal story
   exists in evidence and can legitimately be drawn.
2. Give the compromise an `observed_at` distinct from its subject, or
   render the compromise glyph on its own band so the two are
   distinguishable.
3. Decide the yellow IOC geometry: cite a Cisco reference, or record it
   as a NivXForge design decision and stop calling it parity.
4. Honour `?from=/?to=` so a 4.8 s incident can be focused by deep link.
5. Produce the four native-resolution acceptance screenshots (A–D) and
   re-run the real Windows corpus (`dev_2adbb41a04a4`) regression.
