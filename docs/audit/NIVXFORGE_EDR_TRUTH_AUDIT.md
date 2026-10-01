# NivXForge EDR · Read-Only Truth Audit (40 rows)

**Date:** 2026-06 · **Mode:** READ-ONLY. No code was changed to produce this.
**Rule applied:** NO EVIDENCE → NO CLAIM. Documentation, a route stub, an
empty UI shell or a mock does NOT count as operational capability.

**Evidence sources used**
- Route table enumerated from the live `server.app` (`APIRoute` reflection).
- Persistence counts from Mongo `test_database` (135 collections).
- Runtime probes against the live preview API with an admin bearer token.
- Test inventory from `backend/tests/`.
- UI inventory from `apps/nivxray-xdr/src/xdr/pages` (30 pages).

---

## THE HEADLINE FINDING — the gap is the SUBSTRATE, not the capability

`GET /api/edr/file-trajectory?key=<sha256>` returns, today, live:

```
entry_points   creators   observed_names   observed_paths
first_observed last_observed  affected_endpoints  endpoint_rows
unique_events  raw_observations  content_digests  events
```

That is Cisco's **Entry Point**, **Created By**, **Known Names**, **First
Seen**, **Last Seen**, **Observations** and **computer list** — already
built. And it already tells the truth about why it is empty:

> `content_digests_available: false` — "event.artefacts.file[].sha256 is the
> only content-digest field in this contract and it is unpopulated, so
> hash-keyed fleet correlation cannot be performed on file contents."
> `integrity_note`: "event.raw.sha256 is identical to the document's
> input_sha256 on every record: it is the digest of the ingested
> observation, not of a file."

It even downgraded my SHA-256 query to `key_type: "name"` rather than
pretend to match on hash.

**Conclusion: File Trajectory is not missing. It is complete, honest and
STARVED.** The same is true of Device Trajectory, Spread Watchlist and the
whole response lifecycle. Roughly a third of the matrix is capability that
exists and is waiting on one thing: an endpoint sensor that emits a real
process, a real PID/PPID and a real file SHA-256.

**This validates your instruction to audit first.** Building File
Trajectory again would have been wasted work. Building the sensor lights up
what is already there.

---

## Corrected matrix

Legend — **E** EXISTS (operational, evidenced) · **P** PARTIAL (real code,
not bound to endpoint substrate, or narrower scope than claimed) ·
**M** MISSING (no route, no persistence, no driver).
`RT` runtime-verified · `DB` persistence-verified · `API` route-verified ·
`UI` UI-verified · `T` test-verified.

| # | Capability | Was | **Now** | Evidence | RT | DB | API | UI | T | Action |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Endpoint agent / sensor | ❌ | **M** | Zero routes match `agent\|sensor`. No collection. No process/file/registry telemetry source anywhere | – | – | – | – | – | **BUILD (P0-B)** |
| 2 | Endpoint enrolment / identity | ⚠️ | **P** | `services/edr/device_identity.py` resolves `device_iid` authoritatively from observations; `xdr_collectors` (111 rows) enrols *collectors*, not endpoints. No agent credential, no OS/version/install-date/group/policy | ✓ | ✓ | ✓ | ✓ | ✓ | **EXTEND — do not rewrite (P0-A)** |
| 3 | Live endpoint telemetry | ⚠️ | **P** | P1.10 proved live CEF/LEEF over UDP 5514 → incident. That is *network/security* telemetry, not endpoint | ✓ | ✓ | ✓ | ✓ | ✓ | Reuse the proven path for the agent |
| 4 | Process telemetry | ⚠️ | **P** | `ProcessEntity` exists in the canonical model; every live record carries `pid_state=UNKNOWN`, `ppid_state=UNKNOWN`. Corpus supplies process fields; live telemetry cannot | ✓ | ✓ | – | ✓ | ✓ | **Sensor unlocks (P0-B)** |
| 5 | Process tree / ancestry | ✅ | **E** | `/api/edr/process-tree`; Entity 360 `ancestry` tab; honest `NO PROCESS→PROCESS LINEAGE RESOLVABLE` when absent | ✓ | ✓ | ✓ | ✓ | ✓ | Keep |
| 6 | Device Trajectory | ✅ | **E** | `/api/edr/device-trajectory`, D3 lifeline canvas, 660 observations, `? NO PROCESS EVIDENCE` state | ✓ | ✓ | ✓ | ✓ | ✓ | Keep — starved of process events |
| 7 | File monitoring (create/modify/delete) | ⚠️ | **M** | `FileEntity` exists in the model but nothing emits file events. `file_index` collection: **0 docs** | – | – | – | – | – | **Sensor (P0-B)** |
| 8 | Network connection telemetry | ⚠️ | **P** | Real `src/dst/port/proto` arriving from CEF/LEEF; no per-process attribution | ✓ | ✓ | ✓ | ✓ | ✓ | Sensor adds process→socket binding |
| 9 | DNS telemetry | ⚠️ | **P** | `network.dns_query` mapped and indexed as a spread indicator; no live DNS source emitting it | – | – | ✓ | ✓ | ✓ | Sensor (P0-B) |
| 10 | File Trajectory | ❌ | **E** | `/api/edr/file-trajectory` returns `entry_points`, `creators`, `observed_names`, first/last observed, `endpoint_rows`. **Corrected from ❌** | ✓ | ✓ | ✓ | ✓ | ✓ | **DO NOT REBUILD** |
| 11 | Fleet-wide file propagation | ❌ | **E** | `/api/edr/fleet-spread-index`; P1.8 `XdrFleetFileTrajectoryPage` 7 tabs. **Corrected from ❌** | ✓ | ✓ | ✓ | ✓ | ✓ | **DO NOT REBUILD** |
| 12 | Cross-endpoint spread | ⚠️ | **E** | P1.10a: `xdr_spread_watchlist` (8), `xdr_spread_sightings` (23), 5 routes, threshold evidence → ICE → VEEE → gate. **Corrected** | ✓ | ✓ | ✓ | – | ✓ | **DO NOT REBUILD** — UI pending |
| 13 | Threat hunting | ⚠️ | **P** | Only `/api/investigation/{case_id}/hunting` — case-scoped, not fleet-wide. No saved-hunt persistence | ✓ | – | ✓ | – | – | Widen to fleet (P1.11) |
| 14 | Forensics | ⚠️ | **M** | `/api/platform/snapshot` is a *platform* snapshot, not endpoint forensics. No endpoint artefact collection | – | – | – | – | – | Needs sensor first |
| 15 | Live query | ⚠️ | **M** | Zero routes match `live.?quer\|orbital`. UI page is `XdrReservedPage` | – | – | – | ✓ | – | Needs sensor first |
| 16 | Remote diagnostics | ❌ | **M** | `/api/nivxforge/preview/diagnostics` is preview-build diagnostics, unrelated to endpoints | – | – | – | – | – | Needs sensor first |
| 17 | File fetch | ⚠️ | **M** | No endpoint fetch path. `/api/files/{id}` serves analyst *uploads*, not endpoint retrieval | – | ✓ | ✓ | ✓ | – | Needs sensor first |
| 18 | File quarantine | ⚠️ | **P** | Decision engine models it and returns `CAPABILITY_UNAVAILABLE` (`xdr_response_decision.py:302`). No executor | ✓ | ✓ | ✓ | ✓ | ✓ | **Bind an executor, don't rebuild** |
| 19 | Process termination | ⚠️ | **P** | Same — modelled, no executor | ✓ | ✓ | ✓ | ✓ | ✓ | Bind executor |
| 20 | Endpoint isolation | ⚠️ | **P** | `ISOLATE_ENDPOINT` action type is real in the response catalog; decision path returns `CAPABILITY_UNAVAILABLE`; drawer states `⊘ ISOLATION STATE UNKNOWN` | ✓ | ✓ | ✓ | ✓ | ✓ | Bind executor |
| 21 | Network blocking | ❌ | **P** | `/api/incidents/{id}/report/blocks` exists but is *report* content, not enforcement | ✓ | ✓ | ✓ | ✓ | – | Enforcement missing |
| 22 | USB / device control | ❌ | **M** | Zero routes | – | – | – | – | – | P2 |
| 23 | Custom hash detections | ⚠️ | **P** | 98 `xdr_detection_rules`, 4981 `xdr_detection_versions`, `/api/xdr/detection/policy`. No allow/block-list CRUD, no hash-simple-detection surface | ✓ | ✓ | ✓ | – | ✓ | Add CRUD only |
| 24 | Advanced file detections | ✅ | **E** | 615-object corpus, 31 enterprise rules, `detection_content/` registry | ✓ | ✓ | ✓ | ✓ | ✓ | Keep |
| 25 | Retrospective detection | ⚠️ | **M** | No route matches `retro`. Raw evidence IS retained (329 `xdr_canonical_events`, collector outbox) so replay is *possible* — but no replay driver exists | – | ✓ | – | – | – | **BUILD — high value, no sensor needed** |
| 26 | Static malware analysis | ✅ | **E** | 17 `/api/decode/*` + 21 `/api/die/*` routes; decoder + DIE stack | ✓ | ✓ | ✓ | ✓ | ✓ | Keep |
| 27 | Dynamic sandbox | ❌ | **M** | Zero routes match `sandbox\|detonat` | – | – | – | – | – | P3 — **not next** |
| 28 | IOC investigation / pivot | ✅ | **E** | `/api/ioc/*`, 19 `/api/threat-intel/*`, IKG | ✓ | ✓ | ✓ | ✓ | ✓ | Keep |
| 29 | Observable context menu | ⚠️ | **P** | `ActivityDetailsPanel` + the new `Actions ▼`; no universal right-click pivot on every observable | ✓ | – | – | ✓ | ✓ | Generalise (P1) |
| 30 | Detection → trajectory pivot | ⚠️ | **P** | `EdrTrajectoryResolver` + `/xdr/endpoints/:device/trajectory` route exist; no *exact-event-centred* deep link | ✓ | ✓ | ✓ | ✓ | – | **Small, high-value (P0-F)** |
| 31 | Event → endpoint pivot | ⚠️ | **P** | Just fixed: `latest_incident_id`/`case_ids` now on the identity payload, `Related incident` enabled and proven on HYD-SRV32 | ✓ | ✓ | ✓ | ✓ | ✓ | Mostly done |
| 32 | Endpoint health | ⚠️ | **M** | Only `identity_confidence` + observation counts. **No lifecycle state, no telemetry-health state.** Drawer honestly shows `⊘ NO HEARTBEAT` | – | – | – | ✓ | – | **BUILD (P0-A)** |
| 33 | Policy management | ⚠️ | **P** | 6 policy routes (detection + intelligence policy, versioned, `xdr_intelligence_policy_audit` 252 rows). No endpoint/response/isolation/collection policy | ✓ | ✓ | ✓ | – | ✓ | Extend the existing plane |
| 34 | Audit / change history | ⚠️ | **E** | `xdr_audit_log` 7164 · `xdr_vault_audit` 46856 · `xdr_cortex_scheduler_audit` 55641 · 21 audit routes. **Corrected from ⚠️** | ✓ | ✓ | ✓ | ✓ | ✓ | Add *device-scoped* view only |
| 35 | Saved filters / views | ⚠️ | **P** | `/api/xdr/saved-views` + `/{view_id}` exist. No scheduled alerting, no share scope | ✓ | – | ✓ | – | – | Extend (P1.11) |
| 36 | Streaming export / API | ⚠️ | **P** | P1.9 client-side JSON/MD/CSV export; 10 export/stream routes; collector outbox. No outbound event stream | ✓ | ✓ | ✓ | ✓ | ✓ | Extend |
| 37 | Investigation / IKG | ✅ | **E** | 18 `/api/investigation/*`, 6 `/api/investigations/*`, IKG, attack story | ✓ | ✓ | ✓ | ✓ | ✓ | **Keep — our advantage** |
| 38 | Deterministic verdict | ✅ | **E** | VEEE, weights + cap, 488 `workspace_cases`, `verdict_card.reason` states its arithmetic | ✓ | ✓ | ✓ | ✓ | ✓ | **Keep — our advantage** |
| 39 | Security State / causal FSM | ✅ | **E** | `xdr_response_timeline` 561, `xdr_response_executions` 193, closed-loop recompute | ✓ | ✓ | ✓ | ✓ | ✓ | **Keep — our advantage** |
| 40 | Evidence provenance | ✅ | **E** | `xdr_canonical_evidence` 249 with full provenance; `epistemic_state` per field; verbatim `raw_ref.line` retained for re-parse | ✓ | ✓ | ✓ | ✓ | ✓ | **Keep — our advantage** |

**Tally:** EXISTS 14 · PARTIAL 17 · MISSING 9.
**Corrections to the prior matrix: 6 rows** — #10, #11, #12 and #34 were
understated (already operational); #21 and #16 were overstated (routes exist
but are unrelated to endpoint enforcement/diagnostics).

---

## What is UI-only (no backend capability)

- Live Query page → `XdrReservedPage`, no route (#15)
- Forensics → no endpoint artefact path (#14)
- Network block enforcement → report content only (#21)

## What has backend but no live endpoint substrate (bind, don't build)

Rows **#10, #11, #12, #18, #19, #20, #23, #33** — eight capabilities whose
code is real and whose only missing input is endpoint telemetry.

## Genuinely missing, sensor-independent (buildable now)

- **#25 Retrospective detection** — raw evidence is already retained, so a
  replay driver over the existing pipeline is self-contained and high value.
- **#32 Endpoint health** — the two-dimension model you specified.
- **#30 Exact-event trajectory pivot** — small, and it is the Cisco workflow
  that ties the console together.

---

## Recommended order (revised by the audit)

Your intended order stands, with one change I want to flag: **P0-A must
also deliver the two-dimension health model**, because that is the row the
audit found genuinely MISSING rather than partial.

| Slice | Content | Why |
|---|---|---|
| **P0-A** | Endpoint identity + enrolment + **both health dimensions** (agent lifecycle × NivXRay telemetry health) | Row #32 is MISSING, #2 is PARTIAL. Extends `device_identity.py`, does not replace it |
| **P0-B** | Real Linux sensor — process/PID/PPID/ancestry/cmdline/exe SHA-256, file create-modify-delete, network connect, DNS where observable | The one input that lights up 8 starved capabilities |
| **P0-C** | Authenticated transport — enrolment token + per-agent credential, **pluggable** so mTLS drops in without touching the envelope | Your decision 2(c) |
| **P0-D** | Canonical evidence integration via the EXISTING `process_event_through_pipeline` and a new sensor DSM | Same pattern as the P1.10 CEF/LEEF DSM. No new engine |
| **P0-E** | Device Trajectory binding — real process lifelines, real ancestry | Removes `? NO PROCESS EVIDENCE` honestly |
| **P0-F** | Detection/Event → Device Trajectory exact-event pivot | Row #30 |
| **P0-G** | File/Network evidence expansion → lights up File Trajectory `content_digests` | Row #10 stops being starved |

**Sandbox stays at P3.** The audit confirms your call: it would add a new
evidence producer while eight existing consumers sit starved.

---

## Architectural constraints carried into implementation

- The sensor **collects evidence and does not decide maliciousness.**
- The sensor DSM plugs into the existing `TELEMETRY_DSM_REGISTRY` and the
  existing `process_event_through_pipeline`, exactly as `cef-leef` does.
- No duplicate IUE / ICE / IEDDE / UAIE / VEEE / Decoder / IKG / Verdict /
  Security State / Response Safety / Verification / Detection / Correlation.
- Tenant scope is never taken from the client. Enforced already:
  `/api/xdr/ingest/telemetry` proves header-vs-payload tenant match BEFORE
  any collector lookup.
- Frozen epistemic rules unchanged. `NO_TELEMETRY` must remain
  distinguishable from `OFFLINE`, from `PARSER_ERROR`, from
  `NEVER_ENROLLED`, and from `ISOLATED`.

## Honest limits of this audit

- Classification is based on route reflection, persistence counts, runtime
  probes, UI inventory and test inventory. I did **not** execute all 40
  capabilities end-to-end; rows marked `RT ✓` were probed, rows without it
  were classified on code and persistence evidence only.
- The `T` column reflects whether *some* automated test covers the
  capability, not full branch coverage.
- No Windows/macOS claim is made anywhere. Neither can be built or verified
  in this Linux container.
