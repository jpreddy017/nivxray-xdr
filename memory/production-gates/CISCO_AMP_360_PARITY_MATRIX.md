# NivXForge EDR ↔ Cisco Secure Endpoint (AMP) · 360° BENCHMARK & GAP MATRIX

Read-only architecture work. **Nothing was implemented, weakened or
migrated to produce this document.** No Cisco CSS, JS, image or other
proprietary asset is copied; the benchmark is *documented behaviour and
information architecture*, re-expressed in NivXForge's own components and
vocabulary.

Reference material used (public Cisco documentation):
Secure Endpoint User Guide and Quick Start (`docs.amp.cisco.com`),
"Identify the detection engine in Secure Endpoint" (`cisco.com/c/en/us/
support/docs/security/secure-endpoint/222850`), "Configure and manage
exclusions" (`215418`), "Best practices for exclusions" (`213681`),
Cisco Live TACSEC-2012 (Device Trajectory v2).

Column model, per surface:
**CAP** capability · **FLOW** workflow · **UX** UI/UX · **DEP** backend
dependency · **NVF** NivXForge today · **GAP-C** missing capability ·
**GAP-B** missing backend · **GAP-U** missing UI · **SEC** security
dependency · **TEST** test requirement · **ACC** production acceptance
evidence.

Status legend for **NVF**: `IMPLEMENTED` · `PARTIAL` · `HONEST_N/I`
(declared, disabled, with its reason) · `ABSENT` (not even declared).

---

## 1 · Dashboard
* **CAP** fleet posture at a glance: compromise count, connector health,
  outstanding detections, ingest health.
* **FLOW** land → spot the abnormal number → pivot into the filtered list
  that produced it.
* **UX** dense metric rail (no giant cards), every number a link, time
  window declared on the surface.
* **DEP** aggregate reads over endpoints + detections + telemetry
  freshness, tenant-scoped, single aggregation per tile.
* **NVF** `PARTIAL` — `/edr` Dashboard exists; Computers carries the real
  metric rail (`COMPUTERS 222 · CONNECTED 1 · NO TELEMETRY 151 ·
  SILENT/STALE 0 · DETECTIONS·24H 59`) from ONE aggregation.
* **GAP-C** no "compromised computers" roll-up, no connector-health
  histogram, no ingest-health tile. **GAP-B** none new (reads exist).
  **GAP-U** tiles are not yet click-through filters.
* **SEC** every tile must be tenant-scoped by the server (`edr_tenant`);
  a cross-tenant role must see the applied scope, never the estate.
* **TEST** one aggregation per tile (no N+1), `0` ≠ `null` semantics,
  cross-tenant returns no rows. **ACC** tile number == filtered list
  count, proven on the same dataset.

## 2 · Computers (inventory)
* **CAP** every connector: hostname, OS, group, policy, connector
  version, protection mode, last-seen, definitions.
* **FLOW** filter/search → select → flyout → deep-dive.
* **UX** dense sortable table + contextual pane, not a page navigation.
* **DEP** endpoint registry + per-endpoint health + detection counts in
  one aggregation.
* **NVF** `IMPLEMENTED` — `/edr/computers`, 222 rows in ~0.75 s, real
  `detections_24h/total`, contextual pane with identity, placement,
  protection, telemetry.
* **GAP-C** bulk actions (move group, reboot, uninstall), saved views,
  column chooser, CSV export. **GAP-B** group/policy assignment writes.
  **GAP-U** multi-select.
* **SEC** placement writes are tenant + RBAC gated; `endpoint_id` never
  accepted as authority from the client.
* **TEST** `null` (not evaluated) never merged with `0`; window declared
  per row. **ACC** the live grid on ≥10k endpoints with p95 < 2 s.

## 3 · Computer detail
* **CAP** one endpoint's full record: identity, policy, engines, events,
  vulnerabilities, isolation state.
* **FLOW** Computers → device workspace → lens tabs.
* **UX** permanent tab set; an unimplemented lens is DISABLED with its
  reason, never a functional-looking empty page.
* **DEP** `GET /api/edr/onboarding/computers/{id}` projection.
* **NVF** `IMPLEMENTED` for Overview / Trajectory / Command Intelligence;
  Files · Network · Response · Forensics are `HONEST_N/I`.
* **GAP-C** vulnerability inventory, installed-software inventory,
  connector diagnostics bundle. **GAP-B** none for Overview.
  **GAP-U** the four declared lenses.
* **SEC** enrolment credential id deliberately NOT disclosed to the
  console (already honoured).
* **TEST** enrolment / credential / sensor remain three INDEPENDENT
  facts. **ACC** a real endpoint's card matches the sensor's own report.

## 4 · Device Trajectory
* **CAP** per-endpoint timeline of file/process/network/connector events
  with the detecting engine named (Tetra, Behavioural Protection,
  Malicious Activity Protection, Exploit Prevention).
* **FLOW** Events/Computer → trajectory → select event → details → pivot
  to file trajectory / hunt.
* **UX** navigator band over a lane canvas, filters, search, 24 h window
  with day paging, keyboard and explicit zoom (no wheel hijack).
* **DEP** bounded windowed projection over the observation store +
  progressive completion.
* **NVF** `IMPLEMENTED` — AMP-class renderer, 207,953 observations,
  `BOUNDED_RECENT` first paint ≈2 s, both themes.
* **GAP-C** engine attribution per event (NivXForge has ONE deterministic
  engine today — this is Gate 3), retrospective re-colouring (Gate 6),
  file/network lanes (sensor does not collect them).
  **GAP-B** detection-engine identity on the event.
  **GAP-U** lane legend per engine.
* **SEC** endpoint identity resolution under the caller's scope
  (P0-2C invariant) — already enforced.
* **TEST** counts exact not estimated; `no sensor coverage` ≠ `no
  activity`. **ACC** first paint p95 ≤ 2 s on the 200k endpoint.

## 5 · Events
* **CAP** estate-wide event/detection log with per-field filters and
  shareable deep links.
* **FLOW** filter → inspect → pivot to computer/trajectory/file.
* **UX** dense virtualised table, filter chips, saved filters.
* **DEP** indexed query over raw + canonical evidence with cursoring.
* **NVF** `HONEST_N/I` — declared, disabled, reason states event evidence
  is reachable per computer.
* **GAP-C/GAP-B/GAP-U** the whole surface: no estate-wide event query
  API, no cursor contract, no UI.
* **SEC** tenant predicate in the query, never a client filter.
* **TEST** cursor stability under concurrent ingest; cross-tenant empty.
* **ACC** a known event found by three independent filters.

## 6 · Detections / Compromises
* **CAP** the detection list: file name, SHA-256, disposition, detecting
  engine, action taken (quarantine success/failure), computer.
* **FLOW** detection → trajectory → outbreak-control decision.
* **UX** severity-tokenised rows, engine named, action outcome explicit.
* **DEP** detection store with engine + action provenance.
* **NVF** `PARTIAL` — `/edr/detections` exists and reads real
  `derivations[].outcome`; there is no engine identity and no action
  outcome because there is no prevention engine yet.
* **GAP-C** engine attribution, quarantine action + its result,
  disposition (clean/malicious/unknown) from a reputation authority.
  **GAP-B** Gate 3 fabric + file reputation. **GAP-U** action column and
  its failure states.
* **SEC** a detection must never be created by a client-supplied verdict.
* **TEST** a detection with no action reads NOT ATTEMPTED, never
  "success". **ACC** engine + action + outcome citable per detection.

## 7 · File Trajectory
* **CAP** one SHA-256 across the estate: every computer that saw it,
  first/last seen, parents, dispositions over time.
* **FLOW** detection/file → file trajectory → outbreak control.
* **UX** estate timeline + per-endpoint rows, prevalence number.
* **DEP** content-addressed index on sha256 across endpoints.
* **NVF** `PARTIAL` backend (`GET /api/edr/file-trajectory`,
  `fleet-spread-index`), UI `HONEST_N/I` ("Files": the sensor does not
  collect file-system observation yet).
* **GAP-C** file observation on the endpoint. **GAP-B** sensor file
  events + hashing. **GAP-U** the surface.
* **SEC** prevalence must not leak another tenant's presence.
* **TEST** a hash present in two tenants shows each only its own.
* **ACC** a real file seen on ≥2 endpoints of one tenant.

## 8 · Process investigation (tree / story)
* **CAP** ancestry and lineage with ghost parents made explicit.
* **FLOW** event → process tree → campaign narrative.
* **UX** tree with lineage states, not a prettified guess.
* **DEP** canonical `process_iid`/`parent_iid` identities.
* **NVF** `IMPLEMENTED` — Process Tree + Campaign Story, with
  `GHOST_PARENT_NOT_OBSERVED` kept and never invented.
* **GAP-C** cross-endpoint campaign linking. **GAP-U** graph lens.
* **SEC** scope-bound identity resolution (see Gate 14 A1-b).
* **TEST** the three honest empty states (now asserted separately).
* **ACC** a real intrusion told once, every link cited.

## 9 · Endpoint search / Orbital-class live query
* **CAP** ask a live question of the endpoint fleet.
* **FLOW** query → approval → execution → results with provenance.
* **UX** query library, per-endpoint result state, no silent partials.
* **DEP** endpoint execution channel + approval authority.
* **NVF** `HONEST_N/I` — declared, disabled, reason names the missing
  approval-gated execution channel.
* **GAP-C/B/U** entire capability.
* **SEC** this is a remote-execution primitive: dual authority
  (RBAC permission + per-action approval), signed command, tamper-evident
  audit, and independent verification of what actually ran.
* **TEST** an unapproved query must be impossible, not merely hidden.
* **ACC** an executed query citable end-to-end on a real endpoint.

## 10 · Outbreak Control
* **CAP** Simple Custom Detections, Advanced Custom Detections,
  Application Control (block/allow), IP block/allow lists.
* **FLOW** detection → add to list → policy sync → enforcement on
  endpoint → evidence that it enforced.
* **UX** list management + "used by N policies" + audit of who changed
  what.
* **DEP** list store, policy compilation, endpoint sync, enforcement
  telemetry.
* **NVF** `ABSENT`.
* **GAP-C/B/U** entire capability. **SEC** a blocklist is an enforcement
  authority: write RBAC, tenant binding, change audit, and it must never
  be satisfiable by a client-declared "enforced".
* **TEST** a list entry must demonstrably change an engine's outcome.
* **ACC** endpoint-side proof of enforcement, not console intent.

## 11 · Groups
* **CAP** organise computers; groups carry policy.
* **FLOW** create group → assign policy → move computers → verify.
* **UX** group tree, membership counts, policy inheritance shown.
* **DEP** group store + placement writes + inheritance resolution.
* **NVF** `PARTIAL` — placement fields exist at enrolment
  (`group_id`, `policy_id`, `placement_basis`, `placement_at`) and the
  grid reports `UNASSIGNED` honestly; there is no group management.
* **GAP-C/B/U** CRUD, inheritance, bulk move. **SEC** cross-tenant group
  assignment must be impossible; placement basis is provenance.
* **TEST** inheritance resolution is deterministic and explainable.
* **ACC** a computer's effective policy traceable to the group decision.

## 12 · Policies
* **CAP** per-group connector configuration: engines on/off, modes
  (audit/block), exclusions attached, update cadence.
* **FLOW** author → validate → assign → sync → confirm on endpoint.
* **UX** policy editor with declared defaults and a diff before save.
* **DEP** policy schema + versioning + endpoint sync + acknowledgement.
* **NVF** `HONEST_N/I` — the default Windows policy is `DETECT_ONLY`,
  shown per computer with its enforcement state stated.
* **GAP-C/B/U** authoring, versioning, sync acknowledgement. **This is
  Gate 8.**
* **SEC** a policy is an enforcement authority — RBAC-gated write,
  tenant-bound, signed distribution, endpoint must verify origin.
* **TEST** a policy change must be provably applied or provably pending;
  never assumed.
* **ACC** endpoint acknowledges version N and behaves accordingly.

## 13 · Exclusions
* **CAP** Cisco-maintained + custom exclusion sets: path, extension,
  process, threat, IOC-based; attached to policies.
* **FLOW** create set → attach to policy → verify the engine honours it.
* **UX** set editor, per-type validation, "used by" and impact preview.
* **DEP** exclusion evaluation INSIDE each detection engine + visibility
  semantics in the console.
* **NVF** `ABSENT`.
* **GAP-C/B/U** entire capability. **This is Gate 9.**
* **SEC** an exclusion is an intentional blind spot: RBAC-gated,
  audited, never silently broadening (no "exclude whole drive"), and it
  must be visible in the console as a declared blind spot.
* **TEST** an excluded path must verifiably change engine output AND be
  disclosed in the UI as excluded — not simply absent.
* **ACC** engine trace showing the exclusion that suppressed a finding.

## 14 · Response (endpoint actions)
* **CAP** quarantine/restore a file, stop a process, collect a bundle.
* **FLOW** request → authorise → dispatch → execute → report →
  independently verify.
* **UX** six distinct facts, never collapsed into "done".
* **DEP** command dispatch (`edr_response_commands`), endpoint executor,
  verification read.
* **NVF** `PARTIAL` — dispatch plane and `/edr/response` exist; the
  endpoint executor and independent verification do not.
* **GAP-C** execution + verification. **GAP-B** endpoint action executor.
  **GAP-U** per-action outcome timeline.
* **SEC** `REQUESTED ≠ AUTHORIZED ≠ DISPATCHED ≠ EXECUTED ≠
  RESULT_REPORTED ≠ VERIFIED`; the endpoint's own report is not
  verification.
* **TEST** an unexecuted action can never read as executed.
* **ACC** a real action verified by a second, independent observation.

## 15 · Isolation
* **CAP** network-isolate an endpoint with an allowlist, then release.
* **FLOW** isolate → confirm isolated → investigate → release → confirm.
* **UX** unmistakable isolation banner and audit of who/when/why.
* **DEP** endpoint-side enforcement + heartbeat that survives isolation.
* **NVF** `PARTIAL` — `edr_plane/isolation_policy.py` and
  `GET /api/edr/response/isolation-policy` exist; no endpoint
  enforcement.
* **GAP-C/B** endpoint enforcement + isolation-safe heartbeat.
  **GAP-U** state banner + release workflow.
* **SEC** the most destructive endpoint operation: approval authority,
  tenant binding, and a release path that cannot be lost with the
  console.
* **TEST** isolation must not silently fail open. **ACC** verified
  isolation on a real endpoint (owner-gated, destructive).

## 16 · Connector / sensor management
* **CAP** connector versions, update rings, health, reinstall, uninstall.
* **FLOW** deploy → enrol → connect → keep current.
* **UX** version + health per computer, upgrade campaign view.
* **DEP** package registry, enrolment API, version reporting, update
  channel.
* **NVF** `PARTIAL` — V1 onboarding API, per-device credential at
  enrolment, sensor version reported; Linux sensor real, **Windows sensor
  is Gate 1** and unproven on a real host.
* **GAP-C** update rings/campaigns, uninstall protection.
  **GAP-B** signed update channel. **GAP-U** upgrade view.
* **SEC** installer carries NO tenant credential (already honoured);
  enrolment token single-use, 1 h, tenant-bound, purpose-bound.
* **TEST** `INSTALLED ≠ CONFIGURED ≠ CONNECTED ≠ RECEIVING ≠ HEALTHY`.
* **ACC** the real Windows host chain (Gate 1).

## 17 · Downloads
* **CAP** obtain the installer per architecture with integrity data.
* **FLOW** choose architecture → download → install command.
* **UX** per-package card, artifact hashes, silent-install snippet.
* **NVF** `IMPLEMENTED` — one reusable credential-free build, sha256 per
  artifact, `NOT BUILT` stated for ARM64/x86.
* **GAP-C** code signing (`UNSIGNED` today, stated), macOS/Linux
  packages. **SEC** an unsigned installer is a supply-chain risk and is
  labelled as such. **ACC** signed artifact + verified hash chain.

## 18 · Audit
* **CAP** who changed what, when, from where — policies, lists,
  exclusions, response actions, credentials.
* **NVF** `HONEST_N/I` for EDR; platform audit exists in NivXRay XDR.
* **GAP-C/B/U** EDR-scoped audit projection. **SEC** append-only,
  tamper-evident, never editable from the console. **ACC** every
  enforcement write in this matrix appears in it.

## 19 · Administration
* **CAP** users, roles, API credentials, business, 2FA, subscriptions.
* **NVF** `PARTIAL` — XDR administration exists (roles catalog, API
  keys, collectors); EDR-specific admin does not.
* **GAP-C** groups-grant-nothing defect (RBAC-0), no DENY expression, no
  direct grants/restrictions. **SEC** this is the authorisation spine —
  serialised work, never parallel with another authority change.
* **ACC** RBAC decision path with a reason for every allow and deny.

---

## Execution ordering implied by this matrix

1. **Gate 3** fabric — it unblocks engine attribution (surfaces 4, 6),
   dispositions, and everything Outbreak Control/Exclusions must affect.
2. **Gate 8/9** policies + exclusions — they are the same authority and
   must be serialised with each other.
3. **Surface 5 Events** — the one large read surface with no backend at
   all; it is independent of the enforcement authorities and can run in
   parallel with Gate 3.
4. **Gate 1** Windows endpoint proof — owner-gated, blocking for
   production exit only.
5. Response execution + isolation (surfaces 14, 15) — destructive,
   serialised, approval-gated, owner-authorised.
