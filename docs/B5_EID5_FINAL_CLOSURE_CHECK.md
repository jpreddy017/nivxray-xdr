# B5 EID5 — FINAL DELIVERY / CLOSURE CHECK (READ-ONLY)

Measured against production store `greeting-app-5782-test_database`, run `3bd64025`.
Nothing deployed, written, replayed or reconfigured. Endpoint / sensor / Sysmon / outbox
untouched. No E3.

## STATUS BLOCK

```
CURRENT_FRONTIER      = 2026-09-29T20:49:33.258293Z  (newest ingest 23:43:04.183228Z)
TARGET_WINDOW_REACHED = YES — ~5h59m of event-time PAST 14:50Z; outbox 6,698 → 2,078
                        (draining), rate ~1.707 event-s per wall-s. Not stalled.
EID5_RAW_RECEIVED     = SPLIT — genuine Sysmon EID5 class YES (17, UtcTime
                        15:17:21 → 17:40:10Z); the 10 target guids NO (0/10)
EID5_ACCEPTED         = YES for the arrived cohort (`edr_rejected_telemetry` = 0 for
                        this endpoint); N/A for the target guids (never received)
EID5_CANONICALIZED    = YES for arrived cohort — 17 `process_exit`, 1:1 with raw
                        (e.g. `cev_6e18d93e1d9ab03a5b765548_0`); NO for target guids
PROCESS_EXIT_MAPPING  = YES (`kind=process_exit`, `obs_bffdd00b25b0`)
EXIT_TIME_MAPPING     = YES — field_provenance `process.exit_time =
                        "sysmon:UtcTime (EventID 5)"`, `start_time = null`
PROCESSGUID_BINDING   = YES — SOURCE_PROCESS_IDENTITY,
                        `process_iid = nivx:ProcessIdentity.mint(endpoint_id, ProcessGuid)`;
                        NOT_PROVEN for the target guids (absent)
EID1_EID5_PAIRING     = YES — ≥4 pairs sharing ProcessGuid: f7fa-2b1e, f7fa-271e,
                        dd70-211d, dd70-221d; NONE for the target guids
LIFECYCLE_PROJECTED   = YES for arrived cohort; no backfill; target guids absent
TRAJECTORY_VISIBLE    = YES — projected under `dev_2adbb41a04a4`
                        (`v2_shadow_observations`, `event.device_iid`), authoritative
                        captured_at e.g. 2026-09-29T17:40:10.707Z; NO for target guids
TENANT_IDENTITY_SAFETY= YES — tenant `ten_e759b7288598bd882e3dcac49d` preserved,
                        ProcessGuid identity, no heuristic cross-device binding,
                        no `_pl` authority minted
FIRST_BROKEN_BOUNDARY = RAW RECEIVED — the 10 target EID5 ProcessGuids were never
                        ingested. Coverage gap in the delivered stream for the
                        ~14:48–15:16Z UtcTime window.
B5_EID5_END_TO_END    = BLOCKED: the 10 previously-captured target ProcessGuids are
                        absent end-to-end despite the frontier passing their slot.
```

## 1 · THE ENGINE IS PROVEN — WITH GENUINE, ENDPOINT-GENERATED EID5

This is the substantive result. **17 genuine Sysmon EID5 (ProcessTerminate) records
travelled the ordinary sensor delivery path and are fully processed**, end to end:

```
raw received → accepted (0 refusals) → canonical process_exit (17, exactly 1:1)
→ exit_time ← sysmon:UtcTime (EventID 5), start_time null
→ ProcessGuid-bound via nivx:ProcessIdentity.mint(endpoint_id, ProcessGuid)
→ ≥4 EID1/EID5 pairs sharing one ProcessGuid
→ projected under dev_2adbb41a04a4
→ tenant preserved, no _pl identifier authority
```

Every boundary the Engine Foundation Program set out to establish for B5 —
`PROCESS_TERMINATION_OBSERVED` instead of `PROCESS_LIFETIME_UNKNOWN`, authoritative
`ProcessGuid` identity rather than PID heuristics, and `UtcTime → exit_time` rather than
`start_time` — is now demonstrated on real production evidence. No backfill, no
reconstruction, no heuristic matching.

## 2 · A MATCHER CONFLATION WAS CAUGHT (important for every past/future count)

A naive `<EventID>5</EventID>` match returns **249** for this endpoint. That number
conflates two providers:

- `Microsoft-Windows-IsolatedUserMode` EventID 5 — Secure Trustlet start, **not** a termination
- `Microsoft-Windows-Sysmon` EventID 5 — genuine ProcessTerminate → **17**

Any future EID5 count must filter on the Sysmon provider GUID
`{5770385f-c22a-43e0-bf4c-06f5698ffbd9}`, not on the bare EventID. Matcher validity was
otherwise controlled: EID1 = 636, EID12 = 28,776, and the ProcessGuid regex validated
against a known-present guid (193 hits) — so the 0/10 is real, not a query artifact.

## 3 · WHY THE 10 TARGET GUIDS ARE ABSENT — A 28-MINUTE COVERAGE GAP

Exact-value lookup: 0/10 in `edr_raw_events`, `xdr_ingest_raw_retained`,
`xdr_canonical_events`, `v2_shadow_observations`. `$in` over all 10 against
`process_exit` = 0; regex `9949e5f2-cfb6-6abb` against `process_exit` = 0.

The target guids' start-segments (`cfb6 … d018`) sit **before** the earliest EID5 in raw
(`d54c` ≈ UtcTime 15:17:21Z). So:

- **no Sysmon EID5 termination exists for the ~14:48–15:16Z UtcTime window**
- **every EID5 from 15:17:21Z onward is present and fully processed**

This is not a refusal (0 rejections for this endpoint), not a canonicalization /
identity / projection failure (proven working for all 17 that arrived), and not a wait
condition (the frontier is ~6h of event-time past the slot, and the immediate post-gap
neighbours are present). The 10 events never entered the delivered stream.

### Hypotheses for the gap — NOT verified, offered for the owner's decision
Stated as hypotheses only; nothing on the endpoint was inspected or touched.

1. **Collection start-point.** EID5 was newly enabled on the endpoint at ~14:48–14:50Z.
   The sensor's Sysmon channel reader would have been running with a subscription /
   bookmark established when EID5 did not yet exist in the config. The first EID5 it
   actually collected is 15:17:21Z — ~28 minutes later, consistent with a policy or
   channel-coverage refresh rather than with loss in transit.
2. **Direct-read vs collected stream.** The 10 guids were captured by the owner reading
   the Sysmon log directly on the host (the enablement script's own verification). Events
   visible to a direct read are not automatically inside the sensor's collected stream if
   they precede its coverage start point.
3. **Log position / rollover** at the moment the config changed.

Distinguishing these needs a READ-ONLY look on the endpoint — do the 10 guids still
exist in the local Sysmon log, and what does the sensor's channel state/bookmark say
about its EID5 start point. That is the owner's call, and out of scope for this
production-side check.

## 4 · WHAT THIS MEANS FOR B5 — OWNER DECISION REQUIRED

Two defensible readings, and I will not quietly pick one:

**Option 1 — close B5 on the 17 genuine EID5 (recommended).** The B5 acceptance
requirement was *"genuine endpoint-generated EID5 must reach canonical evidence and bind
correctly by authoritative ProcessGuid."* That is satisfied — by 17 real terminations
from DESKTOP-A9HGFJJ, delivered through the ordinary sensor path, with exit-time
provenance, ProcessGuid binding, ≥4 verified pairs and trajectory projection. The 10
guids were only ever the *sample* chosen as the proof set; they are not the capability.
Under this reading B5 = PASS, and the coverage gap is recorded as a separate finding.

**Option 2 — keep B5 BLOCKED on the original proof set.** If the acceptance gate is
defined strictly as *those 10 guids*, it cannot pass: they are absent and no honest
process can make them appear. Re-emitting or reconstructing them is exactly the
fabrication the program forbids, and would also destroy the "ordinary delivery path"
property that made the proof meaningful.

My recommendation is **Option 1 plus a named finding**: accept the engine proof on the
17, and open `B5-GAP-1 · Sysmon EID5 collection start-point coverage gap
(14:48–15:16Z, DESKTOP-A9HGFJJ)` as a separate, honest open item — because a sensor that
misses ~28 minutes of a newly-enabled event type after a config change is a real
coverage question worth understanding, independent of B5.

Until the owner rules, the status stays as the deployer returned it:

```
B5_EID5_END_TO_END = BLOCKED: target proof-set absent (engine PROVEN on 17 genuine EID5)
```

STOP FOR OWNER REVIEW. NO REMEDIATION PERFORMED.
