# NivXRay v2 · Release Roadmap
## Release-Gated Delivery Plan (Feb-2026, locked)

Every release must pass its gate before the next begins. Scope
does not migrate between releases — new asks land in a
higher-numbered release.

---

## R1 · Device Trajectory MVP · **SHIPPING**

Delivered:
- CEM v1 versioned schema + entity-aware Evidence model
- Shadow adapter + semantic parser (18 deterministic rules)
- POST /api/v2/cases/{id}/observations
- GET  /api/v2/cases/{id}/trajectory/device
- DetectFlow swimlane UI (5 lanes, cyan-teal, Chivo 900)
- Real DFIR seed (Bumblebee → AdaptixC2 → Akira)
- Feature-flag isolation (TRAJECTORY_ENGINE, CASE_ENGINE, ADAPTERS)
- OpenAPI diff + PIC v2 + versioning tests
- 72/72 tests green · zero RC5 files touched

Gate:
- [x] Full test suite green
- [x] RC5 byte-parity verified (Golden Corpus fingerprint)
- [x] TRAJECTORY_ENGINE flag toggle verified end-to-end
- [x] Public Interface Contract v2 updated
- [x] Preview smoke: 53 events, all 5 lanes populated with MITRE tags
- [ ] Git tag `v2-trajectory-mvp`
- [ ] Production redeploy

---

## R1.1 · Analyst Experience (Phase 3g)

Bundle of trajectory-UX refinements:
- MITRE overlay chips on every event node + hover card citing rule id
- Filter chip row: verdict × MITRE tactic × lane
- Case selector at top of trajectory
- "New since last view" badge (uses provenance.ingested_at)
- Evidence confidence badge (High / Medium / Low) next to each chip
- GET /api/v2/coverage/mitre — technique-count coverage endpoint
- Rule provenance hover card

Gate: all above shipped + regression green + real screenshot captured
on the DFIR case + confidence badges visible on hover.

---

## R1.2 · Investigation Navigation

- v2/graph/process_tree.py — deterministic parent/child chains
- GET /api/v2/cases/{id}/tree/process/{iid}
- New route /v2/tree/:caseId/:processIid
- Selecting a process on Trajectory → highlights its lifetime spine

Gate: ancestry renders on the DFIR case + selecting from trajectory
opens the tree with the process pre-selected.

---

## R2 · Evidence Platform (Phase 4a — Artifact Store)

- Immutable, sha256-addressed artifact store
- Stable artifact_id referenceable from trajectory / summary / reports
- Snapshot endpoint set (POST /snapshots/capture, GET /snapshots/{sha})
- Provenance chain per artifact

Gate: capturing a snapshot on a case produces a byte-stable sha256;
referencing the same artifact from two trajectory events resolves
to one stored object.

---

## R3 · Quality & Benchmarking

Golden Trajectory Corpus — scored, not just added:

| Metric | Target |
|---|---|
| Timeline completeness | ≥ 95% of expected events present |
| Entity extraction accuracy | ≥ 90% |
| ATT&CK coverage | ≥ 85% of expected TIDs |
| False-positive rule mappings | 0 |
| Missing-event rate | ≤ 5% |
| Parse latency p95 | ≤ 5 ms |

Includes 5 canonical chains: Bumblebee/Akira · Carbanak · FIN7 ·
Volt Typhoon · MuddyWater.

Gate: pytest tests/golden_trajectory/ green with above thresholds
frozen in baselines/trajectory_baseline.json.

---

## R4 · Investigation Intelligence (Deterministic Summary)

Rule-based narrative walker over the trajectory:

Trajectory → Entities → Actions → MITRE → Evidence → Narrative

Every sentence in the summary must cite one or more evidence_ids.
No AI in the fact path. Copilot (opt-in per case) may rephrase but
must preserve every citation.

Gate: POST /api/v2/cases/{id}/summary returns deterministic text
that is byte-identical across runs for the same case state.

---

## Architectural invariant · Canonical Event (Round-8 amendment)

Adopted as the single source of truth:

    {
      "id":         "...",
      "timestamp":  "...",
      "entity":     "...",
      "action":     "...",
      "target":     "...",
      "evidence":   [...],
      "mitre":      [...],
      "confidence": "high|medium|low",
      "provenance": {...},
      "artifacts":  [...]
    }

This one event model powers Trajectory · Process Tree · Summary ·
Reports · STIX export · Cross-device pivot — no reparsing anywhere.

---

## Explicit non-goals (governance-locked)

- Live-response shell into endpoints
- Real-time telemetry collection
- Vendor-vs-vendor benchmarking
- Any UI mimicry of commercial products
- AI in the fact path
