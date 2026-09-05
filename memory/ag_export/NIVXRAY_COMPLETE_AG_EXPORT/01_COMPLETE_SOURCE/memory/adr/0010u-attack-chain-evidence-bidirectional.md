# ADR-0010u · P2 UI-Slice-2 · Attack Chain ↔ Behavioral Evidence Bidirectional Link — 🟢 GREEN

**Status**: 🟢 PASS (2026-08-12 · Session-19)
**Scope**: Frontend-only click-through link between the existing 14-tactic Attack Chain and the Behavioral Evidence Timeline. **No backend touched.** No new MITRE inference, no new verdict logic, no IKG persistence.

## 1. Files touched

```
frontend/src/components/investigation/BehavioralTimeline.jsx   (technique lookup maps + inbound MITRE listener + outbound Evidence dispatch + clickable MITRE chips)
frontend/src/components/investigation/TrajectoryDiagram.jsx    (node.techId propagation + inbound Evidence listener + amber "linked" ring + outbound MITRE dispatch)
backend/tests/canonical/ssot/test_ssot_isolation.py             (allow-list entry)
memory/adr/0010u-attack-chain-evidence-bidirectional.md         (this file)
```

## 2. Mechanism

Lightweight browser `CustomEvent` bus on `window`:

| Event | Direction | Payload | Producer | Consumer |
|---|---|---|---|---|
| `nivx:mitre-selected`      | forward (chain → timeline) | `{technique_id: "Txxxx"}` | Attack Chain node click · MITRE-handoff chip click | Behavioral Timeline |
| `nivx:evidence-selected`   | reverse (timeline → chain) | `{technique_ids: ["Txxxx", …]}` | E1 / E3 row click | Attack Chain |

No shared Redux, no context plumbing — the panels remain fully decoupled.

## 3. Technique ↔ Evidence lookup (client-side, projection only)

`useMemo` builds four maps from the same `per_event_mitre[]` the backend already emits:
- `e1RefToTechs`  — per-E1 evidence_ref → Set of technique ids.
- `e3RefToTechs`  — per-E3 evidence_ref → Set of technique ids **only via RESOLVED correlation**. UNRESOLVED_DANGLING and AMBIGUOUS_PID_ONLY rows deliberately receive an empty set — the UI must not fabricate a link where the backend has none.
- `techToE1Refs` / `techToE3Refs` — inverse maps.

**UI-Truth locked**: no client-side technique inference. Every technique id displayed on a row is echoed from `response.per_event_mitre[i].techniques[*].id` — the UI-DEF-02 authoritative surface.

## 4. Visual language

- **Selected technique** (forward): amber-boxed MITRE chip in the handoff footer + amber outline on the supporting E1/E3 rows. `clear` link resets.
- **Selected evidence** (reverse): amber inset shadow on the row + amber dashed ring around the corresponding Attack Chain node (via `linkedTechniqueIds` Set → SVG `<rect stroke="#fbbf24" strokeDasharray="4 3">`).
- Existing pan / zoom / drag preserved unchanged.
- Existing NodeInspector still opens on node click (the new event dispatch runs alongside).

## 5. Live proof

Two screenshots captured on the preview URL — see `/tmp/bidirectional_forward.png` and `/tmp/bidirectional_reverse.png`. Both show:
- E1 row explicitly declaring `supports · T1105, T1140, T1218`.
- E3 row explicitly declaring `via E1 · T1105, T1140, T1218`.
- `● RESOLVED` chip, `4b593a29e3a2` evidence_ref.
- Full Evidence Inspector: `count=1 · first_seen · last_seen · raw_refs · Linked to (E1) e16d4ff85e82`.
- Authoritative MITRE handoff row with clickable chips + amber-selected `T1105`.
- Explicit disclaimer: *"Click a technique above → supporting E1/E3 rows highlight. Click an evidence row → its technique(s) broadcast to the Attack Chain."*

## 6. What this slice does NOT do

- No new MITRE mapper.
- No new ATT&CK rules.
- No new verdict scoring.
- No new evidence relationships invented client-side.
- No changes to `services/die/*`, `analysis_core.py`, `operations.py`, or any backend router.
- No modification of the 14-tactic Attack Chain semantics — it still consumes `object.mitre` from the authoritative surface. The new `techId` field is a client-side alias for the existing technique id already in the node.
- No effect on IKG, EVTX, or any P2 backend slice.

## 7. Regression state

Backend suite unchanged (last combined pass: 104 / 104 · 2 skip · 0 fail). Frontend renders without console errors. Both custom events fire correctly on the live preview (confirmed by the second screenshot's `E3 row clicked · reverse direction event dispatched` console log).

## 8. Standing down

Slice-UI-2 closed. Locked sequence remaining:

```
Slice-1 Event 1        ✅
Slice-2 Event 3        ✅
Slice-3 EVTX transport ✅
Slice-UI Timeline      ✅
Slice-UI-2 Bidirectional ✅  (this ADR)
       ↓ (await owner)
Slice-4 Event 22 DNS   ⏸
Slice-5 Event 11 File  ⏸
IKG persistence        ⏸
```
