# ADR-0010t · P2 UI Slice · Behavioral Evidence Timeline — 🟢 GREEN

**Status**: 🟢 PASS · Behavioral UI shipped (2026-08-12 · Session-19)
**Scope**: Read-only Workspace panel projecting the Slice-1/2/3 behavioral evidence. **No new MITRE inference, no verdict logic, no IKG persistence.**
**Companion**: ADR-0010q (Slice-1) · ADR-0010r (Slice-2) · ADR-0010s (Slice-3) · UI-DEF-02 (authoritative MITRE surface).

## 1. Files touched

```
frontend/src/components/investigation/BehavioralTimeline.jsx   (new · projection component)
frontend/src/pages/WorkspacePage.jsx                            (+2 lines · import + mount below Attack Chain)
backend/tests/canonical/ssot/test_ssot_isolation.py             (allow-list entry)
memory/adr/0010t-p2-ui-slice-behavioral-timeline.md             (this file)
```

No backend files touched.

## 2. UI contract (locked)

**Position**: Directly below the existing 14-tactic Attack Chain (`data-testid="attack-trajectory-section"`). Never replaces it, never re-implements MITRE inference.

**Inputs**:
- Sysmon Event XML paste-in (`textarea[data-testid="sysmon-xml-input"]`) + Ingest button.
- EVTX file drop (`label[data-testid="evtx-drop"]`) — reads bytes, base64-encodes, POSTs to `/api/behavioral/sysmon/evtx`.
- Both requests pass the current analyst's `Bearer` token via `authHeaders()`.

**Rendered rows**:
- **[E1] Process Create** — image · PID · evidence_ref chip.
- **[E3] Network Connect** — image → destination_ip:port · correlation-state chip (`RESOLVED` / `UNRESOLVED_DANGLING` / `AMBIGUOUS_PID_ONLY`) · dedup badge `×N · dedup` (only when count > 1) · destination_class · evidence_ref.

**Evidence Inspector** (click any row):
- **Process** — image, ProcessGuid, ProcessId (+ parent block for E1).
- **Network** — protocol, initiated, source, destination, dest hostname, dest class (E3 only).
- **Correlation** — coloured chip + `Linked to (E1)` evidence_ref (E3 only).
- **Evidence** — evidence_ref, count, first_seen, last_seen, raw_refs (all preserved from dedup).
- **Advisory fields · not authoritative** — explicit block for `destination_hostname` etc. with `derivation: sysmon_reverse_lookup`.

**Authoritative MITRE footer** — pill listing the technique ids from `response.mitre_technique_ids` with the explicit disclaimer *"These techniques appear in the 14-tactic Attack Chain above. This timeline does NOT infer techniques on its own."*

## 3. UI-Truth discipline

The component never renders a technique id from any source other than the backend's `mitre_technique_ids` array (which comes from the UI-DEF-02 authoritative surface via Event 1 command lines only). Event 3 alone produces zero techniques on the wire, and the UI faithfully renders that. PID-only correlation renders `AMBIGUOUS_PID_ONLY` (amber border) — never promoted to a resolved link.

## 4. Live proof

Screenshot at `/tmp/behavioral_timeline_authed.png` demonstrates every owner-required element:

- Existing 14-tactic Attack Chain unchanged above.
- New **Behavioral Evidence Timeline** panel visible with header + subtitle.
- Summary strip `E1·1  E3·2  MITRE·3`.
- **[E1] Process Create · C:\Windows\System32\certutil.exe · PID 4242 · e16d4ff85e82**.
- **[E3] Network Connect · certutil.exe → 198.51.100.20:80 · ● RESOLVED · ×2 · dedup · external · 4b593a29e3a2**.
- Inspector open, showing:
  - Correlation `● RESOLVED` · Linked to (E1) `e16d4ff85e82`
  - Evidence: count=2 · first_seen 2026-08-12T10:00:01Z · last_seen 2026-08-12T10:00:05Z · raw_refs `4b593a29e3a2, be1cd704786e`
  - Advisory `destination_hostname → dropper.example.test (derivation: sysmon_reverse_lookup)`
- MITRE handoff footer: `T1105 · T1140 · T1218` with the disclaimer above.

## 5. Test / regression state

- `test_ui_def_02_convergence.py`     — 8/8 PASS
- `test_p2_sysmon_adapter.py`         — 7/7 PASS
- `test_p2_slice2_sysmon_event3.py`   — 16/16 PASS
- `test_p2_slice2_extended_contract.py` — 14/14 PASS
- `test_p2_slice3_evtx_transport.py`  — 10/10 PASS
- `test_workspace_isolation_guard.py` — PASS
- `test_ssot_isolation.py`            — PASS
- Backend regression suites unchanged.

## 6. What Slice-UI does NOT do

- No new MITRE mapping.
- No new ATT&CK rules.
- No new verdict scoring.
- No IKG persistence.
- No new backend endpoints.
- No modification to `TrajectoryDiagram` (the 14-tactic Attack Chain stays as ADR-0010m/p defined).
- No changes to `services/die/*` or `analysis_core.py`.

## 7. Standing down

UI slice closed. Sequence remaining:

```
Slice-1 Event 1        ✅
Slice-2 Event 3        ✅
Slice-3 EVTX transport ✅
Slice-UI Timeline      ✅  (this ADR)
       ↓ (await owner)
Slice-4 Event 22 DNS   ⏸
Slice-5 Event 11 File  ⏸
IKG persistence        ⏸
```
