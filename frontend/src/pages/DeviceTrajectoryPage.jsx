// EDR Device Trajectory · Page shell (Left inventory · Center canvas · Right details)
// Owner rules #7-#19 realised here.  ONE canonical inventory drives all panels.
// Uses the PrivacyBrowse realistic scenario as an initial evidence set so
// analysts see a populated trajectory even before running real acquisitions.
import React, { useState, useMemo, useEffect } from "react";
import axios from "axios";

import EntityInventory       from "../components/edr/EntityInventory";
import TrajectoryCanvas      from "../components/edr/TrajectoryCanvas";
import ActivityDetails       from "../components/edr/ActivityDetails";
import VerdictExplainabilityCard from "../components/edr/VerdictExplainabilityCard";

const API = process.env.REACT_APP_BACKEND_URL;

// PrivacyBrowse realistic evidence (owner rule #17 · no invented facts).
// Extended with the analyst-supplied entity roster so the entity-per-row
// trajectory demonstrates the full workflow (winword→powershell→payload
// →network) alongside the PrivacyBrowse quarantine scenario.
const PRIVACYBROWSE_TIMELINE = {
  events: [
    // ── Baseline user session ─────────────────────────────────────
    { event_id: "evt-100", lane: "log",
      timestamp: "2026-06-15T14:30:00+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:30:00+00:00",
      last_seen:  "2026-06-15T14:30:00+00:00",
      process: "explorer.exe", parent_process: "userinit.exe",
      user: "skrasowski@WHS_ADMIN", host: "win10-user01.local",
      action: "execute",
      display_summary: "explorer.exe running (user session baseline)",
      provenance_chain: ["iue.intake:evt-100"],
    },
    // ── Word → PowerShell macro chain ──────────────────────────────
    { event_id: "evt-101", lane: "log",
      timestamp: "2026-06-15T14:30:30+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:30:30+00:00",
      last_seen:  "2026-06-15T14:30:30+00:00",
      process: "winword.exe", parent_process: "explorer.exe",
      user: "skrasowski@WHS_ADMIN", host: "win10-user01.local",
      action: "execute",
      display_summary: "winword.exe opened Q3-Report.docm",
      provenance_chain: ["iue.intake:evt-101"],
    },
    { event_id: "evt-102", lane: "log",
      timestamp: "2026-06-15T14:30:45+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:30:45+00:00",
      last_seen:  "2026-06-15T14:30:45+00:00",
      process: "powershell.exe", parent_process: "winword.exe",
      user: "skrasowski@WHS_ADMIN", host: "win10-user01.local",
      action: "execute",
      command_line: "powershell.exe -NoP -W hidden -Enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0AC4A",
      display_summary: "powershell.exe spawned by winword.exe (-Enc)",
      canonical_fields: {
        "canonical.process.pid": 5120,
      },
      provenance_chain: ["iue.intake:evt-102"],
    },
    // ── Payload drop + hash + execution ────────────────────────────
    { event_id: "evt-103", lane: "log",
      timestamp: "2026-06-15T14:31:00+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:31:00+00:00",
      last_seen:  "2026-06-15T14:31:00+00:00",
      process: "powershell.exe", parent_process: "winword.exe",
      user: "skrasowski@WHS_ADMIN",
      action: "created",
      file_ref: { path: "C:\\Users\\skrasowski\\AppData\\Local\\Temp\\payload.exe",
                    name: "payload.exe",
                    sha256: "9f2c3b5b6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718" },
      display_summary: "payload.exe dropped to %TEMP%",
      provenance_chain: ["iue.intake:evt-103"],
    },
    { event_id: "evt-104", lane: "log",
      timestamp: "2026-06-15T14:31:05+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:31:05+00:00",
      last_seen:  "2026-06-15T14:31:05+00:00",
      process: "payload.exe", parent_process: "powershell.exe",
      user: "skrasowski@WHS_ADMIN", action: "execute",
      display_summary: "payload.exe launched by powershell.exe",
      canonical_fields: { "canonical.process.pid": 6144 },
      provenance_chain: ["iue.intake:evt-104"],
    },
    { event_id: "evt-105", lane: "log",
      timestamp: "2026-06-15T14:31:10+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:31:10+00:00",
      last_seen:  "2026-06-15T14:31:10+00:00",
      process: "payload.exe", action: "written",
      file_ref: { path: "C:\\Users\\skrasowski\\AppData\\Local\\Temp\\payload.dll",
                    name: "payload.dll",
                    sha256: "aa11bb22cc33dd44ee55ff6677889900aabbccddeeff112233445566778899aa" },
      display_summary: "payload.dll written by payload.exe",
      provenance_chain: ["iue.intake:evt-105"],
    },
    // ── C2 beacon ─────────────────────────────────────────────────
    { event_id: "evt-106", lane: "log",
      timestamp: "2026-06-15T14:31:20+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:31:20+00:00",
      last_seen:  "2026-06-15T14:31:20+00:00",
      process: "payload.exe", action: "connect",
      destination: "https://bad-domain.com/c2",
      display_summary: "payload.exe → bad-domain.com/c2",
      canonical_fields: { "canonical.destination.port": 443 },
      provenance_chain: ["iue.intake:evt-106"],
    },
    { event_id: "evt-107", lane: "log",
      timestamp: "2026-06-15T14:31:25+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:31:25+00:00",
      last_seen:  "2026-06-15T14:31:25+00:00",
      process: "payload.exe", action: "connect",
      destination: "203.0.113.10:8443",
      display_summary: "payload.exe → 203.0.113.10:8443 (fallback C2)",
      canonical_fields: { "canonical.destination.port": 8443 },
      provenance_chain: ["iue.intake:evt-107"],
    },
    // ── PrivacyBrowse scenario (from handoff) ─────────────────────
    { event_id: "evt-001", lane: "log",
      timestamp: "2026-06-15T14:32:11+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:32:11+00:00",
      last_seen:  "2026-06-15T14:32:11+00:00",
      process: "privacybrowse.exe", parent_process: "sihost.exe",
      command_line: "\"C:\\Users\\PrivacyBrowse.exe\" --no-sandbox",
      user: "skrasowski@WHS_ADMIN",
      host: "win10-user01.local",
      action: "execute",
      display_summary: "privacybrowse.exe launched by sihost.exe",
      canonical_fields: {
        "canonical.process.pid":            4384,
        "canonical.process.integrity":      "Medium",
        "canonical.file.path":              "C:\\Users\\PrivacyBrowse.exe",
        "canonical.file.hash.sha1":         "f1b89473dc4be914f44193c3259ca7c93a6fe2ba",
        "canonical.file.hash.md5":          "50e207c52a0305495f9dcfb947ee116d",
        "canonical.file.signature_status":  "unsigned",
      },
      provenance_chain: ["iue.intake:evt-001", "iue.aggregator:evt-001"],
    },
    { event_id: "evt-002", lane: "log",
      timestamp: "2026-06-15T14:32:12+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:32:12+00:00",
      last_seen:  "2026-06-15T14:32:12+00:00",
      action: "detected", process: "privacybrowse.exe",
      display_summary: "Trojan.PhantomJack.1 detected in privacybrowse.exe",
      canonical_fields: {
        "canonical.detection.engine":  "NivXRay Forge EDR",
        "canonical.detection.family":  "Trojan.PhantomJack.1",
        "canonical.file.hash.sha1":    "f1b89473dc4be914f44193c3259ca7c93a6fe2ba",
      },
      provenance_chain: ["iue.intake:evt-002"],
    },
    { event_id: "evt-003", lane: "log",
      timestamp: "2026-06-15T14:32:13+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:32:13+00:00",
      last_seen:  "2026-06-15T14:32:13+00:00",
      action: "quarantine_failed", process: "privacybrowse.exe",
      file_ref: { path: "C:\\Users\\PrivacyBrowse.exe",
                    name: "PrivacyBrowse.exe" },
      display_summary: "Quarantine failed — file locked by parent process",
      provenance_chain: ["iue.intake:evt-003"],
    },
    { event_id: "evt-006", lane: "log",
      timestamp: "2026-06-15T14:31:30+00:00", timestamp_source: "canonical",
      first_seen: "2026-06-15T14:31:30+00:00",
      last_seen:  "2026-06-15T14:31:30+00:00",
      process: "sihost.exe", parent_process: "svchost.exe",
      user: "skrasowski@WHS_ADMIN", host: "win10-user01.local",
      action: "execute",
      display_summary: "sihost.exe running (session host)",
      provenance_chain: ["iue.intake:evt-006"],
    },
  ],
  untimed_events: [],
  lanes: ["log"],
  span_start: "2026-06-15T14:30:00+00:00",
  span_end:   "2026-06-15T14:32:20+00:00",
};

const SAMPLE_INTENT = {
  rule: "c2_beaconing",
  objective: "Command & Control Beaconing",
  confidence: 0.85,
  steps: [
    {intent: "Initial Access"},
    {intent: "Execution"},
    {intent: "Defense Evasion"},
    {intent: "Command and Control"},
  ],
};

export const DeviceTrajectoryPage = () => {
  const [inventory, setInventory]         = useState(null);
  const [verdict, setVerdict]             = useState(null);
  const [selectedEntity, setSelectedEntity] = useState(null);
  const [selectedEvent, setSelectedEvent]   = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const token = () => localStorage.getItem("nvx_token") || "";

  const loadInventory = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await axios.post(
        `${API}/api/activity/inventory`,
        { timeline: PRIVACYBROWSE_TIMELINE },
        { headers: { Authorization: `Bearer ${token()}` }},
      );
      setInventory(r.data);
    } catch (e) {
      setErr(e.response?.data?.detail?.error || e.message);
    } finally {
      setBusy(false);
    }
  };

  const computeVerdict = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await axios.post(
        `${API}/api/verdict/stage2/compute`,
        { timeline: PRIVACYBROWSE_TIMELINE, intent: SAMPLE_INTENT,
          v3x_verdict_card: { verdict: "suspicious", risk_score: 55 } },
        { headers: { Authorization: `Bearer ${token()}` }},
      );
      setVerdict(r.data.verdict_stage2);
    } catch (e) {
      setErr(e.response?.data?.detail?.error || e.message);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { loadInventory(); }, []);
  useEffect(() => { if (inventory && !verdict) computeVerdict(); }, [inventory]);

  const onEntitySelect = (e) => {
    setSelectedEntity(e); setSelectedEvent(null);
  };
  const onEventClick = (ev) => {
    setSelectedEvent(ev);
    // Also cross-select the parent entity so the left rail highlights.
    if (ev && inventory) {
      const ent = (inventory.entities?.[ev.kind] || [])
        .find((x) => x.entity_id === ev.entity_id);
      if (ent) setSelectedEntity(ent);
    }
  };
  const onVerdictRowClick = (row) => {
    if (!row?.event_ids?.length) return;
    // Pivot the canvas + right panel to the first cited event.
    const first = row.event_ids[0];
    const ev = (inventory?.events || []).find((e) => e.event_id === first);
    if (ev) onEventClick(ev);
  };

  return (
    <div data-testid="device-trajectory-page" style={styles.page}>
      <div style={styles.topbar}>
        <div style={styles.brand}>NivXRay Forge · Device Trajectory</div>
        <div style={styles.actions}>
          {err && <span style={styles.err}>err: {err}</span>}
          {busy && <span style={styles.busy}>working…</span>}
          <button data-testid="reload-inventory" style={styles.btn}
                   onClick={loadInventory}>reload inventory</button>
          <button data-testid="recompute-verdict" style={styles.btn}
                   onClick={computeVerdict}>recompute verdict</button>
        </div>
      </div>
      <div style={styles.grid}>
        <div style={styles.left}>
          <EntityInventory
            inventory={inventory}
            selectedEntityId={selectedEntity?.entity_id}
            onSelect={onEntitySelect}
          />
        </div>
        <div style={styles.center}>
          <TrajectoryCanvas
            inventory={inventory}
            verdict={verdict}
            selectedEntityId={selectedEntity?.entity_id}
            selectedEventId={selectedEvent?.event_id}
            onEventClick={onEventClick}
            onEntityClick={onEntitySelect}
          />
        </div>
        <div style={styles.right}>
          <div style={styles.rightTop}>
            <ActivityDetails
              inventory={inventory}
              verdict={verdict}
              selectedEntity={selectedEntity}
              selectedEvent={selectedEvent}
              onEventClick={onEventClick}
              onEntitySelect={onEntitySelect}
            />
          </div>
          <div style={styles.rightBottom}>
            <VerdictExplainabilityCard
              verdict={verdict}
              onRowClick={onVerdictRowClick}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

const styles = {
  page: {
    display: "flex", flexDirection: "column", height: "100vh",
    background: "#08080b", color: "#e0e0e5",
    fontFamily: "ui-monospace, monospace",
  },
  topbar: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    padding: "10px 20px", borderBottom: "1px solid #23232b",
    background: "#0d0d12",
  },
  brand: { fontSize: 14, letterSpacing: 2, fontWeight: 700 },
  actions: { display: "flex", gap: 10, alignItems: "center" },
  btn: {
    all: "unset", cursor: "pointer",
    padding: "6px 12px", border: "1px solid #23232b",
    borderRadius: 4, fontSize: 11, background: "#131318",
  },
  err:  { color: "#e04c60", fontSize: 11 },
  busy: { color: "#eab040", fontSize: 11 },
  grid: {
    display: "grid",
    gridTemplateColumns: "260px 1fr 380px",
    flex: 1,
    minHeight: 0,
  },
  left:   { overflow: "hidden", borderRight: "1px solid #23232b" },
  center: { overflow: "hidden" },
  right:  {
    borderLeft: "1px solid #23232b",
    display: "flex", flexDirection: "column", minHeight: 0,
  },
  rightTop:    { flex: 1, minHeight: 0, overflow: "auto",
                  borderBottom: "1px solid #23232b" },
  rightBottom: { padding: 12, background: "#0d0d12" },
};

export default DeviceTrajectoryPage;
