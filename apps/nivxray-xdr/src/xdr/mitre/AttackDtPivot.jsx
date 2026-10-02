// E3 → E1 REVIEW (flag VITE_E3_ATTACK_PIVOT): HeatMap-side pivot into Device Trajectory. Adds navigation only; no coverage semantics change.
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "@/lib/api";

const dtHref = (device, eventIid) => `/edr/device-trajectory?device=${encodeURIComponent(device)}&event=${encodeURIComponent(eventIid)}`;
const box = { padding: "8px 10px", background: "var(--nx-surf-inset)", border: "1px solid var(--nx-bd-quiet)", borderRadius: 6, fontSize: 12 };

export function DtContextBanner({ params }) {
  if (params.get("from") !== "device-trajectory") return null;
  const t0 = Number(params.get("t0")), t1 = Number(params.get("t1")), iso = (v) => (v ? new Date(v).toISOString().slice(0, 16).replace("T", " ") : "—");
  return (
    <div data-testid="xdr-mitre-dt-context" style={{ ...box, margin: "0 0 12px", color: "var(--nx-text)" }}>
      From Device Trajectory · device <b>{params.get("device") || "—"}</b> · {iso(t0)} – {iso(t1)} UTC · technique <b>{params.get("technique")}</b>.
      Coverage below is tenant-wide; the device and time range are context only.
    </div>
  );
}

export function OpenInDeviceTrajectory({ technique }) {
  const [res, setRes] = useState(null);
  const navigate = useNavigate();
  useEffect(() => {
    let live = true;
    setRes(null);
    api.get(`/edr/attack/techniques/${encodeURIComponent(technique)}/devices`).then(({ data }) => live && setRes(data)).catch(() => live && setRes({ devices: [] }));
    return () => { live = false; };
  }, [technique]);
  return (
    <div data-testid="xdr-mitre-open-dt">
      <div style={{ fontSize: 10, fontWeight: 800, textTransform: "uppercase", letterSpacing: 0.5, color: "var(--nx-muted)", marginBottom: 8 }}>
        Open in Device Trajectory <span style={{ textTransform: "none", fontWeight: 500 }}>— observed technique is not a confirmed attack</span></div>
      {!res ? <div style={box}>Loading devices…</div> : !res.devices.length ? <div data-testid="xdr-mitre-open-dt-empty" style={box}>No device events carry this technique.</div>
        : res.devices.map((d) => (
          <div key={d.device} style={{ ...box, marginBottom: 6 }}>
            <b>{d.hostname}</b> <span style={{ color: "var(--nx-muted)" }}>{d.device}</span>
            {d.events.map((e) => (
              <button key={e.observation_id} type="button" data-testid={`xdr-mitre-open-dt-event-${e.observation_id}`} disabled={!e.event_iid}
                onClick={() => navigate(dtHref(d.device, e.event_iid))}
                style={{ display: "block", width: "100%", textAlign: "left", marginTop: 4, background: "none", border: 0, color: "var(--nx-purple)", cursor: "pointer", fontSize: 12 }}>
                {e.at} · {e.detection} · {e.techniques.join(", ")} ↗</button>))}
          </div>))}
    </div>
  );
}
