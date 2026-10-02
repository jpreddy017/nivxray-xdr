import React, { Suspense, lazy, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import EdrDeviceTrajectoryPage from "@/nivxforge/trajectory/EdrDeviceTrajectoryPage";
import { E3_DT_CONTRACT_PREVIEW } from "./flags";
import { e3 } from "./e3Api";
import { PAL } from "./model";
import { FONT, ui } from "./ui";

const E3TrajectoryPage = lazy(() => import("./E3TrajectoryPage"));

// Flag OFF (default, every E1/prod build): renders the existing live page exactly as before.
export default function DeviceTrajectoryEntry(props) {
  if (!E3_DT_CONTRACT_PREVIEW) return <EdrDeviceTrajectoryPage {...props} />;
  return <SourceSwitch {...props} />;
}

function SourceSwitch(props) {
  const [params, setParams] = useSearchParams();
  const source = params.get("source") === "e3" ? "e3" : "live";
  const sid = params.get("scenario") || "office_chain";
  const [list, setList] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    if (source === "e3" && !list) e3.scenarios().then((r) => setList(r.scenarios)).catch((e) => setErr(e.message));
  }, [source, list]);
  const set = (k, v) => { const n = new URLSearchParams(params); n.set(k, v); setParams(n, { replace: true }); };
  const scenario = list?.find((x) => x.scenario_id === sid);
  const seg = (on) => ({ ...ui.btn, ...(on ? ui.btnOn : {}) });

  return (
    <div style={{ fontFamily: FONT }}>
      <div data-testid="data-source-control" style={{ display: "flex", gap: 8, alignItems: "center", padding: "8px 12px", background: PAL.panel,
        borderBottom: `1px solid ${PAL.gridStrong}`, color: PAL.text, fontSize: 12 }}>
        <span style={{ color: PAL.muted, letterSpacing: 1, fontSize: 11 }}>DATA SOURCE</span>
        <button data-testid="source-live" aria-pressed={source === "live"} style={seg(source === "live")} onClick={() => set("source", "live")}>Live (E1 evidence)</button>
        <button data-testid="source-e3" aria-pressed={source === "e3"} style={seg(source === "e3")} onClick={() => set("source", "e3")}>E3 contract preview</button>
        {source === "e3" && (
          <select data-testid="scenario-picker" value={sid} onChange={(e) => set("scenario", e.target.value)} style={{ ...ui.btn, background: PAL.bg }}>
            {(list || []).map((x) => <option key={x.scenario_id} value={x.scenario_id}>{x.scenario_id} · {x.label}</option>)}
          </select>
        )}
        {source === "e3" && <span style={{ color: PAL.amber }}>Not live data</span>}
      </div>
      {source === "live" && <EdrDeviceTrajectoryPage {...props} />}
      {source === "e3" && err && <div data-testid="e3-source-error" style={{ color: PAL.amber, padding: 16 }}>E3 contract preview unavailable: {err}</div>}
      {source === "e3" && !err && !scenario && <div style={{ color: PAL.muted, padding: 16 }}>{list ? `Unknown scenario ${sid}` : "Loading scenarios…"}</div>}
      {source === "e3" && scenario && (
        <Suspense fallback={<div style={{ color: PAL.muted, padding: 16 }}>Loading E3 preview…</div>}>
          <E3TrajectoryPage key={sid} scenario={scenario} />
        </Suspense>
      )}
    </div>
  );
}
