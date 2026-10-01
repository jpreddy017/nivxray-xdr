/**
 * Computers — the NivXForge fleet operations surface.
 *
 * Dense table → contextual pane → device workspace. Every column is a
 * recorded fact:
 *   · status carries the SERVER's basis sentence (CONNECTED requires
 *     authenticated telemetry inside the sensor's own cadence)
 *   · detections are real counts from the raw evidence store, produced
 *     for the whole grid in ONE aggregation — `0` means evaluated and
 *     genuinely zero, `NOT EVALUATED` is never rendered as zero
 *   · a field the enrolment record does not carry reads unavailable
 */
import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { KeyRound, RefreshCw, Search } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { getComputers } from "@/nivxforge/onboardingApi";
import { Ago, Kpi, NA, OpsTable, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";
import "@/nivxforge/nvf-ops.css";

const WINDOWS = [24, 24 * 7, 24 * 30];
const WINDOW_LABEL = { 24: "24h", 168: "7d", 720: "30d" };

const STATUS_GROUPS = [
  { key: "all", label: "All" },
  { key: "CONNECTED", label: "Connected" },
  { key: "ALIVE_NO_RECENT_TELEMETRY", label: "Alive · stale" },
  { key: "ENROLLED_NO_TELEMETRY", label: "No telemetry" },
  { key: "SILENT", label: "Silent" },
  { key: "REVOKED", label: "Revoked" },
];

function Count({ value, basis }) {
  if (value === null || value === undefined) {
    return <NA label="NOT EVALUATED" reason={basis} />;
  }
  return (
    <span className="mono" title={basis}
          style={{ color: value > 0 ? "var(--red)" : "var(--faint)",
                   fontWeight: value > 0 ? 700 : 400 }}>
      {value}
    </span>
  );
}

function ContextPane({ row, onClose }) {
  const nav = useNavigate();
  return (
    <aside className="ctx-pane" data-testid="edr-computer-pane">
      <div className="ph">
        <div>
          <div className="h" data-testid="edr-pane-hostname">
            {row.hostname || row.endpoint_id}
          </div>
          <div style={{ marginTop: 6 }}>
            <StateChip token={row.status} testid="edr-pane-status" />
          </div>
        </div>
        <button className="x" onClick={onClose}
                data-testid="edr-pane-close" title="Close">×</button>
      </div>

      <div className="ctx-sec">
        <div className="lbl">Why this status</div>
        <div className="basis" data-testid="edr-pane-status-basis">
          {row.status_basis}
        </div>
      </div>

      <div className="ctx-sec">
        <div className="lbl">Identity &amp; placement</div>
        <div className="kv">
          <span className="k">Endpoint</span>
          <span className="v">{row.endpoint_id}</span>
          <span className="k">Operating system</span>
          <span className="v">{row.os || <NA />}</span>
          <span className="k">OS version</span>
          <span className="v">{row.os_version || <NA label="NOT REPORTED" />}</span>
          <span className="k">Architecture</span>
          <span className="v">{row.architecture || <NA label="NOT REPORTED" />}</span>
          <span className="k">Group</span>
          <span className="v">{row.group || <NA label="NOT ASSIGNED" />}</span>
          <span className="k">Policy</span>
          <span className="v">{row.policy || <NA label="NOT ASSIGNED" />}</span>
          <span className="k">Sensor</span>
          <span className="v">{row.sensor_version || <NA label="NOT REPORTED" />}</span>
        </div>
      </div>

      <div className="ctx-sec">
        <div className="lbl">Protection</div>
        <div className="kv">
          <span className="k">Mode</span>
          <span className="v"><StateChip token={row.protection?.state} /></span>
          <span className="k">Prevention</span>
          <span className="v">
            {row.protection?.prevention_enabled ? "ENABLED" : "NOT ENABLED"}
          </span>
          {row.protection?.not_enforced?.length ? (
            <>
              <span className="k">Not enforced</span>
              <span className="v">
                <span className="chipline">
                  {row.protection.not_enforced.map((n) => (
                    <span className="chip" key={n}>{n}</span>))}
                </span>
              </span>
            </>
          ) : null}
        </div>
        <div className="basis" style={{ marginTop: 8 }}>
          {row.protection?.basis}
        </div>
      </div>

      <div className="ctx-sec">
        <div className="lbl">Telemetry</div>
        <div className="kv">
          <span className="k">Last telemetry</span>
          <span className="v"><Ago iso={row.telemetry?.last_telemetry_at} /></span>
          <span className="k">Last heartbeat</span>
          <span className="v"><Ago iso={row.telemetry?.last_heartbeat_at} /></span>
          <span className="k">Events received</span>
          <span className="v">{(row.telemetry?.event_count ?? 0).toLocaleString()}</span>
          <span className="k">Sensor queue</span>
          <span className="v">
            {row.telemetry?.queue_depth_at_sensor ?? <NA label="NOT REPORTED" />}
          </span>
          <span className="k">Cadence</span>
          <span className="v">
            {row.telemetry?.report_interval_seconds
              ? `${row.telemetry.report_interval_seconds}s`
              : <NA label="NOT DECLARED" />}
          </span>
        </div>
      </div>

      <div className="ctx-sec">
        <div className="lbl">Detections</div>
        <div className="kv">
          <span className="k">Window</span>
          <span className="v">
            <Count value={row.detections_24h} basis={row.detections_basis} />
            {" "}last {row.detections_window_hours}h
          </span>
          <span className="k">All time</span>
          <span className="v">
            <Count value={row.detections_total} basis={row.detections_basis} />
          </span>
          <span className="k">Most recent</span>
          <span className="v"><Ago iso={row.last_detection_at} /></span>
        </div>
        <div className="basis" style={{ marginTop: 8 }}>{row.detections_basis}</div>
      </div>

      <div className="ctx-sec" style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button className="btn mint" data-testid="edr-pane-open-device"
                onClick={() => nav(`/edr/computers/${encodeURIComponent(row.endpoint_id)}`)}>
          Open device
        </button>
        <button className="btn" data-testid="edr-pane-open-trajectory"
                onClick={() => nav(`/edr/computers/${encodeURIComponent(row.endpoint_id)}/trajectory`)}>
          Trajectory
        </button>
        <button className="btn" data-testid="edr-pane-open-commands"
                onClick={() => nav(`/edr/computers/${encodeURIComponent(row.endpoint_id)}/commands`)}>
          Commands
        </button>
      </div>
    </aside>
  );
}

export default function EdrComputersPage() {
  const nav = useNavigate();
  const [win, setWin] = useState(24);
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [q, setQ] = useState("");
  const [group, setGroup] = useState("all");
  const [sel, setSel] = useState(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let live = true;
    setData(null); setErr(null);
    getComputers(win)
      .then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) setErr(apiErrorText(e, "computers unavailable")); });
    return () => { live = false; };
  }, [win, tick]);

  const rows = useMemo(() => {
    const all = data?.computers || [];
    const needle = q.trim().toLowerCase();
    return all.filter((r) => {
      if (group !== "all" && r.status !== group) return false;
      if (!needle) return true;
      return [r.hostname, r.endpoint_id, r.os, r.group, r.policy,
              r.sensor_version]
        .some((v) => String(v || "").toLowerCase().includes(needle));
    });
  }, [data, q, group]);

  const counts = useMemo(() => {
    const all = data?.computers || [];
    const by = (s) => all.filter((r) => r.status === s).length;
    return {
      total: all.length,
      connected: by("CONNECTED"),
      noTelemetry: by("ENROLLED_NO_TELEMETRY") + by("NOT_ENROLLED"),
      silent: by("SILENT") + by("ALIVE_NO_RECENT_TELEMETRY"),
      detections: all.reduce((n, r) => n + (r.detections_24h || 0), 0),
    };
  }, [data]);

  const columns = [
    { key: "hostname", label: "Computer", width: "23%",
      render: (r) => (
        <div>
          <div className="host">{r.hostname || r.endpoint_id}</div>
          <div className="sub2">{r.endpoint_id}</div>
        </div>) },
    { key: "status", label: "Status", width: 168,
      render: (r) => <StateChip token={r.status} title={r.status_basis} /> },
    { key: "os", label: "OS", render: (r) => (
        <span className="mono">
          {r.os || <NA />}{r.os_version ? ` ${r.os_version}` : ""}
        </span>) },
    { key: "group", label: "Group",
      render: (r) => r.group || <NA label="UNASSIGNED" /> },
    { key: "policy", label: "Policy",
      render: (r) => r.policy || <NA label="UNASSIGNED" /> },
    { key: "protection", label: "Protection",
      sortValue: (r) => r.protection?.state,
      render: (r) => <StateChip token={r.protection?.state}
                                title={r.protection?.basis} /> },
    { key: "sensor_version", label: "Sensor",
      render: (r) => r.sensor_version
        ? <span className="mono">{r.sensor_version}</span>
        : <NA label="NOT REPORTED" /> },
    { key: "events", label: "Events", cls: "num",
      sortValue: (r) => r.telemetry?.event_count || 0,
      render: (r) => (r.telemetry?.event_count ?? 0).toLocaleString() },
    { key: "detections_24h", label: `Det · ${WINDOW_LABEL[win] || `${win}h`}`,
      cls: "num", title: "Detection matches inside the selected window",
      render: (r) => <Count value={r.detections_24h}
                            basis={r.detections_basis} /> },
    { key: "detections_total", label: "Det · total", cls: "num",
      render: (r) => <Count value={r.detections_total}
                            basis={r.detections_basis} /> },
    { key: "last_seen", label: "Last seen",
      render: (r) => <Ago iso={r.last_seen} /> },
  ];

  return (
    <NivXForgeConsole activeTab="computers">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Fleet operations</span>
          <h1 className="ttl">Computers</h1>
          <div className="sub">
            {data?.status_contract
              || "CONNECTED requires authenticated endpoint telemetry inside "
                 + "the sensor's own declared cadence."}
          </div>
        </div>
        <div className="spacer" />
        <div className="ops-actions">
          <button className="btn" onClick={() => setTick((t) => t + 1)}
                  data-testid="edr-computers-refresh">
            <RefreshCw size={11} /> Refresh
          </button>
          <button className="btn mint" data-testid="edr-computers-add-device"
                  onClick={() => nav("/edr/computers/add")}>
            <KeyRound size={11} /> Add device
          </button>
        </div>
      </div>

      {err ? <Refusal title="Fleet unavailable" body={err}
                      testid="edr-computers-refusal" /> : null}

      {data ? (
        <div className="kpi-rail" data-testid="edr-computers-kpis">
          <Kpi label="Computers" value={counts.total} testid="edr-kpi-total" />
          <Kpi label="Connected" value={counts.connected} tone="mint"
               testid="edr-kpi-connected" />
          <Kpi label="No telemetry" value={counts.noTelemetry} tone="amber"
               testid="edr-kpi-no-telemetry" />
          <Kpi label="Silent / stale" value={counts.silent} tone="red"
               testid="edr-kpi-silent" />
          <Kpi label={`Detections · ${WINDOW_LABEL[win] || `${win}h`}`}
               value={counts.detections} tone="red"
               testid="edr-kpi-detections" />
        </div>
      ) : null}

      <div className="ops-split">
        <div className="ops-main">
          <div className="ops-toolbar">
            <div className="ops-search">
              <Search size={11} color="var(--faint)" />
              <input value={q} onChange={(e) => setQ(e.target.value)}
                     placeholder="hostname · endpoint id · policy · sensor"
                     data-testid="edr-computers-search" />
            </div>
            <div className="seg" data-testid="edr-computers-status-filter">
              {STATUS_GROUPS.map((g) => (
                <button key={g.key} data-on={String(group === g.key)}
                        data-testid={`edr-status-${g.key}`}
                        onClick={() => setGroup(g.key)}>{g.label}</button>
              ))}
            </div>
            <div className="seg" data-testid="edr-detection-window">
              {WINDOWS.map((h) => (
                <button key={h} data-on={String(win === h)}
                        data-testid={`edr-window-${h}`}
                        onClick={() => setWin(h)}>
                  {WINDOW_LABEL[h] || `${h}h`}
                </button>
              ))}
            </div>
            <div className="ops-count" data-testid="edr-computers-count">
              {rows.length} of {data?.count ?? 0} · detections counted over{" "}
              {WINDOW_LABEL[win] || `${win}h`}
            </div>
          </div>

          {!data && !err ? <Skeleton rows={10} testid="edr-computers-loading" /> : null}
          {data && rows.length === 0 ? (
            <div className="x-empty" data-testid="edr-computers-empty">
              No computer matches this filter. {data.count} computer(s) are
              enrolled in this customer.
            </div>
          ) : null}
          {data && rows.length > 0 ? (
            <OpsTable columns={columns} rows={rows} testid="edr-computers-table"
                      rowKey={(r) => r.endpoint_id}
                      selectedKey={sel?.endpoint_id}
                      initialSort={{ key: "last_seen", dir: -1 }}
                      onSelect={(r) => setSel(
                        (p) => (p?.endpoint_id === r.endpoint_id ? null : r))} />
          ) : null}

          {data ? (
            <div className="basis" style={{ marginTop: 10 }}
                 data-testid="edr-detection-method">
              {data.detection_count_method}
            </div>
          ) : null}
        </div>
        {sel ? <ContextPane row={sel} onClose={() => setSel(null)} /> : null}
      </div>
    </NivXForgeConsole>
  );
}
