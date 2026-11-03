/**
 * NivXForge EDR · File Trajectory (SHA-256).
 *
 * Laid out the way Cisco Secure Endpoint lays out File Trajectory, because the
 * shape carries the investigation: VISIBILITY (first/last seen) → ENTRY POINT
 * (which endpoint saw it first) → FILE DETAILS → the TRAJECTORY GRAPHIC
 * (computers down the side, time across the top, one glyph per sighting, a
 * detail pane on the right) → EVENT HISTORY.
 *
 * Where AMP shows a field this substrate does not collect — size, real type,
 * signer, disposition, network profile, and created/moved/quarantined events —
 * the gap is stated. An empty field an analyst reads as "clean" is worse than
 * a named absence.
 *
 * A sighting is always placed at `observed_at`, never at ingest time: the two
 * fall on different UTC days whenever delivery crosses midnight.
 */
import { ChevronDown, ChevronRight, FileText, Loader2, Search } from "lucide-react";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { fileSightings } from "@/nivxforge/edrApi";

const SHA256 = /^[0-9a-f]{64}$/i;
const ms = (iso) => (iso ? Date.parse(iso) : NaN);

const utc = (iso, len = 19) => {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, len) + "Z"; }
  catch { return String(iso); }
};

/** The link that carries this sighting into the device canvas, at its time. */
export function sightingHref(sha256, s, customer) {
  if (!s?.endpoint_id || !s?.observed_at) return null;
  const q = new URLSearchParams({ device: s.endpoint_id, at: s.observed_at, sha256 });
  if (customer) q.set("tenant", customer);
  return `/edr/device-trajectory?${q.toString()}`;
}

// Polling saw a process; polling cannot see a launch. The label says what the
// sensor can actually support, so a count never reads as "ran 797 times".
const ACTIVITY_LABEL = {
  PROCESS_OBSERVED: "Process observed",
  CREATE: "File created", MODIFY: "File modified", DELETE: "File deleted",
};
const label = (a) => ACTIVITY_LABEL[a] || a || "—";

// Which payload field named the path, and therefore what the digest is OF.
const PATH_SOURCE = {
  image_path: "image_path — /proc/<pid>/exe, so the digest is the executed image",
  image: "image — the process image name reported by the sensor",
  path: "path — the file the sensor found in a watched directory, hashed there",
};


const Facts = ({ items, testid }) => (
  <div data-testid={testid} style={{ display: "flex", flexWrap: "wrap", gap: "16px 34px" }}>
    {items.filter(Boolean).map(([k, v, tid]) => (
      <span key={k} style={{ display: "flex", flexDirection: "column", gap: 3 }}>
        <span style={{ fontSize: 10.5, letterSpacing: ".06em",
                       textTransform: "uppercase", opacity: 0.6 }}>{k}</span>
        <span style={{ fontSize: 13 }} data-testid={tid}>{v}</span>
      </span>
    ))}
  </div>
);

const Panel = ({ title, sub, children, testid }) => (
  <section data-testid={testid} style={{ marginTop: 22 }}>
    <h2 style={{ fontSize: 15, fontWeight: 700, margin: "0 0 4px" }}>{title}</h2>
    {sub && <p style={{ fontSize: 12, opacity: 0.65, margin: "0 0 10px", maxWidth: 900 }}>{sub}</p>}
    {children}
  </section>
);

/* ── the trajectory graphic: computers down, time across ─────────────────── */

// Dense lanes overlap: marks nearer than one mark wide cannot all be clicked,
// so they are grouped and the group says how many sightings it stands for.
// Nothing is dropped — the full list stays in Event history.
function groupLane(sightings, at) {
  const out = [];
  for (const s of sightings) {
    const x = at(s.observed_at);
    const last = out[out.length - 1];
    if (last && Math.abs(last.x - x) < 1.1) last.items.push(s);
    else out.push({ x, lead: s, items: [s] });
  }
  return out;
}


function Graphic({ data, selected, onSelect }) {
  const eps = data.endpoints || [];
  const [t0, t1] = useMemo(() => {
    // The axis spans the KNOWN range of this digest, not just the slice of
    // sightings this read returned — otherwise a capped read would redraw the
    // file's history as starting later than Visibility says it did.
    const all = eps.flatMap((e) => [
      ...(e.sightings || []).map((s) => ms(s.observed_at)),
      ms(e.first_observed), ms(e.last_observed),
    ]).filter(Number.isFinite);
    if (!all.length) return [0, 1];
    const lo = Math.min(...all), hi = Math.max(...all);
    return lo === hi ? [lo - 1800000, hi + 1800000] : [lo, hi];
  }, [eps]);

  const drawn = eps.reduce((n, e) => n + (e.sightings || []).length, 0);
  const total = eps.reduce((n, e) => n + (e.sighting_count || 0), 0);
  // A ringed mark the analyst cannot find is a promise the graphic did not keep:
  // day-shifted sightings older than the marks drawn are named, not implied.
  const shiftedDrawn = eps.reduce(
    (n, e) => n + (e.sightings || []).filter((s) => s.ingest_day_differs).length, 0);
  const shiftedOffAxis = Math.max(0, (data.day_shifted_sightings || 0) - shiftedDrawn);

  const at = (iso) => {
    const v = ms(iso);
    if (!Number.isFinite(v)) return 0;
    return Math.max(0, Math.min(100, ((v - t0) / (t1 - t0)) * 100));
  };

  return (
    <div data-testid="edr-files-graphic"
         style={{ border: "1px solid rgba(128,128,128,.22)", borderRadius: 10,
                  overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                    padding: "6px 12px", fontSize: 11, opacity: 0.7,
                    borderBottom: "1px solid rgba(128,128,128,.18)" }}>
        <span data-testid="edr-files-graphic-t0">{utc(new Date(t0).toISOString(), 16)}</span>
        <span style={{ flex: 1, textAlign: "center", letterSpacing: ".06em",
                       textTransform: "uppercase", fontSize: 10 }}>
          observed time (UTC)
        </span>
        <span data-testid="edr-files-graphic-t1">{utc(new Date(t1).toISOString(), 16)}</span>
      </div>

      {eps.map((ep, i) => (
        <div key={ep.endpoint_id || i} data-testid={`edr-files-lane-${i}`}
             data-endpoint={ep.endpoint_id}
             style={{ display: "grid", gridTemplateColumns: "260px 1fr",
                      borderTop: i ? "1px solid rgba(128,128,128,.14)" : "none" }}>
          <div style={{ padding: "10px 12px", minWidth: 0,
                        borderRight: "1px solid rgba(128,128,128,.18)" }}>
            <div style={{ fontSize: 12.5, fontWeight: 600, overflow: "hidden",
                          textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                 title={ep.hostname || ep.endpoint_id}>
              {ep.hostname || ep.endpoint_id}
            </div>
            <div className="mono" style={{ fontSize: 10.5, opacity: 0.6 }}>
              {ep.sighting_count} sightings · {ep.paths.length} path
              {ep.paths.length === 1 ? "" : "s"}
            </div>
            {(data.entry_points || []).some((e) => e.endpoint_id === ep.endpoint_id) && (
              <div data-testid={`edr-files-lane-${i}-entry`}
                   style={{ fontSize: 10, marginTop: 3, color: "var(--amber, #d08700)" }}>
                ◆ first observed here
              </div>
            )}
          </div>
          <div style={{ position: "relative", height: 54 }}>
            <div style={{ position: "absolute", left: 0, right: 0, top: 26,
                          height: 1, background: "rgba(128,128,128,.28)" }} />
            {groupLane(ep.sightings || [], at).map((grp, j) => {
              const s = grp.lead;
              const on = selected?.raw_id === s.raw_id;
              const created = /CREATE/i.test(s.activity || "");
              const kinds = new Set(grp.items.map(
                (x) => (/CREATE/i.test(x.activity || "") ? "created" : "executed")));
              const kind = kinds.size > 1 ? "mixed" : (created ? "created" : "executed");
              const many = grp.items.length > 1;
              return (
                <button key={s.raw_id || j} type="button"
                        data-testid={`edr-files-glyph-${i}-${j}`}
                        data-day-shift={grp.items.some((x) => x.ingest_day_differs) ? "1" : "0"}
                        data-activity={kind}
                        data-covers={grp.items.length}
                        aria-label={many
                          ? `${grp.items.length} sightings around ${utc(s.observed_at)}, newest ${s.activity} ${s.path}`
                          : `${s.activity} ${s.path} at ${utc(s.observed_at)}`}
                        title={many
                          ? `${grp.items.length} sightings · ${utc(grp.items[grp.items.length - 1].observed_at)} → ${utc(s.observed_at)} · ${
                              kind === "mixed" ? "created and observed running"
                                : kind === "created" ? "file created" : "process observed"}`
                          : `${utc(s.observed_at)} · ${label(s.activity)} · ${s.path}`}
                        onClick={() => onSelect(on ? null : { ...s, _covers: grp.items })}
                        style={{ position: "absolute", left: `${at(s.observed_at)}%`,
                                 top: 19, transform: "translateX(-50%)",
                                 width: 15, height: 15, padding: 0,
                                 borderRadius: kind === "created" ? 15 : 3,
                                 cursor: "pointer", transition: "transform .1s, box-shadow .1s",
                                 border: `1px solid ${grp.items.some((x) => x.ingest_day_differs)
                                   ? "var(--amber, #d08700)"
                                   : kind === "mixed" ? "var(--mint, #3fae7d)"
                                   : on ? "var(--cyan, #39b7c4)" : "rgba(128,128,128,.55)"}`,
                                 borderWidth: (grp.items.some((x) => x.ingest_day_differs)
                                               || kind === "mixed") ? 2 : 1,
                                 background: kind === "created"
                                   ? "var(--mint, #3fae7d)" : "var(--cyan, #39b7c4)",
                                 boxShadow: on ? "0 0 0 3px rgba(57,183,196,.28)" : "none" }} />
              );
            })}
          </div>
        </div>
      ))}

      <div style={{ display: "flex", gap: 18, flexWrap: "wrap", padding: "7px 12px",
                    fontSize: 10.5, opacity: 0.72,
                    borderTop: "1px solid rgba(128,128,128,.18)" }}
           data-testid="edr-files-legend">
        <span>▪ process observed — /proc polling saw this image running</span>
        <span style={{ color: "var(--mint, #3fae7d)" }}>● file created — in a directory the sensor watches</span>
        <span>▪ mint-edged — one mark covering both, created and seen running</span>
        <span style={{ color: "var(--amber, #d08700)" }}>▫ ringed — delivered on another UTC day</span>
        <span>◆ first observed on this computer</span>
        <span style={{ opacity: 0.8 }}>
          marks closer together than one mark wide are grouped; selecting one
          shows the newest in the group and says how many it covers
        </span>
        <span style={{ opacity: 0.8 }}>
          never shown because never observed: moved · scanned · quarantined · written · deleted
        </span>
        {drawn < total && (
          <span data-testid="edr-files-graphic-partial" style={{ opacity: 0.9 }}>
            showing the newest {drawn} of {total} sightings on this axis
          </span>
        )}
        {shiftedOffAxis > 0 && (
          <span data-testid="edr-files-graphic-shift-offaxis"
                data-count={shiftedOffAxis}
                style={{ color: "var(--amber, #d08700)" }}>
            {shiftedOffAxis} delivered on another UTC day{" "}
            {shiftedOffAxis === 1 ? "is" : "are"} older than the marks drawn here —
            listed under “Delivered on a different UTC day” below
          </span>
        )}
      </div>
    </div>
  );
}

/* ── the detail pane AMP opens beside the graphic ───────────────────────── */

const Detail = ({ s, sha256, customer }) => {
  if (!s) {
    return (
      <div data-testid="edr-files-detail-empty"
           style={{ fontSize: 12, opacity: 0.6, padding: "12px 0" }}>
        Select a sighting on the graphic to see what the endpoint recorded.
      </div>
    );
  }
  const href = sightingHref(sha256, s, customer);
  const rows = [
    ["Observed (UTC)", utc(s.observed_at)],
    ["Delivered (UTC)", utc(s.ingested_at)],
    ["Activity", label(s.activity)],
    ["Path", s.path || "—"],
    ["Path source", PATH_SOURCE[s.path_field] || s.path_field || "—"],
    ["Size (bytes)", s.size != null ? String(s.size) : "not collected on this event type"],
    ["Parent image", s.parent_image || "not observed"],
    ["Command line", s.command_line || "not observed"],
    ["User", s.user || "—"],
    ["PID / PPID", `${s.pid ?? "—"} / ${s.ppid ?? "—"}`],
    ["Collection", s.collection_method || "—"],
    ["Trust", s.trust_state || "—"],
    ["Evidence id", s.raw_id || "—"],
  ];
  return (
    <div data-testid="edr-files-detail" data-raw-id={s.raw_id}>
      {s._covers && s._covers.length > 1 && (
        <div data-testid="edr-files-detail-covers"
             data-covers={s._covers.length}
             style={{ fontSize: 11.5, marginBottom: 8, opacity: 0.75 }}>
          This mark covers {s._covers.length} sightings between{" "}
          {utc(s._covers[s._covers.length - 1].observed_at)} and {utc(s._covers[0].observed_at)};
          the newest one is shown. Every one of them is listed in Event history.
        </div>
      )}
      {s.ingest_day_differs && (
        <div data-testid="edr-files-detail-day-shift"
             style={{ fontSize: 11.5, marginBottom: 8, color: "var(--amber, #d08700)" }}>
          Observed {s.observed_day_utc}, delivered {s.ingest_day_utc}. The link below
          opens the day the endpoint observed it.
        </div>
      )}
      <dl style={{ margin: 0, display: "grid", gridTemplateColumns: "120px 1fr",
                   gap: "5px 12px", fontSize: 12 }}>
        {rows.map(([k, v]) => (
          <React.Fragment key={k}>
            <dt style={{ opacity: 0.6 }}>{k}</dt>
            <dd className="mono" style={{ margin: 0, wordBreak: "break-all" }}>{v}</dd>
          </React.Fragment>
        ))}
      </dl>
      {href ? (
        <a href={href} target="_blank" rel="noopener noreferrer"
           data-testid="edr-files-detail-open"
           style={{ display: "inline-block", marginTop: 12, fontSize: 13 }}>
          Open Device Trajectory at this time
          <span className="sr-only"> (opens in a new tab)</span>
        </a>
      ) : (
        <span data-testid="edr-files-detail-no-link" style={{ fontSize: 12, opacity: 0.6 }}>
          ◇ this sighting names no endpoint or no observation time, so there is
          nothing to open.
        </span>
      )}
    </div>
  );
};

/* ── event history ──────────────────────────────────────────────────────── */

const History = ({ rows, sha256, customer, selected, onSelect, prefix }) => (
  <table data-testid={`${prefix}-table`}
         style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
    <thead><tr style={{ textAlign: "left", opacity: 0.6, fontSize: 10.5,
                        letterSpacing: ".06em", textTransform: "uppercase" }}>
      {["Observed (UTC)", "Computer", "Activity", "Path", "User", "PID", "Device Trajectory"]
        .map((h) => <th key={h} style={{ padding: "6px 14px 6px 0" }}>{h}</th>)}
    </tr></thead>
    <tbody>
      {rows.map((r, i) => {
        const href = sightingHref(sha256, r, customer);
        const on = selected?.raw_id === r.raw_id;
        return (
          <tr key={r.raw_id || i} data-testid={`${prefix}-row-${i}`}
              data-day-shift={r.ingest_day_differs ? "1" : "0"}
              onClick={() => onSelect(on ? null : r)}
              style={{ borderTop: "1px solid rgba(128,128,128,.18)", cursor: "pointer",
                       background: on ? "rgba(57,183,196,.10)" : "transparent" }}>
            <td className="mono" style={{ whiteSpace: "nowrap", padding: "5px 14px 5px 0" }}>{utc(r.observed_at)}</td>
            <td style={{ padding: "5px 14px 5px 0" }}>{r.hostname || r.endpoint_id}</td>
            <td style={{ padding: "5px 14px 5px 0" }}>{label(r.activity)}</td>
            <td className="mono" style={{ wordBreak: "break-all", padding: "5px 14px 5px 0" }}>{r.path || "—"}</td>
            <td className="mono" style={{ padding: "5px 14px 5px 0" }}>{r.user || "—"}</td>
            <td className="mono" style={{ padding: "5px 14px 5px 0" }}>{r.pid ?? "—"}</td>
            <td style={{ padding: "5px 0", whiteSpace: "nowrap" }}>
              {href ? (
                <a href={href} target="_blank" rel="noopener noreferrer"
                   data-testid={`${prefix}-row-${i}-open`}
                   onClick={(e) => e.stopPropagation()}>
                  Open trajectory<span className="sr-only"> (opens in a new tab)</span>
                </a>
              ) : (
                <span data-testid={`${prefix}-row-${i}-no-link`} style={{ opacity: 0.6 }}>
                  ◇ not openable
                </span>
              )}
            </td>
          </tr>
        );
      })}
    </tbody>
  </table>
);

export default function EdrFilesPage() {
  const [params, setParams] = useSearchParams();
  const urlHash = (params.get("sha256") || "").trim();
  const urlPath = (params.get("path") || "").trim();
  const [draft, setDraft] = useState(urlHash);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [sel, setSel] = useState(null);
  const [showDetails, setShowDetails] = useState(false);
  const [pathFilter, setPathFilter] = useState(urlPath);

  useEffect(() => setDraft(urlHash), [urlHash]);
  useEffect(() => setPathFilter(urlPath), [urlPath]);

  const look = useCallback((hash, pathContains = "") => {
    if (!hash) { setData(null); setErr(null); return; }
    setLoading(true); setErr(null); setSel(null);
    fileSightings(hash, 300, pathContains)
      .then((d) => setData(d))
      .catch((e) => {
        const detail = e?.response?.data?.detail || {};
        setErr({
          neutral: ["TENANT_REQUIRED", "TENANT_NOT_RESOLVED"].includes(detail.code),
          code: detail.code || null,
          text: detail.reason || detail.error || e?.message || String(e),
        });
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { look(urlHash, urlPath); }, [urlHash, urlPath, look]);

  const submit = (e) => {
    e?.preventDefault?.();
    const v = draft.trim();
    setParams(v ? { sha256: v, ...(urlPath ? { path: urlPath } : {}) } : {},
              { replace: true });
  };

  // The filter is a RE-READ, not a browser-side narrowing: the /var/tmp
  // creations of a busy digest are older than its newest 300 executions, so
  // narrowing what was already returned finds nothing and reads as absence.
  const applyFilter = (e) => {
    e?.preventDefault?.();
    const v = pathFilter.trim();
    setParams({ ...(urlHash ? { sha256: urlHash } : {}), ...(v ? { path: v } : {}) },
              { replace: true });
  };

  const malformed = draft.trim() && !SHA256.test(draft.trim());
  const customer = data?.tenant || null;
  const view = data?.ok ? data : null;

  const history = useMemo(() => {
    if (!view?.ok) return [];
    return (view.endpoints || [])
      .flatMap((e) => (e.sightings || []).map((s) => ({ ...s, hostname: e.hostname })))
      .sort((a, b) => String(b.observed_at).localeCompare(String(a.observed_at)));
  }, [view]);

  return (
    <NivXForgeConsole activeTab="files">
      <div className="x-page" data-testid="edr-files-page">
        <h1 className="x-h1"><FileText size={18} /> File Trajectory</h1>
        <p className="x-sub" data-testid="edr-files-scope">
          Where one piece of content has been seen across the acting customer's
          endpoints. A sighting means /proc polling saw this content running from
          this path, or the sensor found it created at this path in a watched
          directory. Two computers reporting the same digest is not evidence that
          the file moved between them — transfer is not observed. Write, delete,
          move, scan and quarantine are never observed either, so silence here is
          not proof the file is absent.
        </p>

        <form onSubmit={submit} className="x-row" data-testid="edr-files-form"
              style={{ gap: 8, margin: "14px 0" }}>
          <input value={draft} onChange={(e) => setDraft(e.target.value)}
                 data-testid="edr-files-sha256-input" aria-label="SHA-256"
                 placeholder="SHA-256 (64 hex characters)"
                 className="mono" style={{ flex: 1, maxWidth: 620 }} />
          <button type="submit" className="x-btn" data-testid="edr-files-lookup"
                  disabled={!draft.trim() || !!malformed}>
            <Search size={13} /> Look up
          </button>
        </form>

        {malformed && (
          <div className="x-empty" data-testid="edr-files-malformed">
            A SHA-256 is 64 hexadecimal characters. Nothing has been looked up,
            so this is not an empty result.
          </div>
        )}

        {loading && (
          <div className="x-empty" data-testid="edr-files-loading">
            <Loader2 size={13} className="spin"
                     style={{ verticalAlign: "middle", marginRight: 6 }} />
            Reading sightings …
          </div>
        )}

        {err && !loading && (err.neutral ? (
          <div className="x-empty" data-testid="edr-files-no-customer" data-code={err.code}>
            Select a customer to look up a file. Sightings are read within one
            customer, so there is nothing to search until you name it.
          </div>
        ) : (
          <div className="x-empty" data-testid="edr-files-error" data-code={err.code}
               style={{ color: "var(--red)" }}>
            The sighting read failed: {err.text}. No evidence was returned, so
            this is not an absence of sightings.
          </div>
        ))}

        {data && !loading && !err && data.ok === false && (
          <div className="x-empty" data-testid="edr-files-rejected"
               data-reason={data.reason}>{data.note}</div>
        )}

        {data?.ok && !loading && (
          <div data-testid="edr-files-result" data-total={data.total_sightings}>
            <Facts testid="edr-files-summary" items={[
              ["SHA-256", <span className="mono" key="k">{data.sha256}</span>, "edr-files-key"],
              ["Customer", data.tenant, "edr-files-customer"],
              ["Sightings", data.filter?.path_contains
                ? `${data.total_sightings} of ${data.total_sightings_unfiltered}`
                : data.total_sightings],
              ["Computers", data.endpoint_count],
            ]} />

            {data.total_sightings === 0 ? (
              <div className="x-empty" data-testid="edr-files-none" style={{ marginTop: 18 }}>
                No endpoint in {data.tenant} has reported this content. The lookup
                succeeded and returned nothing — this is an honest zero for this
                customer, not a failed read, and it says nothing about any other
                customer.
              </div>
            ) : (
              <>
                <Panel testid="edr-files-visibility" title="Visibility"
                       sub="The first and last time any endpoint in this customer observed this content.">
                  <Facts testid="edr-files-visibility-facts" items={[
                    ["First observed", <span className="mono" key="f">{utc(data.first_observed)}</span>, "edr-files-first"],
                    ["Last observed", <span className="mono" key="l">{utc(data.last_observed)}</span>, "edr-files-last"],
                    ["Computers", data.endpoint_count],
                    ["Delivered on another day", data.day_shifted_sightings],
                  ]} />
                </Panel>

                <Panel testid="edr-files-entry-point" title="First observed on"
                       sub={data.entry_point_basis || "The endpoint that observed this content first in this customer."}>
                  {(data.entry_points || []).length ? (
                    <Facts testid="edr-files-entry-facts" items={(data.entry_points || []).map((e, i) => [
                      `Computer ${i + 1}`,
                      <span key={e.endpoint_id}>
                        {e.hostname || e.endpoint_id}{" "}
                        <span className="mono" style={{ opacity: 0.6, fontSize: 11 }}>
                          {utc(e.first_observed)}
                        </span>
                      </span>,
                      `edr-files-entry-${i}`,
                    ])} />
                  ) : (
                    <span style={{ fontSize: 12, opacity: 0.6 }}>
                      No sighting carries an observation time, so no computer can
                      be named as the first to see it.
                    </span>
                  )}
                </Panel>

                <Panel testid="edr-files-details" title="File details">
                  <button type="button" className="x-btn" data-testid="edr-files-details-toggle"
                          onClick={() => setShowDetails((v) => !v)}
                          style={{ fontSize: 12, marginBottom: 10 }}>
                    {showDetails ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    {showDetails ? " Hide attributes" : " Show attributes"}
                  </button>
                  {showDetails && (
                    <div data-testid="edr-files-attributes">
                      <Facts testid="edr-files-attribute-facts" items={[
                        ["Known names", (data.observed_names || []).join(" · ") || "—"],
                        ["Recorded paths", String((data.all_observed_paths || data.observed_paths || []).length)],
                        ["Users", (data.attributes?.users || []).join(" · ") || "—"],
                        ["Parent images", (data.attributes?.parent_images || []).join(" · ") || "not observed"],
                        ["Sensor versions", (data.attributes?.sensor_versions || []).join(" · ") || "—"],
                        ["Activity", Object.entries(data.activity_breakdown_unfiltered
                                                    || data.activity_breakdown || {})
                          .map(([k, v]) => `${label(k)} ×${v}`).join(" · ") || "—"],
                      ]} />
                      <p style={{ fontSize: 11.5, opacity: 0.7, marginTop: 10, maxWidth: 900 }}
                         data-testid="edr-files-observation-basis">
                        {data.process_observation_basis}
                      </p>
                      {data.path_provenance && (
                        <p style={{ fontSize: 11.5, opacity: 0.7, marginTop: 6, maxWidth: 900 }}
                           data-testid="edr-files-path-provenance">
                          Where each path came from:{" "}
                          {Object.entries(data.path_provenance).map(([k, v]) =>
                            `${k} — ${v.sightings} sightings, path read from `
                            + `${v.path_field}, ${v.distinct_paths} distinct paths`).join(" · ")}.
                          A file that was both created and executed appears under both.
                        </p>
                      )}
                      <p style={{ fontSize: 11.5, opacity: 0.65, marginTop: 10, maxWidth: 900 }}
                         data-testid="edr-files-not-collected">
                        Not collected on this substrate, so not shown rather than shown
                        empty: {(data.not_collected || []).join(" · ")}.
                      </p>
                      {(data.all_observed_paths || data.observed_paths || []).length > 1 && (
                        <p className="mono" style={{ fontSize: 11.5, marginTop: 8, opacity: 0.8 }}
                           data-testid="edr-files-paths">
                          {(data.all_observed_paths || data.observed_paths || []).join(" · ")}
                        </p>
                      )}
                    </div>
                  )}
                </Panel>

                <Panel testid="edr-files-trajectory" title="Trajectory"
                       sub="Computers down the side, observed time across. Each mark is one sighting; select it to see what the endpoint recorded.">
                  <form onSubmit={applyFilter}
                        style={{ display: "flex", gap: 8, alignItems: "center",
                                 marginBottom: 10, flexWrap: "wrap" }}>
                    <input value={pathFilter} onChange={(e) => setPathFilter(e.target.value)}
                           data-testid="edr-files-path-filter" aria-label="Filter by path"
                           placeholder="Filter by path, e.g. /var/tmp" className="mono"
                           style={{ maxWidth: 380, fontSize: 12 }} />
                    <button type="submit" className="x-btn" data-testid="edr-files-path-filter-apply"
                            style={{ fontSize: 12 }}>
                      Filter all sightings
                    </button>
                    {urlPath && (
                      <button type="button" className="x-btn" data-testid="edr-files-path-filter-clear"
                              onClick={() => { setPathFilter(""); setParams({ sha256: urlHash }, { replace: true }); }}
                              style={{ fontSize: 12 }}>
                        Clear
                      </button>
                    )}
                    {data.filter?.path_contains && (
                      <span style={{ fontSize: 11.5, opacity: 0.8 }} data-testid="edr-files-filtered-note"
                            data-matched={data.filter.matched_sightings}
                            data-of={data.filter.of_sightings}>
                        {data.filter.matched_sightings} of {data.filter.of_sightings} sightings
                        have a path containing “{data.filter.path_contains}” — matched across
                        every sighting in this customer, not only the newest ones.
                      </span>
                    )}
                  </form>
                  <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) 340px",
                                gap: 16, alignItems: "start" }}>
                    {(view?.endpoints || []).length ? (
                      <Graphic data={view} selected={sel} onSelect={setSel} />
                    ) : (
                      <div className="x-empty" data-testid="edr-files-filter-empty">
                        No sighting of this digest in {data.tenant} has a path
                        containing “{data.filter?.path_contains || pathFilter}”. All{" "}
                        {data.filter?.of_sightings ?? data.total_sightings_unfiltered} sightings
                        were matched on the server, so this is a real zero for that
                        path — not a limit of what was read.
                      </div>
                    )}
                    <div style={{ border: "1px solid rgba(128,128,128,.22)", borderRadius: 10,
                                  padding: 12, minWidth: 0 }}>
                      <div style={{ fontSize: 10.5, letterSpacing: ".06em",
                                    textTransform: "uppercase", opacity: 0.6, marginBottom: 8 }}>
                        Sighting detail
                      </div>
                      <Detail s={sel} sha256={data.sha256} customer={customer} />
                    </div>
                  </div>
                </Panel>

                {data.truncated && (
                  <div className="x-note" data-testid="edr-files-truncated" style={{ marginTop: 14 }}>
                    This digest has more sightings than one read returns ({data.scanned}
                    {" "}read). The newest are shown; the counts above describe what was
                    read, not the whole history.
                  </div>
                )}

                {data.day_shifted_sightings > 0 && (
                  <Panel testid="edr-files-day-shift"
                         title={`Delivered on a different UTC day (${data.day_shifted_sightings})`}
                         sub="Observed on one UTC day and ingested on another. The link uses the day the endpoint OBSERVED them, which is where the evidence actually is.">
                    <History rows={data.day_shifted_examples || []} sha256={data.sha256}
                             customer={customer} selected={sel} onSelect={setSel}
                             prefix="edr-files-shift" />
                  </Panel>
                )}

                <Panel testid="edr-files-history" title="Event history"
                       sub="Every sighting that was read, newest first — when it happened and which computer saw it.">
                  <History rows={history} sha256={data.sha256} customer={customer}
                           selected={sel} onSelect={setSel} prefix="edr-files-event" />
                </Panel>
              </>
            )}
          </div>
        )}
      </div>
    </NivXForgeConsole>
  );
}
