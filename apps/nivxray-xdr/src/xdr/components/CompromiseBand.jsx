/**
 * CompromiseBand · P1.5
 *
 * The case banner beneath the canvas.  Selecting a compromise window
 * casts a cyan halo over the observations that constitute it and dims
 * the rest of the canvas — the window itself comes from those
 * observations' own timestamps, never from a guessed range.
 *
 * Case references are reported with their resolvability: a reference
 * carried by the observation substrate that has no persisted incident
 * record is labelled as such instead of being linked into a 404.
 */
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert, Crosshair } from "lucide-react";

import { fmtUtc, IOC_RED, TELEMETRY_CYAN } from "@/xdr/lib/trajectoryModel";

export default function CompromiseBand({
  spans, caseRows, incidents, selectedSpanId, onSelectSpan, onFocusSpan,
}) {
  const [expanded, setExpanded] = useState(false);
  const resolvable = new Set(
    (incidents || [])
      .filter((i) => i.source !== "v2_shadow_observations")
      .map((i) => i.incident_id),
  );
  const rows = caseRows || [];
  // Every reference unpersisted and carrying the same counts is one fact
  // repeated N times — collapse it, but keep it expandable.
  const collapsible = rows.length > 1
    && rows.every((c) => !resolvable.has(c.case_id)
                          && c.events === rows[0].events
                          && c.ioc === rows[0].ioc);

  return (
    <section className="panel" style={{ padding: 0, background: "#11161D" }}
             data-testid="edr-compromise-band">
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                    padding: "7px 10px", borderBottom: "1px solid #212B36" }}>
        <ShieldAlert size={12} style={{ color: spans.length ? IOC_RED : "var(--faint)" }} />
        <span className="section-title" style={{ margin: 0 }}>
          Compromise Band &amp; Detections
        </span>
        <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}
              data-testid="edr-compromise-summary">
          {spans.length} correlated window{spans.length === 1 ? "" : "s"} ·{" "}
          {(caseRows || []).length} case reference{(caseRows || []).length === 1 ? "" : "s"} ·{" "}
          {resolvable.size} resolve to a persisted incident record
        </span>
        <div style={{ flex: 1 }} />
        {selectedSpanId && (
          <button className="btn" style={{ padding: "2px 7px", fontSize: 9.5 }}
                  onClick={() => onSelectSpan(null)}
                  data-testid="edr-compromise-clear">
            ↩ Return to activity
          </button>
        )}
      </div>

      {spans.length === 0 ? (
        <div className="x-empty" data-testid="edr-compromise-empty">
          <b>◇ NO COMPROMISE EVENTS OBSERVED</b>
          <div style={{ marginTop: 4 }}>
            No observation in this window carries a detection, a high
            severity, an ATT&amp;CK attribution or a label. Nothing is
            haloed because nothing was flagged.
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", gap: 8, padding: 8, flexWrap: "wrap" }}>
          {spans.map((s) => {
            const active = selectedSpanId === s.id;
            return (
              <button key={s.id}
                      onClick={() => onSelectSpan(active ? null : s.id)}
                      onDoubleClick={() => onFocusSpan?.(s)}
                      style={{
                        textAlign: "left", cursor: "pointer",
                        padding: "6px 9px", borderRadius: 4,
                        minWidth: 240,
                        background: active ? "rgba(0,210,211,0.08)" : "#0B0F14",
                        border: `1px solid ${active ? TELEMETRY_CYAN : "#212B36"}`,
                      }}
                      title="Click to halo the contributing observations · double-click to scope the window"
                      data-testid={`edr-compromise-span-${s.id}`}>
                <div className="mono" style={{ fontSize: 10, color: "var(--text)" }}>
                  {fmtUtc(s.start)} → {fmtUtc(s.end)}
                </div>
                <div className="mono" style={{ fontSize: 9.5, color: "var(--faint)",
                                               marginTop: 3 }}>
                  {s.events.length} attributed observation
                  {s.events.length === 1 ? "" : "s"}
                  {s.mitre.length > 0 && ` · ${s.mitre.join(", ")}`}
                </div>
                {active && (
                  <div className="mono" style={{ fontSize: 9, marginTop: 3,
                                                 color: TELEMETRY_CYAN }}>
                    <Crosshair size={9} style={{ verticalAlign: "middle" }} />{" "}
                    haloed on canvas · background dimmed
                  </div>
                )}
              </button>
            );
          })}
        </div>
      )}

      {rows.length > 0 && (
        <div style={{ borderTop: "1px solid #212B36", overflowX: "auto" }}>
          {collapsible && !expanded ? (
            <div style={{ padding: "8px 10px", display: "flex", gap: 10,
                          alignItems: "center" }}
                 data-testid="edr-compromise-cases-collapsed">
              <span className="nx-ep" data-ep="no_evidence" data-known="true">
                ◇ CASE RECORD NOT PERSISTED
              </span>
              <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
                ×{rows.length} case references carry the same {rows[0].events}{" "}
                observations ({rows[0].ioc} attributed); none resolves to a
                persisted incident record.
              </span>
              <button className="btn" style={{ padding: "2px 7px", fontSize: 9.5 }}
                      onClick={() => setExpanded(true)}
                      data-testid="edr-compromise-cases-expand">
                Show all {rows.length}
              </button>
            </div>
          ) : (
          <table className="x-table" data-testid="edr-compromise-cases">
            <thead>
              <tr>
                <th>Case Reference</th>
                <th>Observations</th>
                <th>Attributed</th>
                <th>First</th>
                <th>Last</th>
                <th>Record State</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.case_id} data-testid={`edr-compromise-case-${c.case_id}`}>
                  <td className="mono" style={{ fontSize: 10 }}>
                    {resolvable.has(c.case_id) ? (
                      <Link to={`/xdr/incidents/${c.case_id}`}
                            style={{ color: "var(--cyan)" }}>{c.case_id}</Link>
                    ) : c.case_id}
                  </td>
                  <td className="mono">{c.events}</td>
                  <td className="mono" style={{ color: c.ioc ? "#F39C12" : "var(--faint)" }}>
                    {c.ioc}
                  </td>
                  <td className="mono" style={{ fontSize: 10 }}>{fmtUtc(c.first)}</td>
                  <td className="mono" style={{ fontSize: 10 }}>{fmtUtc(c.last)}</td>
                  <td>
                    {resolvable.has(c.case_id) ? (
                      <span className="nx-ep" data-ep="evidence_present" data-known="true">
                        ◆ INCIDENT RECORD PERSISTED
                      </span>
                    ) : (
                      <span className="nx-ep" data-ep="no_evidence" data-known="true"
                            title="The observation substrate carries this case_id, but no incident record exists for it — so it is not linked.">
                        ◇ CASE RECORD NOT PERSISTED
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          )}
        </div>
      )}
    </section>
  );
}
