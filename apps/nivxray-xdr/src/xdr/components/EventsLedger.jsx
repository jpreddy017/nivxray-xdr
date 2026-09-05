/**
 * EventsLedger · P1.6
 *
 * Dense chronological mirror of the canvas:
 *   [Timestamp UTC ms] [Actor] [Glyph] [Target] [Disposition]
 *
 * Bidirectional with the canvas: hovering a row highlights its marker,
 * clicking a row centres the shared temporal window on that instant and
 * selects the observation.  Right-click opens the artifact pivot menu.
 *
 * Disposition is stated as unknown because the substrate carries no
 * disposition field — it is never inferred from severity.
 */
import React from "react";

import {
  glyphFor, tsOf, severityTier, TIER_COLOR, TIER_MALICIOUS, TIER_ATTRIBUTED,
  actorOf, targetOf, shortHash,
} from "@/xdr/lib/trajectoryModel";

function tsMs(ms) {
  if (ms === null) return "◇";
  return new Date(ms).toISOString().replace("T", " ").replace("Z", "Z");
}

export default function EventsLedger({
  events, selectedId, hoverId, onHover, onSelect, onCenter, onContextMenu,
}) {
  const rows = (events || [])
    .map((e) => ({ e, t: tsOf(e) }))
    .filter((r) => r.t !== null)
    .sort((a, b) => a.t - b.t);

  return (
    <section className="panel" style={{ padding: 0 }} data-testid="edr-events-ledger">
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                    padding: "7px 10px", borderBottom: "1px solid #212B36",
                    background: "#11161D" }}>
        <span className="section-title" style={{ margin: 0 }}>Events Ledger</span>
        <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}
              data-testid="edr-ledger-count">
          {rows.length} observation{rows.length === 1 ? "" : "s"} in the selected window ·
          row click centres the canvas · right-click for artifact pivots
        </span>
      </div>

      {rows.length === 0 ? (
        <div className="x-empty" data-testid="edr-ledger-empty">
          <b>◇ NO OBSERVATIONS IN SELECTED WINDOW</b>
        </div>
      ) : (
        <div style={{ maxHeight: 300, overflow: "auto" }}>
          <table className="x-table" data-testid="edr-ledger-table">
            <thead>
              <tr>
                <th style={{ width: 190 }}>Timestamp (UTC ms)</th>
                <th>Actor Process</th>
                <th style={{ width: 108 }}>Event</th>
                <th>Target Object</th>
                <th style={{ width: 150 }}>ATT&amp;CK</th>
                <th style={{ width: 190 }}>Disposition</th>
                <th style={{ width: 34 }} title="Row actions (keyboard accessible)">⋯</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ e, t }) => {
                const g = glyphFor(e);
                const tier = severityTier(e);
                const sel = selectedId === e.id;
                const hov = hoverId === e.id;
                return (
                  <tr key={e.id}
                      className="rowlink"
                      style={{
                        background: sel ? "rgba(0,210,211,0.10)"
                                  : hov ? "rgba(255,255,255,0.04)" : undefined,
                        borderLeft: `2px solid ${tier === TIER_MALICIOUS
                          ? TIER_COLOR[TIER_MALICIOUS]
                          : tier === TIER_ATTRIBUTED
                            ? TIER_COLOR[TIER_ATTRIBUTED] : "transparent"}`,
                      }}
                      onMouseEnter={() => onHover?.(e.id)}
                      onMouseLeave={() => onHover?.(null)}
                      onClick={() => { onSelect?.(e); onCenter?.(t); }}
                      onContextMenu={(ev) => {
                        ev.preventDefault();
                        onContextMenu?.(e, { x: ev.clientX, y: ev.clientY });
                      }}
                      data-testid={`edr-ledger-row-${e.id}`}>
                    <td className="mono" style={{ fontSize: 10 }}>{tsMs(t)}</td>
                    <td className="mono" style={{ fontSize: 10.5, color: "var(--text)" }}>
                      {actorOf(e) || <span className="nx-ep" data-ep="no_evidence"
                                           data-known="true">◇ NOT RECORDED</span>}
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: 9.5,
                                                      color: TIER_COLOR[tier] }}>
                        {g.sym} {g.tag}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 10, color: "var(--text-dim)",
                                                  maxWidth: 360, overflow: "hidden",
                                                  textOverflow: "ellipsis",
                                                  whiteSpace: "nowrap" }}
                        title={targetOf(e) || ""}>
                      {targetOf(e) || <span className="nx-ep" data-ep="no_evidence"
                                            data-known="true">◇ NONE RECORDED</span>}
                      {e.sha256 && (
                        <span style={{ color: "var(--faint)" }}>
                          {" "}({shortHash(e.sha256)})
                        </span>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: 9.5, color: "#F39C12" }}>
                      {(e.mitre || []).length
                        ? e.mitre.join(", ")
                        : <span className="nx-ep" data-ep="no_evidence" data-known="true">◇</span>}
                    </td>
                    <td>
                      <span className="nx-ep" data-ep="unknown" data-known="true"
                            title="v2_shadow_observations carries no disposition field. Nothing is inferred from severity.">
                        ? UNKNOWN DISPOSITION
                      </span>
                    </td>
                    <td>
                      <button type="button" className="btn ghost"
                              style={{ padding: "1px 5px", fontSize: 11 }}
                              aria-label="Artifact pivots for this observation"
                              title="Artifact pivots"
                              onClick={(ev) => {
                                ev.stopPropagation();
                                const r = ev.currentTarget.getBoundingClientRect();
                                onContextMenu?.(e, { x: r.left - 250, y: r.bottom });
                              }}
                              data-testid={`edr-ledger-row-actions-${e.id}`}>
                        ⋯
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
