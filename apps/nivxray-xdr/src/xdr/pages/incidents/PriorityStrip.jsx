/**
 * PriorityStrip · 8-tile attention/priority overview.
 *
 * Reads `/api/xdr/mss/kpis` (existing) which returns lens tiles
 * grouped by section.  We pick 8 specific lens IDs to project onto
 * the strip.  Every tile navigates the queue to the corresponding
 * lens URL — pure filter application, no engine invocation.
 */
import React, { useEffect, useState, useCallback } from "react";
import { getMssKpis } from "@/lib/incidentsApi";

// Lens id → { label, tone } — mapped from Defender's "top priorities"
// pattern into NivXRay-specific lens ids.
const STRIP_TILES = [
  { id: "critical",           label: "Critical",     tone: "crit"   },
  { id: "high_priority",      label: "High",         tone: "high"   },
  { id: "unassigned",         label: "Unassigned",   tone: "amber"  },
  { id: "in_progress_mine",   label: "My Queue",     tone: "purple" },
  { id: "aging",              label: "SLA Risk",     tone: "amber"  },
  { id: "on_hold",            label: "On Hold",      tone: "blue"   },
  { id: "recently_created",   label: "New",          tone: "blue"   },
  { id: "recently_updated",   label: "Updated",      tone: "green"  },
];

export default function PriorityStrip({ activeLens, onLensClick }) {
  const [tiles, setTiles] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const data = await getMssKpis();
      const byId = {};
      (data?.groups || []).forEach(g =>
        (g.tiles || []).forEach(t => { byId[t.id] = t; }));
      setTiles(byId);
    } catch (e) {
      setError(e?.message || "kpi_load_failed");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="ql-strip" data-testid="ql-priority-strip">
      {STRIP_TILES.map(s => {
        const t = tiles[s.id];
        const isActive = activeLens === s.id;
        const count = t?.count;
        // Honest empty state: if the KPI hasn't loaded, show em-dash.
        const showDash = loading || count == null;
        return (
          <button
            key={s.id}
            className={`ql-tile ${s.tone} ${isActive ? "active" : ""} ${showDash ? "na" : ""}`}
            onClick={() => onLensClick(s.id)}
            data-testid={`ql-strip-tile-${s.id}`}
            data-active={isActive || undefined}
            title={t?.description || s.label}
          >
            <span className="ql-tile-label">{s.label}</span>
            <span className="ql-tile-count">
              {showDash ? "—" : count.toLocaleString()}
            </span>
          </button>
        );
      })}
      {error && (
        <div style={{ gridColumn: "1 / -1", fontSize: 10.5,
                      fontFamily: "var(--qs-mono)", color: "#DC2626" }}>
          KPI FEED: {error}
        </div>
      )}
    </div>
  );
}
