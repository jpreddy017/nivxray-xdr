/**
 * XdrDashboardPage · Analyst Operations Dashboard.
 *
 * The SOC analyst's starting point.  Ten operational lenses grouped
 * into TRIAGE · OWNERSHIP · RISK, each backed by the authoritative
 * `/api/xdr/dashboard/tiles` endpoint.  Every tile shares its Mongo
 * predicate with the corresponding `/api/incidents?lens=<id>` queue,
 * so the count on the tile equals the count in the queue the analyst
 * lands in when they click.
 *
 * Owner-locked invariants (2026-02-31):
 *   - No client-side counting.  All counts come from the backend.
 *   - No fabricated numbers.  Missing data → honest "—" / "0 (empty)".
 *   - Every interactive element carries a data-testid.
 *   - The dashboard NEVER invokes an investigation engine.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertOctagon, AlertTriangle, Zap, UserX, UserCheck, MessageCircle,
  PauseCircle, Timer, Sparkles, Activity, RefreshCw,
} from "lucide-react";

import XdrShell           from "@/xdr/XdrShell";
import { getDashboardTiles } from "@/lib/incidentsApi";


// ── Lens → icon mapping (visual only — never affects behaviour) ────
const LENS_ICON = {
  critical:          AlertOctagon,
  high_priority:     AlertTriangle,
  high_fidelity:     Zap,
  unassigned:        UserX,
  in_progress_mine:  UserCheck,
  customer_response: MessageCircle,
  on_hold:           PauseCircle,
  aging:             Timer,
  recently_created:  Sparkles,
  recently_updated:  Activity,
};

const TONE_COLOR = {
  red:   { fg: "#f87171", bg: "rgba(248,113,113,0.10)", ring: "rgba(248,113,113,0.35)" },
  amber: { fg: "#fbbf24", bg: "rgba(251,191,36,0.10)",  ring: "rgba(251,191,36,0.35)" },
  cyan:  { fg: "#22d3ee", bg: "rgba(34,211,238,0.10)",  ring: "rgba(34,211,238,0.30)" },
  mint:  { fg: "#4ade80", bg: "rgba(74,222,128,0.10)",  ring: "rgba(74,222,128,0.30)" },
};


export default function XdrDashboardPage() {
  const navigate = useNavigate();
  const [body,   setBody]   = useState(null);
  const [loading, setL]     = useState(true);
  const [error, setError]   = useState(null);

  const load = useCallback(async () => {
    setL(true); setError(null);
    try {
      const res = await getDashboardTiles();
      setBody(res);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message
                || "Failed to load dashboard.");
    } finally {
      setL(false);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  const generatedAt = useMemo(() => {
    if (!body?.generated_at) return null;
    try { return new Date(body.generated_at).toLocaleString(); }
    catch { return body.generated_at; }
  }, [body]);

  return (
    <XdrShell activeTop="dashboards">
      <div style={headerRow}>
        <div>
          <h1 className="page-h1"
                data-testid="xdr-operations-dashboard-heading">
            Analyst Operations
          </h1>
          <div className="page-sub"
                data-testid="xdr-operations-dashboard-sub">
            The SOC starting point.  Ten operational lenses — each tile
            counts the same incidents that appear when you click it.
          </div>
        </div>
        <button className="btn ghost"
                   data-testid="xdr-operations-dashboard-refresh"
                   onClick={load}
                   disabled={loading}
                   style={refreshBtn}>
          <RefreshCw size={11}
                        style={loading ? { animation: "spin 0.9s linear infinite" } : {}} />
          Refresh
        </button>
      </div>

      {generatedAt && (
        <div data-testid="xdr-operations-dashboard-generated-at"
                style={metaLine}>
          Live · generated {generatedAt}
        </div>
      )}

      {loading && !body && (
        <div className="x-empty"
              data-testid="xdr-operations-dashboard-loading">
          LOADING…
        </div>
      )}

      {error && (
        <div className="x-empty"
              data-testid="xdr-operations-dashboard-error"
              style={{ color: "#ff9494", marginTop: 12 }}>
          {String(error)}
        </div>
      )}

      {!error && body?.groups?.map((group) => (
        <section key={group.id}
                    data-testid={`xdr-operations-dashboard-group-${group.id}`}
                    style={groupSection}>
          <div style={groupTitle}
                 data-testid={`xdr-operations-dashboard-group-title-${group.id}`}>
            {group.label}
          </div>
          <div style={tileGrid}>
            {group.tiles.map((tile) => (
              <LensTile key={tile.id}
                             tile={tile}
                             onClick={() => navigate(tile.lens_href)} />
            ))}
          </div>
        </section>
      ))}

      {!loading && !error && body && (
        <div data-testid="xdr-operations-dashboard-invariant"
                style={invariantNote}>
          {body.invariant}
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </XdrShell>
  );
}


// ── Tile component ─────────────────────────────────────────────────
function LensTile({ tile, onClick }) {
  const Icon = LENS_ICON[tile.id] || AlertOctagon;
  const tone = TONE_COLOR[tile.tone] || TONE_COLOR.cyan;
  const isEmpty = tile.count_source === "empty";
  const isZero  = tile.count === 0;

  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={`xdr-operations-dashboard-tile-${tile.id}`}
      data-tile-count={tile.count}
      data-tile-source={tile.count_source}
      style={{
        ...tileBtn,
        borderColor: tone.ring,
        background: tone.bg,
      }}
      aria-label={`${tile.label} · ${tile.count} incidents`}
    >
      <div style={tileHead}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Icon size={14} style={{ color: tone.fg, flexShrink: 0 }} />
          <div style={{ ...tileLabel, color: "var(--text)" }}
                 data-testid={`xdr-operations-dashboard-tile-label-${tile.id}`}>
            {tile.label}
          </div>
        </div>
      </div>

      <div style={{ ...tileCount, color: tone.fg }}
             data-testid={`xdr-operations-dashboard-tile-count-${tile.id}`}>
        {tile.count}
      </div>

      <div style={tileDesc}
             data-testid={`xdr-operations-dashboard-tile-desc-${tile.id}`}>
        {tile.description}
      </div>

      {isEmpty && (
        <div style={emptyChip}
                data-testid={`xdr-operations-dashboard-tile-empty-${tile.id}`}>
          NO SCOPE · honest empty
        </div>
      )}
      {!isEmpty && isZero && (
        <div style={zeroChip}
                data-testid={`xdr-operations-dashboard-tile-zero-${tile.id}`}>
          NO MATCHES
        </div>
      )}
    </button>
  );
}


// ── Styles ─────────────────────────────────────────────────────────
const headerRow = {
  display: "flex", justifyContent: "space-between", alignItems: "flex-start",
  gap: 12, marginBottom: 4,
};
const refreshBtn = {
  display: "inline-flex", alignItems: "center", gap: 6,
  padding: "6px 10px", fontSize: 11, fontFamily: "var(--mono)",
};
const metaLine = {
  fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-dim)",
  letterSpacing: 0.4, marginTop: 2, marginBottom: 14,
};
const groupSection = {
  marginTop: 22,
};
const groupTitle = {
  fontFamily: "var(--mono)", fontSize: 10, letterSpacing: 1.4,
  color: "var(--text-dim)", marginBottom: 8, paddingLeft: 2,
};
const tileGrid = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))",
  gap: 10,
};
const tileBtn = {
  textAlign: "left",
  padding: "14px 16px",
  border: "1px solid",
  borderRadius: 6,
  cursor: "pointer",
  color: "var(--text)",
  fontFamily: "inherit",
  transition: "transform 120ms ease, border-color 120ms ease",
};
const tileHead = {
  display: "flex", justifyContent: "space-between", alignItems: "center",
  gap: 8,
};
const tileLabel = {
  fontFamily: "var(--mono)", fontSize: 11, letterSpacing: 0.6,
  fontWeight: 700,
};
const tileCount = {
  fontFamily: "var(--mono)", fontSize: 34, fontWeight: 800,
  lineHeight: 1.02, marginTop: 8, marginBottom: 2,
  letterSpacing: -0.5,
};
const tileDesc = {
  fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-dim)",
  marginTop: 6, lineHeight: 1.42,
};
const emptyChip = {
  display: "inline-block", marginTop: 10,
  padding: "2px 6px", borderRadius: 3,
  border: "1px solid rgba(200,200,220,0.25)",
  color: "var(--faint)", fontFamily: "var(--mono)",
  fontSize: 9, letterSpacing: 1,
};
const zeroChip = {
  display: "inline-block", marginTop: 10,
  padding: "2px 6px", borderRadius: 3,
  color: "var(--faint)", fontFamily: "var(--mono)",
  fontSize: 9, letterSpacing: 1,
};
const invariantNote = {
  marginTop: 28, padding: "10px 12px",
  border: "1px dashed rgba(120,130,150,0.35)",
  borderRadius: 4,
  fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)",
  letterSpacing: 0.25, lineHeight: 1.55,
};
