import React from "react";
import { AlertOctagon, AlertTriangle, Timer, UserCheck, UserX, Zap, ArrowUpRight } from "lucide-react";

const CARDS = [
  { id: "critical", label: "Critical", icon: AlertOctagon, tone: "critical" },
  { id: "high_priority", label: "High", icon: AlertTriangle, tone: "high" },
  { id: "unassigned", label: "Unassigned", icon: UserX, tone: "high" },
  { id: "aging", label: "Aging", icon: Timer, tone: "high" },
  { id: "in_progress_mine", label: "My Queue", icon: UserCheck, tone: "accent" },
  { id: "high_fidelity", label: "High Fidelity", icon: Zap, tone: "accent" },
];

function cardState(data, tile, loading) {
  if (loading) return "Loading";
  if (data?.status === 401 || data?.status === 403) return "Access denied";
  if (data?.error) return "Error loading";
  if (tile?.count_source === "empty") return "No scope";
  if (tile?.count_source !== "live" || !Number.isSafeInteger(tile?.count) || tile.count < 0)
    return "Not available";
  return "ready";
}

export default function SecurityOverviewKpis({ data, loading = false, onNavigate }) {
  const tiles = new Map();
  if (Array.isArray(data?.groups)) data.groups.forEach((group) => {
    if (Array.isArray(group?.tiles)) group.tiles.forEach((tile) => {
      if (tile?.id) tiles.set(tile.id, tile);
    });
  });
  return (
    <section className="cc-security" aria-labelledby="cc-security-title" aria-busy={loading}>
      <h2 id="cc-security-title" className="cc-security__title">Security overview</h2>
      <div className="cc-attn" data-testid="cc-attention">
        {CARDS.map(({ id, label, icon: Icon, tone }) => {
          const tile = tiles.get(id);
          const state = cardState(data, tile, loading);
          const ready = state === "ready";
          const canOpen = ready && Boolean(tile.lens_href);
          const detail = ready ? (canOpen ? "Open queue" : "Queue not available") : state;
          return (
            <button type="button" key={id} className="cc-attn__i"
              disabled={!canOpen} data-state={state} data-tone={ready && tile.count > 0 ? tone : "quiet"}
              data-testid={`cc-attn-${id}`}
              aria-label={`${label}: ${ready ? tile.count : state}. ${ready ? detail : ""}`.trim()}
              aria-describedby={tile?.description ? `cc-kpi-${id}-description` : undefined}
              onClick={() => canOpen && onNavigate(tile.lens_href)}>
              <span className="cc-attn__k"><Icon size={15} aria-hidden="true" />{label}</span>
              <span className="cc-attn__v" data-testid={`cc-attn-${id}-value`}>{ready ? tile.count : "—"}</span>
              {tile?.description && <span className="cc-attn__description cc-visually-hidden" id={`cc-kpi-${id}-description`}>{tile.description}</span>}
              <span className="cc-attn__s">{detail}{canOpen && <ArrowUpRight size={13} aria-hidden="true" />}</span>
            </button>
          );
        })}
      </div>
      <details className="cc-kpi-definitions">
        <summary>Metric definitions</summary>
        <dl>{CARDS.map(({ id, label }) => <React.Fragment key={id}>
          <dt>{label}</dt><dd>{tiles.get(id)?.description || "Definition not available in this response."}</dd>
        </React.Fragment>)}</dl>
      </details>
    </section>
  );
}
