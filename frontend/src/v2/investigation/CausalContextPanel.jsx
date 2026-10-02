// DT-I1D causal context groups. Chronology, evidence-backed relationships, correlation and UNKNOWN stay visually distinct.
import { GROUPS } from "./causalView.mjs";

const TITLES = { observed: "Observed", preceded_by: "Preceded by · chronological only, not causal",
  caused_by: "Caused by / Parent · evidence-supported only", produced: "Produced · child, file, network, registry effects",
  correlated: "Correlated · relevant but not established", unknown: "Unknown · and why", evidence: "Evidence refs" };
const STATE = {
  PROVEN_CAUSAL: { bg: "#064E3B", fg: "#6EE7B7", border: "1px solid #10B981" },
  SUPPORTED_RELATIONSHIP: { bg: "#0C2A4A", fg: "#93C5FD", border: "1px solid #3B82F6" },
  CORRELATED: { bg: "transparent", fg: "#94A3B8", border: "1px dashed #64748B" },
  UNKNOWN: { bg: "#3B2A06", fg: "#FCD34D", border: "1px solid #B45309" },
};
const mono = "text-[10px] font-mono break-all";

function EdgeRow({ e }) {
  const st = STATE[e.relationship_state];
  return (
    <div className="rounded px-1.5 py-1 mb-1" data-testid={`causal-edge-${e.relationship_id}`}
         data-state={e.relationship_state} style={{ border: st.border, background: "rgba(15,23,42,0.4)" }}>
      <div className="flex items-center gap-1.5 flex-wrap">
        <span className="text-[8px] px-1 rounded font-bold" style={{ background: st.bg, color: st.fg }}>
          {e.relationship_state}</span>
        <span className={mono} style={{ color: "#E2E8F0" }}>
          {e.source_entity || "UNKNOWN"} —{e.relationship_type}→ {e.target_entity || "UNKNOWN"}</span>
      </div>
      <div className="text-[10px] italic" style={{ color: "#94A3B8" }}>{e.reason}</div>
      <div className={mono} style={{ color: "#64748B" }}>
        refs: {e.evidence_refs.join(", ") || "none"} · {e.resolver}@{e.resolver_version}
        {e.window ? ` · window ${e.window.start} → ${e.window.end}` : ""}
      </div>
    </div>
  );
}

function Plain({ items }) {
  return items.map((o) => (
    <div key={o.frame_iid} className={mono} style={{ color: "#CBD5E1" }}>
      {o.ts} · {o.lane} · {o.label}{o.relation ? ` · ${o.relation}` : ""}
    </div>
  ));
}

export function CausalContextPanel({ causal }) {
  return (
    <div data-testid="causal-context-panel">
      {GROUPS.map((g) => {
        const items = causal.groups[g] || [];
        return (
          <div key={g} className="mt-1.5" data-testid={`causal-group-${g}`}>
            <div className="text-[9px] font-bold" style={{ color: "#94A3B8" }}>
              {TITLES[g]} <span style={{ color: "#64748B" }}>({items.length})</span></div>
            {!items.length && <div className="text-[10px] italic" style={{ color: "#64748B" }}>
              {g === "caused_by" ? "No evidence-supported cause recorded; none is inferred." : "None."}</div>}
            {g === "evidence" ? <div className={mono} style={{ color: "#CBD5E1" }}>{items.join(", ")}</div>
              : g === "observed" || g === "preceded_by" ? <Plain items={items} />
              : items.map((e) => <EdgeRow key={e.relationship_id} e={e} />)}
          </div>
        );
      })}
    </div>
  );
}
