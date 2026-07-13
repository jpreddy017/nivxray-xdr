import { useEffect, useState, useMemo } from "react";
import api from "@/lib/api";
import { Search, Plus } from "lucide-react";

export default function OperationsPanel({ onAdd }) {
  const [ops, setOps] = useState([]);
  const [q, setQ] = useState("");

  useEffect(() => {
    api.get("/operations").then((r) => setOps(r.data)).catch(() => {});
  }, []);

  const grouped = useMemo(() => {
    const query = q.trim().toLowerCase();
    const filt = ops.filter(
      (o) =>
        !query ||
        o.name.toLowerCase().includes(query) ||
        o.id.toLowerCase().includes(query) ||
        (o.description || "").toLowerCase().includes(query),
    );
    const g = {};
    for (const o of filt) {
      g[o.category] ||= [];
      g[o.category].push(o);
    }
    return g;
  }, [ops, q]);

  const total = ops.length;

  return (
    <aside
      className="brut-border"
      style={{
        borderLeft: "none",
        borderTop: "none",
        borderBottom: "none",
        background: "var(--surface)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
      data-testid="operations-panel"
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 14px",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>
          ▸ OPERATIONS
        </div>
        <span className="badge neutral" data-testid="ops-count">{total}</span>
      </div>

      <div style={{ padding: 10, borderBottom: "1px solid var(--border)", position: "relative" }}>
        <Search
          size={13}
          color="var(--text-mute)"
          style={{ position: "absolute", left: 20, top: 20 }}
        />
        <input
          data-testid="ops-search-input"
          className="nvx-input"
          placeholder="Search operations…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ paddingLeft: 30 }}
        />
      </div>

      <div style={{ overflowY: "auto", flex: 1 }}>
        {Object.entries(grouped).map(([cat, list]) => (
          <div key={cat}>
            <div className="cat-head" data-testid={`ops-cat-${cat.toLowerCase()}`}>
              <span>◆ {cat}</span>
              <span style={{ color: "var(--text-mute)" }}>{list.length}</span>
            </div>
            {list.map((op) => (
              <div
                key={op.id}
                className="op-row"
                data-testid={`op-${op.id}`}
                title={op.description}
                onClick={() => onAdd(op)}
              >
                <div>
                  <div className="mono" style={{ fontSize: 12, color: "var(--text)" }}>
                    {op.name}
                  </div>
                  {op.description && (
                    <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 2 }}>
                      {op.description.slice(0, 60)}{op.description.length > 60 ? "…" : ""}
                    </div>
                  )}
                </div>
                <div className="op-add">
                  <Plus size={14} />
                </div>
              </div>
            ))}
          </div>
        ))}
        {total > 0 && Object.keys(grouped).length === 0 && (
          <div className="mono" style={{ padding: 20, color: "var(--text-mute)", fontSize: 11 }}>
            No operations match "{q}"
          </div>
        )}
      </div>
    </aside>
  );
}
