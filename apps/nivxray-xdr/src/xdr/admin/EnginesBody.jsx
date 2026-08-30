/**
 * Admin → Engines · NivXRay XDR Computational Architecture Inventory.
 *
 * Reads `docs/NIVXRAY_CAPABILITY_REGISTRY.json` — the v2 schema — and
 * renders EVERY engine across NivXRay Tool + XDR Platform with honest
 * status classification.  No fabricated engines, no fabricated counts.
 *
 * Status buckets (owner-mandated):
 *   CONNECTED · ADOPTED · IMPLEMENTED · SCAFFOLD ·
 *   EXTERNAL_AVAILABLE · BLOCKED · NOT_YET_INTEGRATED
 */
import React, { useMemo, useState } from "react";
import { Cpu, Search, Filter, CheckCircle2, Circle,
                Package, ExternalLink, BookOpen } from "lucide-react";

import registry from "../../../docs/NIVXRAY_CAPABILITY_REGISTRY.json";


const STATUS_META = {
  CONNECTED:          { color: "var(--mint)",  glyph: CheckCircle2 },
  ADOPTED:            { color: "#38bdf8",      glyph: CheckCircle2 },
  IMPLEMENTED:        { color: "#a3e635",      glyph: Package      },
  SCAFFOLD:           { color: "var(--amber)", glyph: Circle       },
  EXTERNAL_AVAILABLE: { color: "#c084fc",      glyph: ExternalLink },
  BLOCKED:            { color: "#f87171",      glyph: Circle       },
  NOT_YET_INTEGRATED: { color: "var(--faint)", glyph: Circle       },
};


function StatusPill({ status }) {
  const meta = STATUS_META[status] || STATUS_META.NOT_YET_INTEGRATED;
  const Glyph = meta.glyph;
  return (
    <span data-testid={`engines-status-${status}`}
              style={{ display: "inline-flex", alignItems: "center", gap: 4,
                              padding: "1px 6px", border: `1px solid ${meta.color}`,
                              color: meta.color, borderRadius: 2,
                              fontFamily: "var(--mono)", fontSize: 9.5,
                              fontWeight: 700, textTransform: "uppercase",
                              letterSpacing: ".3px" }}>
      <Glyph size={9} /> {status.replace("_", " ")}
    </span>
  );
}


function BoolBadge({ label, value }) {
  return (
    <span style={{ padding: "1px 5px", fontSize: 9.5,
                            border: "1px solid var(--border)", borderRadius: 2,
                            fontFamily: "var(--mono)", letterSpacing: ".3px",
                            color: value ? "var(--mint)" : "var(--faint)" }}>
      {label}: {value ? "YES" : "NO"}
    </span>
  );
}


function EngineRow({ e }) {
  const [open, setOpen] = useState(false);
  return (
    <div data-testid={`engine-row-${e.id}`}
              style={{ border: "1px solid var(--border)", borderRadius: 3,
                              padding: 10, background: "var(--panel2)",
                              marginBottom: 6 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                          cursor: "pointer" }}
                onClick={() => setOpen((x) => !x)}>
        <Cpu size={12} style={{ color: "var(--cyan)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{e.name}</b>
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                              color: "var(--faint)" }}>{e.id}</span>
        <span style={{ flex: 1 }} />
        <StatusPill status={e.status} />
      </div>
      <div style={{ color: "var(--text-dim)", fontSize: 11, marginTop: 4 }}>
        {e.purpose}
      </div>
      {open && (
        <div style={{ marginTop: 10, borderTop: "1px solid var(--border)",
                                paddingTop: 8, display: "grid",
                                gridTemplateColumns: "1fr 1fr", gap: 10,
                                fontSize: 11, fontFamily: "var(--mono)" }}>
          <div>
            <div style={metaLabel}>Domain</div>
            <div>{e.domain}</div>
            <div style={{...metaLabel, marginTop: 6}}>Consumes</div>
            <div style={metaMuted}>
              {(e.consumes && e.consumes.length) ? e.consumes.join(", ") : "—"}
            </div>
            <div style={{...metaLabel, marginTop: 6}}>Produces</div>
            <div style={metaMuted}>
              {(e.produces && e.produces.length) ? e.produces.join(", ") : "—"}
            </div>
            <div style={{...metaLabel, marginTop: 6}}>Backend path</div>
            <div style={{...metaMuted, color: "var(--cyan)"}}>{e.backend_path || "—"}</div>
            <div style={{...metaLabel, marginTop: 6}}>APIs</div>
            <div style={metaMuted}>
              {(e.api && e.api.length) ? e.api.slice(0, 5).join(", ") : "—"}
            </div>
          </div>
          <div>
            <div style={metaLabel}>Availability</div>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              <BoolBadge label="NivXRay Tool" value={e.nivxray_tool_existing} />
              <BoolBadge label="XDR wired"    value={e.xdr_integrated} />
              <BoolBadge label="External"     value={e.external_available} />
            </div>
            {e.open_source_project && (
              <>
                <div style={{...metaLabel, marginTop: 6}}>Open-source project</div>
                <div style={metaMuted}>{e.open_source_project}</div>
              </>
            )}
            {e.license && (
              <>
                <div style={{...metaLabel, marginTop: 6}}>License</div>
                <div style={metaMuted}>{e.license}</div>
              </>
            )}
            {(e.tests && e.tests.length) ? (
              <>
                <div style={{...metaLabel, marginTop: 6}}>Tests</div>
                <div style={metaMuted}>{e.tests.join(", ")}</div>
              </>
            ) : null}
            {e.notes && (
              <>
                <div style={{...metaLabel, marginTop: 6}}>Notes</div>
                <div style={metaMuted}>{e.notes}</div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}


export default function EnginesBody() {
  const caps = registry.capabilities || [];
  const summary = registry.summary || {};
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("ALL");
  const [domain, setDomain] = useState("ALL");

  const filtered = useMemo(() => caps.filter((c) => {
    if (status !== "ALL" && c.status !== status) return false;
    if (domain !== "ALL" && c.domain !== domain) return false;
    if (q) {
      const qs = q.toLowerCase();
      if (!(`${c.name} ${c.id} ${c.purpose} ${c.open_source_project || ""}`
              .toLowerCase().includes(qs))) return false;
    }
    return true;
  }), [caps, q, status, domain]);

  const byDomain = useMemo(() => {
    const g = {};
    filtered.forEach((c) => { (g[c.domain] = g[c.domain] || []).push(c); });
    return g;
  }, [filtered]);

  return (
    <div data-testid="xdr-admin-engines-body">
      {/* Header + summary */}
      <div style={{ display: "flex", gap: 10, alignItems: "center",
                          marginBottom: 8 }}>
        <Cpu size={14} style={{ color: "var(--cyan)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
          NivXRay XDR Engine Registry
        </b>
        <span style={{ padding: "1px 6px", border: "1px solid var(--cyan)",
                                color: "var(--cyan)", borderRadius: 2, fontSize: 9.5,
                                fontFamily: "var(--mono)", fontWeight: 700 }}>
          {summary.total || caps.length} CAPABILITIES · {(summary.verified_backend_paths || 0)} VERIFIED PATHS
        </span>
        <span style={{ flex: 1 }} />
        <a href="https://github.com/jpreddy017/nivxray-xdr/blob/main/docs/NIVXRAY_CAPABILITY_REGISTRY.json"
              target="_blank" rel="noreferrer"
              className="btn ghost" style={{ padding: "3px 10px", fontSize: 11 }}>
          <ExternalLink size={11} /> registry.json
        </a>
      </div>
      <div style={{ color: "var(--faint)", fontSize: 11, marginBottom: 12,
                          fontFamily: "var(--mono)" }}>
        {registry.boundary || "NivXRay XDR = NivXRay Tool + XDR Platform."}
      </div>

      {/* Status buckets summary */}
      <div style={statsGrid}>
        {Object.entries(STATUS_META).map(([key, meta]) => (
          <div key={key}
                    data-testid={`engines-bucket-${key}`}
                    onClick={() => setStatus((x) => x === key ? "ALL" : key)}
                    style={{ ...statBox,
                                    border: `1px solid ${status === key
                                                                        ? meta.color
                                                                        : "var(--border)"}` }}>
            <div style={{ ...statLabel, color: meta.color }}>{key.replace("_", " ")}</div>
            <div style={statValue}>{summary.by_status?.[key] || 0}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 6, marginBottom: 8,
                          alignItems: "center" }}>
        <Search size={12} style={{ color: "var(--faint)" }} />
        <input value={q} onChange={(e) => setQ(e.target.value)}
                   placeholder="Search engine, project, purpose…"
                   data-testid="engines-search"
                   style={{ flex: 1, padding: "4px 8px",
                                    background: "var(--panel2)",
                                    border: "1px solid var(--border)",
                                    color: "var(--text)", fontSize: 11,
                                    borderRadius: 3, fontFamily: "var(--mono)" }} />
        <Filter size={12} style={{ color: "var(--faint)" }} />
        <select value={domain} onChange={(e) => setDomain(e.target.value)}
                     data-testid="engines-domain-filter"
                     style={selectStyle}>
          <option value="ALL">All domains</option>
          {Object.keys(summary.by_domain || {}).map((d) => (
            <option key={d} value={d}>{d}</option>
          ))}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)}
                     data-testid="engines-status-filter"
                     style={selectStyle}>
          <option value="ALL">All statuses</option>
          {Object.keys(STATUS_META).map((s) => (
            <option key={s} value={s}>{s.replace("_", " ")}</option>
          ))}
        </select>
      </div>

      <div style={{ color: "var(--faint)", fontSize: 10.5, marginBottom: 6,
                          fontFamily: "var(--mono)" }}>
        Showing {filtered.length} of {caps.length}
      </div>

      {/* Groups by domain */}
      {Object.keys(byDomain).sort().map((dom) => (
        <div key={dom} style={{ marginBottom: 14 }}>
          <div style={domainHeader}>
            <BookOpen size={11} /> {dom}
            <span style={{ marginLeft: 6, color: "var(--faint)",
                                    fontSize: 10 }}>
              · {byDomain[dom].length} engines
            </span>
          </div>
          {byDomain[dom].map((e) => <EngineRow key={e.id} e={e} />)}
        </div>
      ))}

      {filtered.length === 0 && (
        <div style={{ padding: 12, fontSize: 11, color: "var(--faint)",
                                fontFamily: "var(--mono)" }}>
          NO ENGINES MATCH · adjust search / filters
        </div>
      )}

      {/* Footer legend */}
      <div style={{ marginTop: 20, padding: 10, background: "var(--panel2)",
                          border: "1px solid var(--border)", borderRadius: 3,
                          fontSize: 10.5, fontFamily: "var(--mono)",
                          color: "var(--faint)" }}>
        <b style={{ color: "var(--text-dim)" }}>Status legend · </b>
        {(registry.status_buckets || []).map((b, i) => (
          <span key={b.key}>
            {i > 0 ? " · " : ""}
            <span style={{ color: STATUS_META[b.key]?.color || "var(--faint)",
                                    fontWeight: 700 }}>{b.key}</span>
            {" "}— {b.meaning}
          </span>
        ))}
      </div>
    </div>
  );
}


const statsGrid = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
  gap: 6, marginBottom: 14,
};
const statBox = {
  padding: "8px 10px", borderRadius: 3, background: "var(--panel2)",
  cursor: "pointer", transition: "border 0.15s",
};
const statLabel = {
  fontSize: 9, fontFamily: "var(--mono)", fontWeight: 700,
  textTransform: "uppercase", letterSpacing: ".3px", marginBottom: 4,
};
const statValue = { fontSize: 18, fontWeight: 700, fontFamily: "var(--mono)" };
const domainHeader = {
  display: "flex", alignItems: "center", gap: 6, padding: "6px 10px",
  background: "var(--panel2)", border: "1px solid var(--border)",
  borderRadius: 3, fontFamily: "var(--mono)", fontSize: 11,
  fontWeight: 700, textTransform: "uppercase", letterSpacing: ".4px",
  color: "var(--text)", marginBottom: 6,
};
const metaLabel = {
  fontSize: 9, color: "var(--faint)", textTransform: "uppercase",
  letterSpacing: ".3px", marginBottom: 2,
};
const metaMuted = { color: "var(--text-dim)", fontSize: 10.5 };
const selectStyle = {
  padding: "4px 6px", background: "var(--panel2)",
  border: "1px solid var(--border)", color: "var(--text)",
  fontSize: 11, borderRadius: 3, fontFamily: "var(--mono)",
};
