/**
 * Admin → Engines · read-only inventory of every NivXRay engine
 * that XDR consumes.  Backed by ``docs/NIVXRAY_CAPABILITY_REGISTRY.json``
 * so the surface always matches what the anti-hallucination CI gate
 * verifies against the real base codebase.
 *
 * Includes a small architecture diagram (SVG) showing the adopt-
 * before-invent flow:
 *
 *      XDR frontend  →  Adopt Layer  →  base engines  →  SSOT → Verdict → Response
 *
 * The diagram is data-driven — nodes are the actually-present
 * engines from the registry, not a decorative illustration.
 */
import React, { useMemo, useState } from "react";
import { Cpu, Search, ExternalLink } from "lucide-react";

import registry from "../../../docs/NIVXRAY_CAPABILITY_REGISTRY.json";
import { honestyBanner } from "@/xdr/capabilityRegistry";


// ── Grouping helpers ────────────────────────────────────────────
const GROUPS = [
  { key: "canonical",   label: "Canonical engines (owner-listed acronyms)",
    match: (c) => /^engine\.(die|iedde|iue|uaie|uil|ida|cem|ice|veee)/i.test(c.id) },
  { key: "evidence",    label: "Evidence · Analysis · Decoding",
    match: (c) => /^(evidence|artifact|decode|command|ioc|reputation|malware|corpus)/i.test(c.id) },
  { key: "detection",   label: "Detection · Correlation · Verdict",
    match: (c) => /^(detection|correlation|verdict|mitre|behavior)/i.test(c.id) },
  { key: "investigation", label: "Investigation · IKG · SSOT · Timeline",
    match: (c) => /^(ssot|ikg|process|trajectory|attack|timeline|report|corrections)/i.test(c.id) },
  { key: "response",    label: "Response · Evidence Sink · Collector",
    match: (c) => /^(response|collector)/i.test(c.id) },
];

function classify(cap) {
  for (const g of GROUPS) {
    if (g.match(cap)) return g.key;
  }
  return "other";
}


function statusColor(s) {
  const t = String(s || "").toUpperCase();
  if (t.startsWith("CONNECTED")) return "var(--mint)";
  if (t === "ADOPT" || t === "ADAPT" || t === "EXTEND") return "var(--amber)";
  if (t === "BASE_ONLY") return "var(--faint)";
  if (t === "EXTERNAL")  return "var(--cyan)";
  if (t === "NEW")       return "#c084fc";
  if (t === "NOT_PRESENT") return "#f87171";
  return "var(--faint)";
}


// ── Engine card ─────────────────────────────────────────────────
function EngineCard({ cap }) {
  const banner = honestyBanner(cap.id);
  return (
    <div className="panel"
            data-testid={`xdr-engine-card-${cap.id}`}
            style={{ padding: 10, display: "flex",
                        flexDirection: "column", gap: 6 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <b className="mono" style={{ fontSize: 11, color: "var(--text)" }}>
          {cap.name}
        </b>
        <span style={{ flex: 1 }} />
        <span className="mono"
                  style={{ fontSize: 9.5, letterSpacing: ".4px",
                              padding: "1px 6px", borderRadius: 3,
                              border: `1px solid ${statusColor(cap.status)}`,
                              color: statusColor(cap.status),
                              textTransform: "uppercase" }}>
          {String(cap.status).replace(/[()]/g, "").split(" ")[0]}
        </span>
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
        {cap.id}
      </div>
      {cap.base_api && (
        <div className="mono" style={{ fontSize: 10.5,
                                                      color: "var(--cyan)" }}>
          {cap.base_api}
        </div>
      )}
      {cap.backend_path && (
        <div className="mono" style={{ fontSize: 10,
                                                      color: "var(--faint)" }}>
          <span style={{ color: "var(--text-dim)" }}>path:</span>{" "}
          {cap.backend_path}
        </div>
      )}
      {!cap.backend_path && cap.source && (
        <div className="mono" style={{ fontSize: 10,
                                                      color: "var(--faint)" }}>
          <span style={{ color: "var(--text-dim)" }}>source:</span>{" "}
          {cap.source}
        </div>
      )}
      <div style={{ display: "flex", gap: 6, alignItems: "center",
                       fontSize: 9.5, color: "var(--faint)" }}>
        <span className="mono">owner: {cap.owner}</span>
        <span>·</span>
        <span className="mono">adopt: {cap.adoption}</span>
      </div>
      {banner && (
        <div style={{ marginTop: 2, fontSize: 10, color: statusColor(cap.status) }}>
          {banner.text}
        </div>
      )}
    </div>
  );
}


// ── Architecture diagram ────────────────────────────────────────
// Renders the adopt-before-invent flow using real engine names from
// the registry, laid out on an SVG with three vertical bands:
//   XDR surfaces  →  Adopt Layer  →  Authoritative base engines
// Followed by SSOT → Verdict → Response emerging on the right.
function ArchitectureDiagram({ engines }) {
  const laneX = { xdr: 60, adopt: 260, base: 470, out: 720 };
  const xdrSurfaces = [
    "Investigation Canvas",
    "Verdict Panel",
    "DIE / IEDDE Panels",
    "IUE Timeline Panel",
    "UAIE Catalog Panel",
    "Response Drawer",
  ];
  const adoptLayer = [
    "baseCapabilities.js",
    "capabilityRegistry.js",
    "consumerPanels.jsx",
    "enginePanels.jsx",
  ];
  const outNodes = ["SSOT", "Verdict Stage-2", "Response Engine (XDR)"];
  return (
    <div style={{ marginTop: 10, padding: 10,
                     border: "1px solid var(--border)",
                     borderRadius: 4, background: "var(--panel2)",
                     overflow: "auto" }}
            data-testid="xdr-engines-architecture">
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    marginBottom: 6 }}>
        Adoption architecture (data-driven · rendered from registry)
      </div>
      <svg width={880} height={Math.max(420, engines.length * 20 + 80)}
              style={{ display: "block", fontFamily: "var(--mono)" }}>
        {/* Lane labels */}
        <text x={laneX.xdr}   y={16} fill="var(--cyan)" fontSize="10">
          XDR SURFACES
        </text>
        <text x={laneX.adopt} y={16} fill="var(--amber)" fontSize="10">
          ADOPT LAYER
        </text>
        <text x={laneX.base}  y={16} fill="var(--mint)" fontSize="10">
          BASE ENGINES ({engines.length})
        </text>
        <text x={laneX.out}   y={16} fill="#c084fc" fontSize="10">
          AUTHORITATIVE OUT
        </text>

        {/* XDR surfaces */}
        {xdrSurfaces.map((s, i) => (
          <g key={s}>
            <rect x={laneX.xdr - 10} y={30 + i * 34} width={170} height={26}
                    rx={4} fill="rgba(34,211,238,.08)" stroke="var(--cyan)" />
            <text x={laneX.xdr - 4} y={47 + i * 34} fill="var(--text)"
                    fontSize="10.5">{s}</text>
            {/* Arrow → adopt lane */}
            <line x1={laneX.xdr + 160} y1={43 + i * 34}
                     x2={laneX.adopt - 10} y2={43 + i * 34}
                     stroke="var(--faint)" strokeDasharray="3 3" />
          </g>
        ))}

        {/* Adopt layer files */}
        {adoptLayer.map((s, i) => (
          <g key={s}>
            <rect x={laneX.adopt - 10} y={30 + i * 34} width={180} height={26}
                    rx={4} fill="rgba(245,166,35,.08)" stroke="var(--amber)" />
            <text x={laneX.adopt - 4} y={47 + i * 34} fill="var(--text)"
                    fontSize="10.5">{s}</text>
            {/* Arrow → base lane */}
            <line x1={laneX.adopt + 170} y1={43 + i * 34}
                     x2={laneX.base - 10}   y2={43 + i * 34}
                     stroke="var(--faint)" strokeDasharray="3 3" />
          </g>
        ))}

        {/* Base engines (data-driven) */}
        {engines.slice(0, 18).map((e, i) => (
          <g key={e.id}>
            <rect x={laneX.base - 10} y={30 + i * 22} width={220} height={18}
                    rx={3} fill="rgba(50,205,80,.06)"
                    stroke={statusColor(e.status)} />
            <text x={laneX.base - 4} y={44 + i * 22} fill="var(--text)"
                    fontSize="9.5">
              {e.name.slice(0, 42)}{e.name.length > 42 ? "…" : ""}
            </text>
            {/* Arrow → out lane at midpoint */}
            {i === Math.floor(Math.min(engines.length, 18) / 2) && (
              <line x1={laneX.base + 210} y1={39 + i * 22}
                       x2={laneX.out - 10}    y2={80}
                       stroke="var(--faint)" strokeDasharray="3 3" />
            )}
          </g>
        ))}

        {/* Authoritative out */}
        {outNodes.map((s, i) => (
          <g key={s}>
            <rect x={laneX.out - 10} y={40 + i * 40} width={150} height={30}
                    rx={4} fill="rgba(192,132,252,.08)" stroke="#c084fc" />
            <text x={laneX.out - 4} y={60 + i * 40} fill="var(--text)"
                    fontSize="10.5">{s}</text>
          </g>
        ))}

        {/* Footer note */}
        <text x={laneX.xdr - 10} y={Math.max(400, engines.length * 20 + 60)}
                fill="var(--faint)" fontSize="9.5">
          Adopt-before-invent · every base engine is CONSUMED, never re-implemented.
          Verified by tests/adoption/test_capability_registry_matches_base.mjs.
        </text>
      </svg>
    </div>
  );
}


// ── The Engines body ────────────────────────────────────────────
export default function EnginesBody() {
  const [q, setQ] = useState("");
  const [group, setGroup] = useState("all");

  const engines = useMemo(() => {
    const withGroup = registry.capabilities.map((c) => ({
      ...c, _group: classify(c),
    }));
    // Only consider capabilities that represent an engine surface — every
    // registry entry qualifies except pure external taxonomies (mitre).
    return withGroup;
  }, []);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return engines.filter((c) => {
      if (group !== "all" && c._group !== group) return false;
      if (!needle) return true;
      const hay = `${c.id} ${c.name} ${c.base_api || ""} ${c.backend_path || ""} ${c.source || ""}`.toLowerCase();
      return hay.includes(needle);
    });
  }, [engines, q, group]);

  const canonical = filtered.filter((c) => c._group === "canonical");

  const totalByStatus = useMemo(() => {
    const t = {};
    for (const c of engines) {
      const s = String(c.status).toUpperCase().split(" ")[0];
      t[s] = (t[s] || 0) + 1;
    }
    return t;
  }, [engines]);

  return (
    <div data-testid="xdr-engines-body">
      {/* Header strip */}
      <div style={{ display: "flex", alignItems: "center", gap: 12,
                       flexWrap: "wrap", marginBottom: 10 }}>
        <div className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
          {engines.length} engines · registry
          {" · "}
          {Object.entries(totalByStatus).map(([k, v]) => (
            <span key={k} style={{ marginLeft: 6,
                                                  color: statusColor(k) }}>
              {v} {k}
            </span>
          ))}
        </div>
        <span style={{ flex: 1 }} />
        <div style={{ position: "relative" }}>
          <Search size={11} style={{ position: "absolute", left: 6,
                                                        top: 6, color: "var(--faint)" }} />
          <input
            data-testid="xdr-engines-search"
            placeholder="Search engines, APIs, paths…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ padding: "4px 8px 4px 22px", fontSize: 11,
                        width: 260, border: "1px solid var(--border)",
                        borderRadius: 4, background: "var(--panel2)",
                        color: "var(--text)", fontFamily: "var(--mono)" }} />
        </div>
        <select value={group} onChange={(e) => setGroup(e.target.value)}
                  data-testid="xdr-engines-group-filter"
                  style={{ padding: "4px 6px", fontSize: 11,
                              border: "1px solid var(--border)", borderRadius: 4,
                              background: "var(--panel2)",
                              color: "var(--text)" }}>
          <option value="all">All groups</option>
          {GROUPS.map((g) => (
            <option key={g.key} value={g.key}>{g.label}</option>
          ))}
        </select>
      </div>

      {/* Architecture diagram — data-driven from canonical engines */}
      <ArchitectureDiagram engines={canonical.length ? canonical : filtered} />

      {/* Grouped cards */}
      {GROUPS.map((g) => {
        const rows = filtered.filter((c) => c._group === g.key);
        if (rows.length === 0) return null;
        return (
          <div key={g.key} style={{ marginTop: 14 }}
                  data-testid={`xdr-engines-group-${g.key}`}>
            <div className="section-title" style={{ marginBottom: 6,
                                                                display: "flex", alignItems: "center", gap: 6 }}>
              <Cpu size={11} /> {g.label}
              <span className="mono" style={{ marginLeft: 6, fontSize: 10,
                                                              color: "var(--faint)" }}>
                {rows.length}
              </span>
            </div>
            <div style={{ display: "grid",
                              gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
                              gap: 8 }}>
              {rows.map((c) => <EngineCard key={c.id} cap={c} />)}
            </div>
          </div>
        );
      })}

      {/* Footer provenance */}
      <div style={{ marginTop: 12, fontSize: 10.5, color: "var(--faint)",
                       fontFamily: "var(--mono)" }}>
        source: <span style={{ color: "var(--cyan)" }}>
          docs/NIVXRAY_CAPABILITY_REGISTRY.json
        </span>{" "}· regression-guarded by{" "}
        <span style={{ color: "var(--cyan)" }}>
          tests/adoption/test_capability_registry_matches_base.mjs
        </span>
      </div>
      <div style={{ marginTop: 4, fontSize: 10, color: "var(--faint)",
                       fontFamily: "var(--mono)" }}>
        adoption matrix:{" "}
        <a href="https://github.com/jpreddy017/nivxray-xdr/blob/main/docs/NIVXRAY_XDR_TECHNOLOGY_ADOPTION_MATRIX.md"
             target="_blank" rel="noreferrer"
             style={{ color: "var(--cyan)", textDecoration: "none" }}>
          NIVXRAY_XDR_TECHNOLOGY_ADOPTION_MATRIX.md
          <ExternalLink size={9} style={{ marginLeft: 3,
                                                        verticalAlign: "middle" }} />
        </a>
      </div>
    </div>
  );
}
