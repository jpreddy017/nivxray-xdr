/**
 * Admin › Detection Content — unified rule / regex / LOLBAS / MITRE.
 *
 * Consumes:
 *   · detectionRuleStore   (Sigma / detection lifecycle)
 *   · patternRuleStore     (regex / glob / exact / cidr / …)
 *   · lolbas.pack.json     (native LOLBAS content pack, 15 seeds)
 *
 * Every row is real content in-tree.  No fabrication.
 */
import React, { useMemo, useState } from "react";
import { Radar, Search, ExternalLink } from "lucide-react";

import { listRules as listDetectionRules } from "@/xdr/detect/detectionRuleStore";
import { listPatternRules }   from "@/xdr/detect/patternRuleStore";
import lolbasPack             from "../../../docs/content/packs/lolbas.pack.json";


function StatCard({ label, value, testid, sub }) {
  return (
    <div data-testid={testid}
            style={{ padding: 10, borderRadius: 4,
                        border: "1px solid var(--border)",
                        background: "var(--panel2)" }}>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    textTransform: "uppercase",
                                                    marginBottom: 4 }}>
        {label}
      </div>
      <div className="mono" style={{ fontSize: 16, color: "var(--text)" }}>
        {value}
      </div>
      {sub && (
        <div style={{ fontSize: 10, color: "var(--faint)",
                          marginTop: 2 }}>
          {sub}
        </div>
      )}
    </div>
  );
}


export default function DetectionContentBody() {
  const [q, setQ] = useState("");

  const rules    = useMemo(() => listDetectionRules(), []);
  const patterns = useMemo(() => listPatternRules(),   []);
  const lolbins  = lolbasPack.binaries || [];

  const attackTechniques = useMemo(() => {
    const s = new Set();
    for (const r of rules) (r.tags || []).filter((t) => /^T\d+/.test(t))
                                                          .forEach((t) => s.add(t));
    for (const p of patterns) (p.tags || []).forEach((t) => s.add(t));
    for (const b of lolbins)  (b.attack || []).forEach((t) => s.add(t));
    return Array.from(s).sort();
  }, [rules, patterns, lolbins]);

  const filteredPatterns = useMemo(() => {
    const n = q.trim().toLowerCase();
    if (!n) return patterns;
    return patterns.filter((p) => `${p.id} ${p.name} ${p.pattern}
                                                    ${(p.tags || []).join(" ")}`.toLowerCase()
                                                   .includes(n));
  }, [patterns, q]);

  const filteredLolbins = useMemo(() => {
    const n = q.trim().toLowerCase();
    if (!n) return lolbins;
    return lolbins.filter((b) => `${b.binary} ${b.id}
                                                  ${(b.attack || []).join(" ")}`.toLowerCase()
                                                 .includes(n));
  }, [lolbins, q]);

  return (
    <div data-testid="xdr-detection-content-body">
      <div style={{ display: "flex", alignItems: "center", gap: 12,
                       marginBottom: 10, flexWrap: "wrap" }}>
        <div className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
          NivXRay-native detection content · deterministic · evidence-first
        </div>
        <span style={{ flex: 1 }} />
        <div style={{ position: "relative" }}>
          <Search size={11} style={{ position: "absolute", left: 6,
                                                        top: 6, color: "var(--faint)" }} />
          <input
            data-testid="xdr-content-search"
            placeholder="Search rules · patterns · LOLBins · techniques…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ padding: "4px 8px 4px 22px", fontSize: 11,
                        width: 300, border: "1px solid var(--border)",
                        borderRadius: 4, background: "var(--panel2)",
                        color: "var(--text)", fontFamily: "var(--mono)" }} />
        </div>
      </div>

      <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
                        gap: 8, marginBottom: 12 }}>
        <StatCard label="Detection Rules" testid="content-stat-rules"
                        value={rules.length} sub="Sigma authoring lifecycle" />
        <StatCard label="Pattern Rules" testid="content-stat-patterns"
                        value={patterns.length} sub="regex · glob · exact" />
        <StatCard label="LOLBAS Binaries" testid="content-stat-lolbas"
                        value={lolbins.length} sub={lolbasPack.pack_id} />
        <StatCard label="ATT&CK Techniques" testid="content-stat-mitre"
                        value={attackTechniques.length}
                        sub="union across rules/patterns/LOLBAS" />
      </div>

      {/* Pattern Rules */}
      <div className="section-title" style={{ marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <Radar size={11} /> Pattern Rules ({filteredPatterns.length})
        <span className="mono" style={{ marginLeft: 6, fontSize: 10,
                                                        color: "var(--faint)" }}>
          reusable regex / glob / exact primitives — never a verdict
        </span>
      </div>
      <div style={{ maxHeight: 260, overflow: "auto",
                        border: "1px solid var(--border)", borderRadius: 3,
                        padding: 6, background: "var(--panel2)" }}>
        {filteredPatterns.map((p) => (
          <div key={p.id} data-testid={`xdr-pattern-${p.id}`}
                  style={{ padding: "4px 0", fontSize: 11,
                              color: "var(--text-dim)",
                              borderBottom: "1px solid var(--border)" }}>
            <span className="mono" style={{ color: "var(--cyan)" }}>{p.id}</span>
            {" · "}
            <b>{p.name}</b>
            <span className="mono" style={{ marginLeft: 6, fontSize: 10,
                                                          color: p.enabled ? "var(--mint)" : "var(--faint)" }}>
              {p.enabled ? "ENABLED" : "DISABLED"}
            </span>
            <span className="mono" style={{ marginLeft: 6, fontSize: 10,
                                                          color: "var(--amber)" }}>
              {p.severity?.toUpperCase()} · {p.confidence?.toUpperCase()}
            </span>
            <div style={{ marginLeft: 8, fontFamily: "var(--mono)",
                              fontSize: 10, color: "var(--faint)",
                              whiteSpace: "pre-wrap", overflow: "hidden" }}>
              {p.engine} · {p.pattern.slice(0, 120)}{p.pattern.length > 120 ? "…" : ""}
            </div>
            {(p.tags || []).length > 0 && (
              <div style={{ marginLeft: 8, marginTop: 2 }}>
                {(p.tags || []).map((t) => (
                  <span key={t} className="mono"
                            style={{ padding: "1px 5px", marginRight: 4,
                                        border: "1px solid #f472b6",
                                        color: "#f472b6", fontSize: 9,
                                        borderRadius: 3 }}>
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* LOLBAS Content Pack */}
      <div className="section-title" style={{ marginTop: 12, marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <Radar size={11} /> LOLBAS Content Pack ({filteredLolbins.length})
        <span className="mono" style={{ marginLeft: 6, fontSize: 10,
                                                        color: "var(--faint)" }}>
          {lolbasPack.pack_id} · v{lolbasPack.version}
        </span>
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    marginBottom: 6 }}>
        {lolbasPack.license}
      </div>
      <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
                        gap: 8 }}>
        {filteredLolbins.map((b) => (
          <div key={b.id} className="panel"
                  data-testid={`xdr-lolbin-${b.id}`}
                  style={{ padding: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <b className="mono" style={{ fontSize: 11, color: "var(--cyan)" }}>
                {b.binary}
              </b>
              <span style={{ flex: 1 }} />
              <span className="mono" style={{ fontSize: 9.5,
                                                              color: "var(--amber)" }}>
                {b.severity?.toUpperCase()} · {b.confidence?.toUpperCase()}
              </span>
            </div>
            <div style={{ fontSize: 10.5, color: "var(--text-dim)",
                              marginTop: 4 }}>
              {b.legitimate_purpose}
            </div>
            {(b.suspicious_arguments || []).length > 0 && (
              <div style={{ marginTop: 4, fontSize: 10,
                                color: "var(--faint)",
                                fontFamily: "var(--mono)" }}>
                <b style={{ color: "var(--text-dim)" }}>suspicious args:</b>{" "}
                {(b.suspicious_arguments || []).slice(0, 3).join(", ")}
                {(b.suspicious_arguments || []).length > 3 ? "…" : ""}
              </div>
            )}
            {(b.attack || []).length > 0 && (
              <div style={{ marginTop: 4 }}>
                {(b.attack || []).map((t) => (
                  <span key={t} className="mono"
                            style={{ padding: "1px 5px", marginRight: 4,
                                        border: "1px solid #f472b6",
                                        color: "#f472b6", fontSize: 9,
                                        borderRadius: 3 }}>
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ATT&CK coverage */}
      <div className="section-title" style={{ marginTop: 12, marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <Radar size={11} /> ATT&CK Coverage ({attackTechniques.length})
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
        {attackTechniques.map((t) => (
          <span key={t} className="mono"
                    data-testid={`xdr-technique-${t}`}
                    style={{ padding: "2px 6px", fontSize: 10,
                                border: "1px solid #f472b6",
                                color: "#f472b6", borderRadius: 3 }}>
            {t}
          </span>
        ))}
      </div>

      <div style={{ marginTop: 12, fontSize: 10.5, color: "var(--faint)",
                       fontFamily: "var(--mono)" }}>
        source: <span style={{ color: "var(--cyan)" }}>
          detectionRuleStore · patternRuleStore · docs/content/packs/lolbas.pack.json
        </span>{" "}· deterministic evidence · never a verdict on its own.
      </div>
    </div>
  );
}
