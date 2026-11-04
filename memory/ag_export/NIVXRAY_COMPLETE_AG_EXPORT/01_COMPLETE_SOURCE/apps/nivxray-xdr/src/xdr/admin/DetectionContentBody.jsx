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
import React, { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import { Radar, Search, ExternalLink, Package } from "lucide-react";

import { listRules as listDetectionRules } from "@/xdr/detect/detectionRuleStore";
import { listPatternRules }   from "@/xdr/detect/patternRuleStore";
import api                    from "@/lib/api";


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
  const [lolbasStatus, setLolbasStatus] = useState(null);
  const [lolbasSample, setLolbasSample] = useState([]);
  const [pcCounts, setPcCounts] = useState({ normal: 0, suspicious: 0,
                                                                        abnormal: 0 });

  const rules    = useMemo(() => listDetectionRules(), []);
  const patterns = useMemo(() => listPatternRules(),   []);

  // Live LOLBAS metadata + sample from the authoritative API.  Never
  // read from the retired 15-seed JSON.
  useEffect(() => {
    (async () => {
      try {
        const [s, e, p] = await Promise.all([
          api.get("/xdr/lolbas/status"),
          api.get("/xdr/lolbas/entries", { params: { limit: 50 }}),
          api.get("/xdr/lolbas/primitives",
                          { params: { kind: "lolbin.parent_child", limit: 5000 }}),
        ]);
        setLolbasStatus(s?.data?.data || null);
        setLolbasSample(e?.data?.data?.entries || []);
        const prims = p?.data?.data?.primitives || [];
        setPcCounts({
          normal:     prims.filter((x) => x.tier === "normal").length,
          suspicious: prims.filter((x) => x.tier === "suspicious").length,
          abnormal:   prims.filter((x) => x.tier === "abnormal").length,
        });
      } catch { /* honest empty state */ }
    })();
  }, []);

  const lolbasCount = lolbasStatus?.entries_total ?? 0;
  const lolbasCoverage = lolbasStatus?.active_version?.coverage_pct;
  const lolbasVersion  = lolbasStatus?.active_version?.upstream_version;
  const lolbasLicense  = lolbasStatus?.license;

  const attackTechniques = useMemo(() => {
    const s = new Set();
    for (const r of rules) (r.tags || []).filter((t) => /^T\d+/.test(t))
                                                          .forEach((t) => s.add(t));
    for (const p of patterns) (p.tags || []).forEach((t) => s.add(t));
    for (const b of lolbasSample) (b.mitre_ids || []).forEach((t) => s.add(t));
    return Array.from(s).sort();
  }, [rules, patterns, lolbasSample]);

  const filteredPatterns = useMemo(() => {
    const n = q.trim().toLowerCase();
    if (!n) return patterns;
    return patterns.filter((p) => `${p.id} ${p.name} ${p.pattern}
                                                    ${(p.tags || []).join(" ")}`.toLowerCase()
                                                   .includes(n));
  }, [patterns, q]);

  const filteredLolbins = useMemo(() => {
    const n = q.trim().toLowerCase();
    if (!n) return lolbasSample;
    return lolbasSample.filter((b) => `${b.name} ${b.description}
                                                    ${(b.mitre_ids || []).join(" ")}`.toLowerCase()
                                                   .includes(n));
  }, [lolbasSample, q]);

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
                        value={lolbasCount}
                        sub={lolbasCoverage != null
                          ? `${lolbasCoverage}% upstream coverage · live sync`
                          : "sync pack in Content Pack · LOLBAS"} />
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

      {/* LOLBAS · live from the 10-stage synchronization pipeline */}
      <div className="section-title" style={{ marginTop: 12, marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <Package size={11} /> LOLBAS · live pack ({lolbasCount} entries · sample: {filteredLolbins.length})
        <span className="mono" style={{ marginLeft: 6, fontSize: 10,
                                                        color: "var(--faint)" }}>
          {lolbasVersion || "not-synced"}
        </span>
        <span style={{ flex: 1 }} />
        <NavLink to="/xdr/admin/content-pack-lolbas"
                        className="btn ghost"
                        data-testid="xdr-content-open-lolbas-pack"
                        style={{ padding: "2px 8px", fontSize: 10 }}>
          Manage full pack →
        </NavLink>
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                    marginBottom: 6 }}>
        {lolbasLicense || "license: not synced yet"} · parent-child relations:
        {" "}<span style={{ color: "var(--mint)" }}>{pcCounts.normal} normal</span>
        {" · "}<span style={{ color: "var(--amber)" }}>{pcCounts.suspicious} suspicious</span>
        {" · "}<span style={{ color: "#f87171" }}>{pcCounts.abnormal} abnormal</span>
      </div>
      <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
                        gap: 8 }}>
        {filteredLolbins.slice(0, 24).map((b) => (
          <div key={b.name} className="panel"
                  data-testid={`xdr-lolbin-${b.name}`}
                  style={{ padding: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <b className="mono" style={{ fontSize: 11, color: "var(--cyan)" }}>
                {b.name}
              </b>
              <span style={{ flex: 1 }} />
              <span className="mono" style={{ fontSize: 9.5,
                                                              color: b.enabled_for_tenant ? "var(--mint)" : "#f87171" }}>
                {b.enabled_for_tenant ? "ENABLED" : "DISABLED"}
              </span>
            </div>
            <div style={{ fontSize: 10.5, color: "var(--text-dim)",
                              marginTop: 4 }}>
              {(b.description || "").slice(0, 120)}
              {(b.description || "").length > 120 ? "…" : ""}
            </div>
            {(b.categories || []).length > 0 && (
              <div style={{ marginTop: 4, fontSize: 10,
                                color: "var(--faint)",
                                fontFamily: "var(--mono)" }}>
                <b style={{ color: "var(--text-dim)" }}>categories:</b>{" "}
                {(b.categories || []).join(", ")}
              </div>
            )}
            {(b.mitre_ids || []).length > 0 && (
              <div style={{ marginTop: 4 }}>
                {(b.mitre_ids || []).map((t) => (
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
        {filteredLolbins.length > 24 && (
          <div className="mono" style={{ padding: 10, fontSize: 11,
                                                              color: "var(--faint)",
                                                              alignSelf: "center" }}>
            +{filteredLolbins.length - 24} more · use Content Pack · LOLBAS for full list
          </div>
        )}
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
          detectionRuleStore · patternRuleStore · GET /api/xdr/lolbas/*
        </span>{" "}· deterministic evidence · never a verdict on its own.
      </div>
    </div>
  );
}
