/**
 * FrameworkMappingsPanel — Round 15 · P0.7.2 · Framework Mapping
 * Fabric UI (read-only).
 *
 * Reads
 *   GET /api/admin/content-supply-chain/incidents/:id/framework-mappings
 *
 * Renders the honest state per framework (ATT&CK · D3FEND ·
 * NIST IR · NIST CSF 2.0 · OWASP).  NOT_APPLICABLE frameworks
 * are rendered with the exact backend reason — never hidden.
 */
import React, { useEffect, useState } from "react";
import { Layers, ShieldCheck, GitBranch, BookOpen, Target,
                Circle } from "lucide-react";
import api from "@/lib/api";


const FW_META = {
  mitre_attack:  { label: "MITRE ATT&CK",   icon: Target },
  mitre_d3fend:  { label: "MITRE D3FEND",   icon: ShieldCheck },
  nist_ir:       { label: "NIST IR",        icon: GitBranch },
  nist_csf_2:    { label: "NIST CSF 2.0",   icon: Layers },
  owasp:         { label: "OWASP",          icon: BookOpen },
};

const CONF_COLOR = {
  HIGH:   "var(--mint)",
  MEDIUM: "var(--amber)",
  LOW:    "var(--faint)",
  "N/A":  "var(--faint)",
};


export default function FrameworkMappingsPanel({ incidentId, testid }) {
  const [data,    setData]    = useState(null);
  const [err,     setErr]     = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!incidentId) return;
    setLoading(true); setErr(null); setData(null);
    (async () => {
      try {
        const r = await api.get(
          `/admin/content-supply-chain/incidents/${incidentId}/framework-mappings`);
        setData(r.data);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "unavailable");
      } finally {
        setLoading(false);
      }
    })();
  }, [incidentId]);

  if (!incidentId) return null;
  if (loading) {
    return (
      <div data-testid={testid || "framework-mappings"}
                className="panel" style={{ padding: 12, marginTop: 14,
                                                        fontFamily: "var(--mono)",
                                                        fontSize: 11,
                                                        color: "var(--faint)",
                                                        borderLeft: "3px solid #a78bfa" }}>
        Resolving Framework Mappings for {incidentId}…
      </div>
    );
  }
  if (err || !data) {
    return (
      <div data-testid={testid || "framework-mappings"}
                className="panel" style={{ padding: 12, marginTop: 14,
                                                        color: "var(--amber)" }}>
        {err || "no data"}
      </div>
    );
  }

  return (
    <div data-testid={testid || "framework-mappings"}
              className="panel"
              style={{ padding: "14px 16px", marginTop: 14,
                              borderLeft: "3px solid #a78bfa" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                          marginBottom: 10 }}>
        <span style={{
          fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
          letterSpacing: ".6px", textTransform: "uppercase",
          color: "#a78bfa",
        }}>
          Framework Mapping Fabric · {data.incident_id}
        </span>
        <span style={{ flex: 1 }} />
        <span style={{ fontFamily: "var(--mono)", fontSize: 11,
                            color: "var(--text-dim)" }}>
          {Object.entries(data.counts || {})
                    .map(([k, v]) => `${k}=${v}`).join(" · ")}
        </span>
      </div>

      <div style={{ display: "grid",
                          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                          gap: 10 }}>
        {Object.entries(FW_META).map(([fwId, meta]) => (
          <FrameworkCard key={fwId}
                                fwId={fwId}
                                meta={meta}
                                mappings={data.mappings?.[fwId] || []} />
        ))}
      </div>

      <div style={{ marginTop: 10, fontFamily: "var(--mono)",
                          fontSize: 9.5, color: "var(--faint)",
                          lineHeight: 1.5 }}>
        {data.honesty_note}
      </div>
    </div>
  );
}


function FrameworkCard({ fwId, meta, mappings }) {
  const Icon = meta.icon;
  const active = mappings.filter((m) => m.status === "ACTIVE");
  const not_ap = mappings.filter((m) => m.status === "NOT_APPLICABLE");
  return (
    <div data-testid={`framework-${fwId}`}
              style={{ padding: 10, border: "1px solid var(--border)",
                              borderRadius: 4, background: "var(--panel2)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6,
                          marginBottom: 6 }}>
        <Icon size={12} style={{ color: "#a78bfa" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 12,
                          color: "var(--text)" }}>{meta.label}</b>
        <span style={{ flex: 1 }} />
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                            padding: "1px 6px",
                            border: `1px solid ${active.length
                                                            ? "var(--mint)" : "var(--faint)"}`,
                            color: active.length ? "var(--mint)" : "var(--faint)",
                            borderRadius: 2, fontWeight: 700 }}>
          {active.length ? `${active.length} ACTIVE` : "NOT_APPLICABLE"}
        </span>
      </div>

      {active.map((m) => (
        <div key={m.mapping_id}
                  style={{ padding: "4px 0",
                                  borderBottom: "1px solid var(--border)",
                                  fontFamily: "var(--mono)", fontSize: 10.5 }}>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <b style={{ color: "var(--cyan)" }}>{m.object_id}</b>
            <span style={{ color: "var(--text-dim)" }}>
              {m.object_name}
            </span>
            <span style={{ flex: 1 }} />
            <span style={{
              padding: "0 5px",
              border: `1px solid ${CONF_COLOR[m.confidence] || "var(--faint)"}`,
              color:  CONF_COLOR[m.confidence] || "var(--faint)",
              borderRadius: 2, fontSize: 9, fontWeight: 700,
            }}>{m.confidence}</span>
          </div>
          <div style={{ marginTop: 2, color: "var(--faint)",
                              fontSize: 9.5 }}>
            {m.mapping_method} · {m.rationale}
          </div>
        </div>
      ))}

      {active.length === 0 && not_ap[0] && (
        <div style={{ padding: "4px 0", fontFamily: "var(--mono)",
                            fontSize: 10, color: "var(--faint)",
                            lineHeight: 1.5 }}>
          {not_ap[0].rationale}
        </div>
      )}
    </div>
  );
}
