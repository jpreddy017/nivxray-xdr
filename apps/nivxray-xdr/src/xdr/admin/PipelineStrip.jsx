/**
 * PipelineStrip — Visualises the NivXRay XDR ingestion pipeline.
 *
 *   Integration → Data Source → Collector → Parser → Normalizer → Canonical Evidence
 *
 * Each stage's count is pulled from the authoritative admin APIs.  A
 * stage with `count === 0` is drawn dim + labelled `NOT CONFIGURED`,
 * never fabricated.  A stage that has no backend yet (Parsers,
 * Normalizers today) is drawn dashed + labelled `PENDING`.
 */
import React, { useEffect, useState } from "react";
import { Plug, HardDrive, Cpu, Filter, Shuffle, Database,
                ChevronRight } from "lucide-react";
import api from "@/lib/api";


const STAGES_STATIC = [
  { key: "integrations",  label: "Integrations", icon: Plug,      path: null },
  { key: "data-sources",  label: "Data Sources", icon: HardDrive, path: "/xdr/data-sources" },
  { key: "collectors",    label: "Collectors",   icon: Cpu,       path: "/xdr/collectors" },
  { key: "parsers",       label: "Parsers",      icon: Filter,    path: null, pending: true },
  { key: "normalizers",   label: "Normalizers",  icon: Shuffle,   path: null, pending: true },
  { key: "evidence",      label: "Canonical Evidence", icon: Database, path: null, terminal: true },
];


export default function PipelineStrip({ testid }) {
  const [counts, setCounts] = useState({});
  const [err,    setErr]    = useState(null);

  useEffect(() => {
    (async () => {
      const c = {};
      // data-sources
      try {
        const r = await api.get("/xdr/data-sources");
        c["data-sources"] = r?.data?.data?.count
                                        ?? (r?.data?.data?.data_sources || []).length;
      } catch { c["data-sources"] = null; }
      // collectors
      try {
        const r = await api.get("/xdr/collectors");
        c["collectors"] = r?.data?.data?.count
                                    ?? (r?.data?.data?.collectors || []).length;
      } catch { c["collectors"] = null; }
      setCounts(c);
    })().catch((e) =>
      setErr(e?.response?.data?.detail || e?.message || "unavailable"));
  }, []);

  return (
    <div data-testid={testid || "admin-pipeline-strip"}
              className="panel"
              style={{
      padding: "12px 14px", marginBottom: 14,
      borderLeft: "3px solid var(--nx-purple, #6D4EE0)",
    }}>
      <div style={{
        fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
        letterSpacing: ".5px", color: "var(--nx-purple, var(--cyan))",
        textTransform: "uppercase", marginBottom: 8,
      }}>
        Ingestion Pipeline
      </div>
      <div style={{
        display: "grid",
        gridTemplateColumns: STAGES_STATIC
              .map(() => "1fr auto").slice(0, -1).join(" ") + " 1fr",
        alignItems: "center", gap: 6,
      }}>
        {STAGES_STATIC.map((s, i) => {
          const raw = counts[s.key];
          const configured = typeof raw === "number";
          const empty      = configured && raw === 0;
          const pending    = !!s.pending;
          const stageState = pending    ? "PENDING"
                                        : !configured  ? (s.terminal ? "DERIVED" : "UNKNOWN")
                                        : empty        ? "NOT CONFIGURED"
                                        :                "CONFIGURED";
          const color = pending    ? "var(--amber)"
                                    : stageState === "NOT CONFIGURED" ? "var(--faint)"
                                    : stageState === "CONFIGURED"     ? "var(--mint)"
                                    :                                       "var(--faint)";
          const border = pending
              ? "1px dashed var(--amber)"
              : "1px solid var(--border)";
          return (
            <React.Fragment key={s.key}>
              <div data-testid={`pipeline-stage-${s.key}`}
                        style={{
                border, borderRadius: 4, padding: "8px 10px",
                background: "var(--panel2)",
                minWidth: 0,
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6,
                                    marginBottom: 4 }}>
                  <s.icon size={11} style={{ color: "var(--cyan)" }} />
                  <span style={{
                    fontFamily: "var(--sans)", fontSize: 11,
                    fontWeight: 700, color: "var(--text)",
                  }}>{s.label}</span>
                </div>
                <div style={{
                  fontFamily: "var(--mono)", fontSize: 9,
                  letterSpacing: ".4px", fontWeight: 700, color,
                }}>
                  {configured
                        ? `${raw} · ${stageState}`
                        : stageState}
                </div>
              </div>
              {i < STAGES_STATIC.length - 1 && (
                <ChevronRight size={11}
                                      style={{ color: "var(--faint)" }} />
              )}
            </React.Fragment>
          );
        })}
      </div>
      {err && (
        <div style={{ marginTop: 6, fontSize: 10,
                            color: "var(--amber)", fontFamily: "var(--mono)" }}>
          {err}
        </div>
      )}
      <div style={{
        marginTop: 8, fontSize: 10, color: "var(--faint)",
        fontFamily: "var(--mono)", lineHeight: 1.5,
      }}>
        Every stage's count is pulled from the authoritative admin API for
        that resource. `PENDING` stages have no backend service yet — the
        UI will never invent one.
      </div>
    </div>
  );
}
