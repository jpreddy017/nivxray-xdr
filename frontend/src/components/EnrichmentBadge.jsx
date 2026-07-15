import { useState } from "react";
import { Shield, ShieldAlert, ShieldQuestion, ShieldOff, ExternalLink, X, Loader2 } from "lucide-react";
import api from "@/lib/api";

/**
 * EnrichmentBadge — small chip next to an IOC that fetches threat-intel on
 * click and shows the aggregate verdict from VirusTotal / OTX / AbuseIPDB.
 *
 * Props:
 *   value:  string   the IOC (URL, IP, domain, MD5/SHA hash)
 *   input:  string   optional — parent investigation input (logs to timeline)
 *   auto:   bool     if true, look up immediately on mount
 */
const VERDICT_META = {
  malicious: { color: "#f87171", bg: "rgba(248,113,113,0.10)", Icon: ShieldAlert, label: "MALICIOUS" },
  suspicious: { color: "#f59e0b", bg: "rgba(245,158,11,0.10)", Icon: ShieldAlert, label: "SUSPICIOUS" },
  clean: { color: "#7ee3c9", bg: "rgba(126,227,201,0.10)", Icon: Shield, label: "CLEAN" },
  unknown: { color: "#94a3b8", bg: "rgba(148,163,184,0.08)", Icon: ShieldQuestion, label: "UNKNOWN" },
  "no-key": { color: "#64748b", bg: "rgba(100,116,139,0.08)", Icon: ShieldOff, label: "NO KEY" },
  error: { color: "#f87171", bg: "rgba(248,113,113,0.08)", Icon: X, label: "ERROR" },
};

export default function EnrichmentBadge({ value, input, auto = false }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const lookup = async () => {
    if (loading) return;
    setLoading(true);
    try {
      const r = await api.post("/enrichment/ioc", { value });
      setResult(r.data);
    } catch {
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  useState(() => {
    if (auto) lookup();
  }, []);

  const verdict = result?.aggregate?.verdict;
  const meta = verdict ? VERDICT_META[verdict] : null;

  return (
    <span style={{ display: "inline-flex", flexDirection: "column", gap: 3 }}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
        <span style={{ fontSize: 11, fontFamily: "monospace" }}>{value}</span>
        {result === null && !loading ? (
          <button
            className="nvx-btn sm ghost"
            onClick={lookup}
            data-testid={`enrichment-lookup-${value}`}
            style={{ fontSize: 9, padding: "2px 6px" }}
            title="Enrich IOC"
          >
            <Shield size={10} /> ENRICH
          </button>
        ) : loading ? (
          <span style={{ display: "inline-flex", alignItems: "center", color: "#94a3b8" }}>
            <Loader2 size={10} className="spin" />
          </span>
        ) : (
          <span
            onClick={() => setExpanded((s) => !s)}
            style={{
              cursor: "pointer",
              padding: "1px 6px",
              borderRadius: 2,
              background: meta.bg,
              color: meta.color,
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: 0.5,
              display: "inline-flex",
              alignItems: "center",
              gap: 3,
            }}
            data-testid={`enrichment-badge-${value}`}
            title={result?.providers?.map((p) => `${p.provider}: ${p.verdict}`).join(" · ")}
          >
            <meta.Icon size={10} /> {meta.label}
            {result?.aggregate?.sources > 0 && (
              <span style={{ opacity: 0.7 }}>({result.aggregate.sources})</span>
            )}
          </span>
        )}
      </span>
      {expanded && result && (
        <div
          style={{
            padding: "6px 10px", background: "rgba(15,23,42,0.5)",
            borderRadius: 3, fontSize: 10, fontFamily: "monospace",
            color: "#c9d1d9", marginTop: 2, marginLeft: 12,
            borderLeft: `2px solid ${meta.color}`,
          }}
        >
          <div style={{ color: meta.color, fontWeight: 600, marginBottom: 4 }}>
            Kind: {result.kind || "?"} · Aggregate: {meta.label}
          </div>
          {(result.providers || []).map((p, i) => {
            const pMeta = VERDICT_META[p.verdict] || VERDICT_META.unknown;
            return (
              <div key={i} style={{ display: "flex", gap: 6, marginTop: 2 }}>
                <span style={{ color: "#94a3b8", minWidth: 88 }}>{p.provider}</span>
                <span style={{ color: pMeta.color, fontWeight: 600, minWidth: 90 }}>{p.verdict}</span>
                <span style={{ opacity: 0.7 }}>
                  {p.sources > 0 && `${p.sources} src · `}
                  {p.cached && "(cached) · "}
                  {p.details && Object.keys(p.details).length > 0
                    ? JSON.stringify(p.details).slice(0, 100)
                    : ""}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </span>
  );
}
