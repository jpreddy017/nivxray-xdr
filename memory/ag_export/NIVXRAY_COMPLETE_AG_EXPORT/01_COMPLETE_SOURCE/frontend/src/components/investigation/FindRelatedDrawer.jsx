/**
 * FindRelatedDrawer — Phase 4 · P1.
 *
 * Analyst-triggered "Find Related Cases" experience. Launched from a
 * History row action or a Workspace button. Renders:
 *   • Existing investigation (if the case is already correlated)
 *   • Auto-scan suggestions with confirm/dismiss/create actions
 *   • "Create new Investigation from this case" fallback
 */
import { useEffect, useState } from "react";
import api from "@/lib/api";
import CorrelationSuggestionCard from "@/components/investigation/CorrelationSuggestionCard";
import { X, Sparkles, Radar, RefreshCcw, Plus, ExternalLink } from "lucide-react";

export default function FindRelatedDrawer({ caseId, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  const load = async (refresh = false) => {
    setLoading(true); setErr("");
    try {
      const r = await api.post("/correlations/find-related", {
        case_id: caseId, limit: 25, refresh,
      });
      setData(r.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || String(e));
    } finally { setLoading(false); }
  };

  useEffect(() => { load(false); }, [caseId]);

  const linkTo = async (targetCorrelationId, targetCaseId) => {
    try {
      await api.post(`/correlations/${targetCorrelationId}/suggestions/${targetCaseId}/confirm`);
      window.location.assign(`/investigations/${targetCorrelationId}`);
    } catch (e) {
      setErr(e?.response?.data?.detail || String(e));
    }
  };

  const createInvestigation = async () => {
    try {
      const r = await api.post("/correlations", { root_case_id: caseId });
      const cid = r.data?.correlation?.id;
      if (cid) window.location.assign(`/investigations/${cid}`);
    } catch (e) {
      setErr(e?.response?.data?.detail || String(e));
    }
  };

  const confirmSuggestion = async (candidateCaseId) => {
    // Either link to existing investigation OR create a new one seeded from
    // the current case and immediately link the candidate.
    try {
      let cid = data?.existing_investigation?.id;
      if (!cid) {
        const c = await api.post("/correlations", { root_case_id: caseId });
        cid = c.data?.correlation?.id;
      }
      if (!cid) throw new Error("could_not_create_investigation");
      await api.post(`/correlations/${cid}/link`, {
        case_id: candidateCaseId,
        source: "auto_correlated",
      });
      window.location.assign(`/investigations/${cid}`);
    } catch (e) {
      setErr(e?.response?.data?.detail || String(e));
    }
  };

  const dismissSuggestion = async (candidateCaseId) => {
    if (!data?.existing_investigation?.id) {
      // Nothing persistent to dismiss against. Just remove locally.
      setData((d) => ({
        ...d,
        suggestions: d.suggestions.filter(s => s.case_id !== candidateCaseId),
      }));
      return;
    }
    try {
      await api.post(`/correlations/${data.existing_investigation.id}/suggestions/${candidateCaseId}/dismiss`);
      setData((d) => ({
        ...d,
        suggestions: d.suggestions.filter(s => s.case_id !== candidateCaseId),
      }));
    } catch (e) {
      setErr(e?.response?.data?.detail || String(e));
    }
  };

  return (
    <div data-testid="find-related-drawer"
         onClick={onClose}
         style={{
           position: "fixed", inset: 0, zIndex: 60,
           background: "rgba(2,6,23,0.72)",
           display: "flex", justifyContent: "flex-end",
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{ width: "min(560px, 92vw)", height: "100%",
                    background: "linear-gradient(180deg, #0b1220, #050912)",
                    borderLeft: "1px solid rgba(103,232,249,0.30)",
                    overflowY: "auto", padding: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10,
                      marginBottom: 14 }}>
          <Radar size={16} style={{ color: "#67e8f9" }} />
          <div style={{ fontFamily: "JetBrains Mono, monospace",
                        fontSize: 13, letterSpacing: "0.10em",
                        color: "#e2e8f0", textTransform: "uppercase" }}>
            Find Related Cases
          </div>
          <div style={{ flex: 1 }} />
          <button data-testid="find-related-refresh"
                  onClick={() => load(true)}
                  style={btnStyle("cyan")}>
            <RefreshCcw size={12} /> Refresh
          </button>
          <button data-testid="find-related-close"
                  onClick={onClose}
                  style={{ ...btnStyle("neutral"), padding: "5px 8px" }}>
            <X size={13} />
          </button>
        </div>

        {err && (
          <div style={{ background: "rgba(248,113,113,0.10)",
                        border: "1px solid rgba(248,113,113,0.35)",
                        color: "#fca5a5", padding: 10, borderRadius: 8,
                        fontSize: 12, marginBottom: 12 }}>{err}</div>
        )}

        {loading ? (
          <div style={{ padding: 40, textAlign: "center", color: "#64748b",
                        fontFamily: "monospace", fontSize: 13 }}>
            Scanning history for shared evidence…
          </div>
        ) : (
          <>
            {data?.existing_investigation ? (
              <div data-testid="find-related-existing"
                   style={{ background: "rgba(139,92,246,0.10)",
                            border: "1px solid rgba(139,92,246,0.35)",
                            borderRadius: 10, padding: 12, marginBottom: 14 }}>
                <div style={{ fontSize: 10, letterSpacing: "0.12em",
                              color: "#c4b5fd", textTransform: "uppercase",
                              fontFamily: "JetBrains Mono, monospace",
                              marginBottom: 6 }}>
                  This case is part of an Investigation
                </div>
                <div style={{ fontSize: 14, color: "#e2e8f0", fontWeight: 600,
                              fontFamily: "JetBrains Mono, monospace",
                              marginBottom: 8 }}>
                  {data.existing_investigation.name}
                </div>
                <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 10 }}>
                  {data.existing_investigation.case_count} member case{data.existing_investigation.case_count === 1 ? "" : "s"}
                </div>
                <a href={`/investigations/${data.existing_investigation.id}`}
                   data-testid="find-related-open-existing"
                   style={{ ...btnStyle("accent"),
                            textDecoration: "none",
                            display: "inline-flex" }}>
                  <ExternalLink size={12} /> Open Investigation
                </a>
              </div>
            ) : (
              <button data-testid="find-related-create"
                      onClick={createInvestigation}
                      style={{ width: "100%", marginBottom: 14, padding: "10px 12px",
                               background: "rgba(34,197,94,0.10)",
                               color: "#86efac",
                               border: "1px solid rgba(34,197,94,0.35)",
                               borderRadius: 8, cursor: "pointer",
                               fontFamily: "JetBrains Mono, monospace",
                               fontSize: 12, letterSpacing: "0.08em",
                               textTransform: "uppercase",
                               display: "inline-flex", alignItems: "center",
                               justifyContent: "center", gap: 6 }}>
                <Plus size={13} /> Start Investigation From This Case
              </button>
            )}

            <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginBottom: 8 }}>
              <Sparkles size={13} style={{ color: "#c4b5fd" }} />
              <div style={{ fontFamily: "JetBrains Mono, monospace",
                            fontSize: 10, letterSpacing: "0.12em",
                            color: "#c4b5fd", textTransform: "uppercase" }}>
                Cross-Case Suggestions · {data?.count || 0}
              </div>
              <div style={{ marginLeft: "auto", fontSize: 9, color: "#64748b",
                            fontFamily: "JetBrains Mono, monospace" }}>
                {data?.source === "cache" ? "cached" : "live scan"} · min score {data?.min_score}
              </div>
            </div>

            {(data?.suggestions || []).length === 0 ? (
              <div data-testid="find-related-empty"
                   style={{ padding: 24, textAlign: "center", color: "#64748b",
                            border: "1px dashed rgba(148,163,184,0.20)",
                            borderRadius: 8, fontSize: 12, lineHeight: 1.6 }}>
                No cases in your history share deterministic evidence with
                this one — no matching hashes, URLs, C2 indicators, or
                MITRE technique overlap above the confidence threshold.
              </div>
            ) : (
              <div style={{ display: "grid", gap: 10 }}>
                {data.suggestions.map(s => (
                  <CorrelationSuggestionCard
                    key={s.case_id}
                    suggestion={s}
                    onConfirm={() => confirmSuggestion(s.case_id)}
                    onDismiss={() => dismissSuggestion(s.case_id)}
                  />
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function btnStyle(tone) {
  const t = {
    cyan:    { fg: "#67e8f9", bg: "rgba(103,232,249,0.10)", bd: "rgba(103,232,249,0.35)" },
    accent:  { fg: "#86efac", bg: "rgba(34,197,94,0.14)",   bd: "rgba(34,197,94,0.35)" },
    neutral: { fg: "#94a3b8", bg: "rgba(148,163,184,0.06)", bd: "rgba(148,163,184,0.20)" },
  }[tone] || { fg: "#94a3b8", bg: "transparent", bd: "rgba(148,163,184,0.20)" };
  return {
    padding: "5px 10px", fontSize: 10,
    background: t.bg, color: t.fg,
    border: `1px solid ${t.bd}`, borderRadius: 4,
    cursor: "pointer",
    fontFamily: "JetBrains Mono, monospace",
    letterSpacing: "0.08em", textTransform: "uppercase",
    display: "inline-flex", alignItems: "center", gap: 4,
  };
}
