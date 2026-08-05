/**
 * InvestigationDetailPage — Phase 4 · P1 · Cross-Artifact Correlation.
 *
 * First-class Investigation view. Renders:
 *   • Consolidated Threat Summary (verdict, risk, MITRE, IOCs, artifact types)
 *   • Chain View (default) — top-to-bottom attack chain
 *   • Graph View — force-directed evidence graph
 *   • Timeline View — chronological unified events
 *   • Suggestion Panel — pending auto-correlations to confirm/dismiss
 *   • Manual link/unlink controls
 */
import { useCallback, useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import Header from "@/components/Header";
import NavTabs from "@/components/NavTabs";
import api from "@/lib/api";
import AttackChainView from "@/components/investigation/AttackChainView";
import EvidenceGraphView from "@/components/investigation/EvidenceGraphView";
import UnifiedTimelineView from "@/components/investigation/UnifiedTimelineView";
import CorrelationSuggestionCard from "@/components/investigation/CorrelationSuggestionCard";
import InvestigationThreatSummaryCard from "@/components/investigation/InvestigationThreatSummaryCard";
import { useEvidenceModal } from "@/components/EvidenceModal";
import {
  fromChainStep, fromTimelineEvent, fromMitreEntry,
} from "@/components/evidenceDescriptors";
import { Layers3, Network, Clock3, Sparkles, ArrowLeft, Trash2, Play } from "lucide-react";

export default function InvestigationDetailPage() {
  const { id } = useParams();
  const [inv, setInv] = useState(null);
  const [summary, setSummary] = useState(null);
  const [chain, setChain] = useState(null);
  const [graph, setGraph] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [suggestions, setSuggestions] = useState([]);
  const [tab, setTab] = useState("chain");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  const evi = useEvidenceModal();

  const load = useCallback(async () => {
    setLoading(true); setErr("");
    try {
      const [d, s, c, g, t, sg] = await Promise.all([
        api.get(`/correlations/${id}`),
        api.get(`/correlations/${id}/summary`),
        api.get(`/correlations/${id}/chain`),
        api.get(`/correlations/${id}/graph`),
        api.get(`/correlations/${id}/timeline`),
        api.get(`/correlations/${id}/suggestions`),
      ]);
      setInv(d.data.correlation);
      setSummary(s.data.summary);
      setChain(c.data);
      setGraph(g.data);
      setTimeline(t.data);
      setSuggestions(sg.data.suggestions || []);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || String(e));
    } finally { setLoading(false); }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const onConfirm = async (case_id) => {
    try {
      await api.post(`/correlations/${id}/suggestions/${case_id}/confirm`);
      load();
    } catch (e) { setErr(e?.response?.data?.detail || String(e)); }
  };
  const onDismiss = async (case_id) => {
    try {
      await api.post(`/correlations/${id}/suggestions/${case_id}/dismiss`);
      load();
    } catch (e) { setErr(e?.response?.data?.detail || String(e)); }
  };
  const onUnlink = async (case_id) => {
    if (!window.confirm("Unlink this case from the investigation?")) return;
    try {
      await api.post(`/correlations/${id}/unlink`, { case_id });
      load();
    } catch (e) { setErr(e?.response?.data?.detail || String(e)); }
  };
  const onDelete = async () => {
    if (!window.confirm("Delete this investigation? Member cases will be detached but preserved.")) return;
    try {
      await api.delete(`/correlations/${id}`);
      window.location.href = "/investigations";
    } catch (e) { setErr(e?.response?.data?.detail || String(e)); }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg,#0b1220)" }}>
      <Header />
      <div style={{ maxWidth: 1400, margin: "0 auto", padding: "20px 24px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
          <Link to="/investigations"
                data-testid="investigation-back"
                style={{ color: "#67e8f9", textDecoration: "none",
                         display: "inline-flex", alignItems: "center", gap: 6,
                         fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>
            <ArrowLeft size={14} /> Investigations
          </Link>
          <div style={{ flex: 1 }} />
          {inv?.root_case_id && (
            <Link to={`/investigations/${inv.root_case_id}/replay`}
                  data-testid="investigation-replay"
                  title="Step through the deterministic pipeline for the root case"
                  style={{ padding: "6px 12px", fontSize: 11,
                           background: "rgba(56,189,248,0.10)",
                           color: "#7dd3fc",
                           border: "1px solid rgba(56,189,248,0.35)",
                           borderRadius: 6, cursor: "pointer",
                           fontFamily: "JetBrains Mono, monospace",
                           letterSpacing: "0.08em", textTransform: "uppercase",
                           display: "inline-flex", alignItems: "center", gap: 6,
                           textDecoration: "none", marginRight: 8 }}>
              <Play size={12} /> Replay Investigation
            </Link>
          )}
          <button data-testid="investigation-delete"
                  onClick={onDelete}
                  style={{ padding: "6px 12px", fontSize: 11,
                           background: "rgba(248,113,113,0.10)",
                           color: "#fca5a5",
                           border: "1px solid rgba(248,113,113,0.35)",
                           borderRadius: 6, cursor: "pointer",
                           fontFamily: "JetBrains Mono, monospace",
                           letterSpacing: "0.08em", textTransform: "uppercase",
                           display: "inline-flex", alignItems: "center", gap: 6 }}>
            <Trash2 size={12} /> Delete
          </button>
        </div>

        {err && (
          <div style={{ background: "rgba(248,113,113,0.12)",
                        border: "1px solid rgba(248,113,113,0.35)",
                        color: "#fca5a5", padding: 10, borderRadius: 8,
                        fontSize: 12, marginBottom: 14 }}>{err}</div>
        )}

        {loading && !inv ? (
          <div style={{ opacity: 0.5, fontSize: 13, color: "#64748b",
                        fontFamily: "monospace", padding: 40, textAlign: "center" }}>
            Loading investigation…
          </div>
        ) : inv ? (
          <>
            <div style={{ marginBottom: 16 }}>
              <h1 data-testid="investigation-name"
                  style={{ margin: 0, fontFamily: "JetBrains Mono, monospace",
                           fontSize: 20, fontWeight: 700, color: "#e2e8f0",
                           letterSpacing: "0.03em" }}>
                {inv.name}
              </h1>
              {inv.description && (
                <div style={{ marginTop: 6, fontSize: 12, color: "#94a3b8" }}>
                  {inv.description}
                </div>
              )}
            </div>

            {summary && (
              <div style={{ marginBottom: 20 }}>
                <InvestigationThreatSummaryCard
                  summary={summary}
                  onOpenEvidence={(m) => evi.open(fromMitreEntry(m))} />
              </div>
            )}

            <div style={{ display: "grid",
                          gridTemplateColumns: "minmax(0, 1fr) 320px",
                          gap: 18, alignItems: "start" }}>
              <div style={{ minWidth: 0 }}>
                <NavTabs
                  variant="strip"
                  size="sm"
                  tone="cyan"
                  activeKey={tab}
                  onSelect={setTab}
                  testId="investigation-view-tabs"
                  items={[
                    { key: "chain",    label: "Attack Chain", icon: Layers3, testId: "tab-chain" },
                    { key: "graph",    label: "Evidence Graph", icon: Network, testId: "tab-graph" },
                    { key: "timeline", label: "Timeline", icon: Clock3, testId: "tab-timeline" },
                  ]}
                />
                <div style={{ marginTop: 14 }}>
                  {tab === "chain"    && <AttackChainView chain={chain} onUnlink={onUnlink}
                                            onOpenEvidence={(step) => evi.open(fromChainStep(step))} />}
                  {tab === "graph"    && <EvidenceGraphView graph={graph} />}
                  {tab === "timeline" && <UnifiedTimelineView timeline={timeline}
                                            onOpenEvidence={(ev) => evi.open(fromTimelineEvent(ev))} />}
                </div>
              </div>

              <SidePanel
                inv={inv}
                suggestions={suggestions}
                onConfirm={onConfirm}
                onDismiss={onDismiss}
              />
            </div>
          </>
        ) : (
          <div style={{ opacity: 0.5, fontSize: 13, color: "#64748b",
                        fontFamily: "monospace", padding: 40, textAlign: "center" }}>
            Investigation not found.
          </div>
        )}
      </div>
      {evi.modal}
    </div>
  );
}

function SidePanel({ inv, suggestions, onConfirm, onDismiss }) {
  return (
    <aside style={{ display: "grid", gap: 14 }}>
      <div style={{ background: "rgba(2,6,23,0.6)",
                    border: "1px solid rgba(148,163,184,0.14)",
                    borderRadius: 10, padding: 14 }}
           data-testid="suggestions-panel">
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <Sparkles size={14} style={{ color: "#c4b5fd" }} />
          <div style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11,
                        letterSpacing: "0.1em", textTransform: "uppercase",
                        color: "#c4b5fd" }}>
            Auto-Correlation Suggestions
          </div>
          <span style={{ marginLeft: "auto", fontSize: 10, color: "#64748b" }}>
            {suggestions.length}
          </span>
        </div>
        {suggestions.length === 0 ? (
          <div style={{ fontSize: 11, color: "#64748b", padding: "10px 4px",
                        lineHeight: 1.5 }}
               data-testid="suggestions-empty">
            No new correlation candidates. Auto-scanner checks shared hashes,
            URLs, C2 indicators, and MITRE technique overlap across your
            history.
          </div>
        ) : (
          <div style={{ display: "grid", gap: 10 }}>
            {suggestions.map(s => (
              <CorrelationSuggestionCard
                key={s.case_id}
                suggestion={s}
                onConfirm={() => onConfirm(s.case_id)}
                onDismiss={() => onDismiss(s.case_id)}
              />
            ))}
          </div>
        )}
      </div>

      <div style={{ background: "rgba(2,6,23,0.6)",
                    border: "1px solid rgba(148,163,184,0.14)",
                    borderRadius: 10, padding: 14 }}>
        <div style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11,
                      letterSpacing: "0.1em", textTransform: "uppercase",
                      color: "#94a3b8", marginBottom: 8 }}>
          Metadata
        </div>
        <MetaRow k="Cases"      v={(inv.case_ids || []).length} />
        <MetaRow k="Nodes"      v={(inv.artifact_nodes || []).length} />
        <MetaRow k="Edges"      v={(inv.edges || []).length} />
        <MetaRow k="Dismissed"  v={(inv.dismissed_case_ids || []).length} />
        <MetaRow k="Created"    v={inv.created_at ? new Date(inv.created_at).toLocaleString() : "—"} />
        <MetaRow k="Updated"    v={inv.updated_at ? new Date(inv.updated_at).toLocaleString() : "—"} />
      </div>
    </aside>
  );
}

function MetaRow({ k, v }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                  padding: "5px 0", fontSize: 11,
                  fontFamily: "JetBrains Mono, monospace",
                  borderBottom: "1px dotted rgba(148,163,184,0.10)" }}>
      <span style={{ color: "#64748b" }}>{k}</span>
      <span style={{ color: "#e2e8f0" }}>{v}</span>
    </div>
  );
}
