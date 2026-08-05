/**
 * InvestigationDetailPage — Phase A.5 · item 3.7 · Attack Story IA.
 *
 * Owner-locked (2026-02-16): the investigation surface uses ONLY four
 * tabs — Overview · Story · Evidence · Report. Replay, Timeline,
 * Trajectory, MITRE, Fingerprint, and Provenance no longer live as
 * separate navigation targets; they are sections within Story or
 * Evidence. Presentation-only refactor — zero backend changes.
 *
 * URL contract: `?tab=<overview|story|evidence|report>` deep-links
 * into a specific tab. The retired route `/investigations/:id/replay`
 * redirects (see App.js) to `?tab=story`.
 */
import { useCallback, useEffect, useState } from "react";
import { useParams, Link, useLocation, useNavigate } from "react-router-dom";
import Header from "@/components/Header";
import NavTabs from "@/components/NavTabs";
import api from "@/lib/api";
import CorrelationSuggestionCard from "@/components/investigation/CorrelationSuggestionCard";
import { useEvidenceModal } from "@/components/EvidenceModal";
import OverviewTab from "@/components/investigation/OverviewTab";
import StoryTab    from "@/components/investigation/StoryTab";
import EvidenceTab from "@/components/investigation/EvidenceTab";
import ReportTab   from "@/components/investigation/ReportTab";
import { LayoutDashboard, BookOpen, Fingerprint, FileText, Sparkles,
         ArrowLeft, Trash2 } from "lucide-react";

const TAB_KEYS = ["overview", "story", "evidence", "report"];

export default function InvestigationDetailPage() {
  const { id } = useParams();
  const location = useLocation();
  const nav = useNavigate();
  const [inv, setInv] = useState(null);
  const [summary, setSummary] = useState(null);
  const [chain, setChain] = useState(null);
  const [graph, setGraph] = useState(null);
  const [suggestions, setSuggestions] = useState([]);
  const [fp, setFp] = useState(null);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  const evi = useEvidenceModal();

  const params = new URLSearchParams(location.search);
  const initialTab = TAB_KEYS.includes(params.get("tab"))
                       ? params.get("tab") : "overview";
  const [tab, setTab] = useState(initialTab);

  useEffect(() => {
    const p = new URLSearchParams(location.search);
    if (p.get("tab") !== tab) {
      p.set("tab", tab);
      nav(`${location.pathname}?${p.toString()}`, { replace: true });
    }
  }, [tab, location.pathname, location.search, nav]);

  const load = useCallback(async () => {
    setLoading(true); setErr("");
    try {
      const [d, s, c, g, sg] = await Promise.all([
        api.get(`/correlations/${id}`),
        api.get(`/correlations/${id}/summary`),
        api.get(`/correlations/${id}/chain`),
        api.get(`/correlations/${id}/graph`),
        api.get(`/correlations/${id}/suggestions`),
      ]);
      setInv(d.data.correlation);
      setSummary(s.data.summary);
      setChain(c.data);
      setGraph(g.data);
      setSuggestions(sg.data.suggestions || []);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || String(e));
    } finally { setLoading(false); }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  // Fingerprint (root-case-scoped) — optional; failure is silent so the
  // page keeps working before the correlation has been fingerprinted.
  useEffect(() => {
    const root = inv?.root_case_id;
    if (!root) return;
    (async () => {
      try {
        const r = await api.get(`/correlations/fingerprint/${root}`);
        setFp(r.data?.fingerprint);
      } catch { /* silently absent */ }
    })();
  }, [inv?.root_case_id]);

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
            </div>

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
                    { key: "overview", label: "Overview", icon: LayoutDashboard, testId: "tab-overview" },
                    { key: "story",    label: "Story",    icon: BookOpen,        testId: "tab-story" },
                    { key: "evidence", label: "Evidence", icon: Fingerprint,     testId: "tab-evidence" },
                    { key: "report",   label: "Report",   icon: FileText,        testId: "tab-report" },
                  ]}
                />
                <div style={{ marginTop: 14 }}>
                  {tab === "overview" && <OverviewTab
                                            inv={inv} summary={summary} fp={fp}
                                            onOpenEvidence={evi.open} />}
                  {tab === "story"    && <StoryTab
                                            caseId={inv.root_case_id}
                                            openEvidence={evi.open} />}
                  {tab === "evidence" && <EvidenceTab
                                            chain={chain} graph={graph}
                                            caseId={inv.root_case_id}
                                            onUnlink={onUnlink}
                                            onOpenEvidence={evi.open} />}
                  {tab === "report"   && <ReportTab
                                            inv={inv} summary={summary}
                                            chain={chain} fp={fp} />}
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
