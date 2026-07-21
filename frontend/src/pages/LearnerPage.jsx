/**
 * LearnerPage — /learner
 *
 * Auto-Archetype Learner (Feb 2026). Analysts submit failed payloads with
 * their expected decoded output. The engine features/clusters them, proposes
 * a candidate archetype, and — after a hard NXGEC regression gate + human
 * approval — writes the code into the LEARNED staging file with rollback.
 *
 * Tabs: Inbox · Clusters · Proposals · Approved · History
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import Header from "@/components/Header";
import api from "@/lib/api";
import {
  Inbox as InboxIcon, Layers, FlaskConical, ShieldCheck, History as HistoryIcon,
  Upload, Play, Check, X, RotateCcw, Copy, AlertTriangle,
} from "lucide-react";

const TABS = [
  { key: "inbox",     label: "INBOX",     icon: InboxIcon },
  { key: "clusters",  label: "CLUSTERS",  icon: Layers },
  { key: "proposals", label: "PROPOSALS", icon: FlaskConical },
  { key: "approved",  label: "APPROVED",  icon: ShieldCheck },
  { key: "history",   label: "HISTORY",   icon: HistoryIcon },
];

const STATUS_COLOR = {
  inbox:       "#9ca3af",
  proposed:    "#f59e0b",
  merged:      "#10b981",
  rejected:    "#ef4444",
  rolled_back: "#a855f7",
};


export default function LearnerPage() {
  const [tab, setTab] = useState("inbox");
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);
  const [status, setStatus] = useState("READY");

  return (
    <div data-testid="learner-page">
      <Header />
      <main style={{ maxWidth: 1400, margin: "0 auto", padding: "16px 24px" }}>
        <div style={{ marginBottom: 12 }}>
          <h1 style={{ fontSize: 22, margin: 0, color: "var(--text)" }}>
            Auto-Archetype Learner
          </h1>
          <p style={{ margin: "4px 0 0", fontSize: 12, color: "var(--text-dim)" }}>
            Submit failed payloads + expected output. The engine clusters,
            proposes a candidate archetype, and merges into the LEARNED staging
            file only after NXGEC regression passes and you approve.
          </p>
        </div>

        <TabBar tab={tab} setTab={setTab} />

        <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
          STATUS · <span data-testid="learner-status">{status}</span>
          {err && <span style={{ color: "#ef4444", marginLeft: 12 }}>· {err}</span>}
        </div>

        <div style={{ marginTop: 12 }}>
          {tab === "inbox"     && <InboxTab setStatus={setStatus} setErr={setErr} />}
          {tab === "clusters"  && <ClustersTab setStatus={setStatus} setErr={setErr} />}
          {tab === "proposals" && <ProposalsTab setStatus={setStatus} setErr={setErr} />}
          {tab === "approved"  && <ApprovedTab setStatus={setStatus} setErr={setErr} />}
          {tab === "history"   && <HistoryTab setStatus={setStatus} setErr={setErr} />}
        </div>
      </main>
    </div>
  );
}


function TabBar({ tab, setTab }) {
  return (
    <div style={{ display: "flex", gap: 4, borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
      {TABS.map(({ key, label, icon: Icon }) => (
        <button
          key={key}
          onClick={() => setTab(key)}
          data-testid={`learner-tab-${key}`}
          className="nvx-btn sm ghost"
          style={{
            color: tab === key ? "var(--accent)" : "var(--text-dim)",
            borderColor: tab === key ? "var(--accent)" : "transparent",
          }}
        >
          <Icon size={12} /> {label}
        </button>
      ))}
    </div>
  );
}


// ─── INBOX TAB ─────────────────────────────────────────────────────────

function InboxTab({ setStatus, setErr }) {
  const [rows, setRows]     = useState([]);
  const [filter, setFilter] = useState("inbox");
  const [raw, setRaw]       = useState("");
  const [expected, setExpected] = useState("");
  const [notes, setNotes]   = useState("");
  const [source, setSource] = useState("manual");
  const [dupes, setDupes]   = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [busy, setBusy]     = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.get(`/learner/inbox`, { params: { status: filter, limit: 200 } });
      setRows(r.data.rows || []);
    } catch (e) { setErr(e?.response?.data?.detail || e.message); }
  }, [filter, setErr]);

  useEffect(() => { load(); }, [load]);

  const checkDupes = async () => {
    if (!raw.trim()) return setDupes([]);
    try {
      const r = await api.post("/learner/duplicate-check", { raw_payload: raw });
      setDupes(r.data.dupes || []);
    } catch (_) { setDupes([]); }
  };

  const submit = async () => {
    setErr(null); setStatus("SUBMITTING...");
    setBusy(true);
    try {
      const r = await api.post("/learner/submit", {
        raw_payload: raw,
        expected_output: expected,
        notes,
        dataset_source: source,
      });
      setStatus(`SUBMITTED · id=${(r.data?.id || "").slice(0, 8)} · cluster=${r.data?.cluster_key}`);
      setRaw(""); setExpected(""); setNotes(""); setDupes([]);
      load();
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
      setStatus("SUBMIT FAILED");
    } finally { setBusy(false); }
  };

  const analyze = async (id) => {
    setStatus(`ANALYZING ${id.slice(0, 8)}...`); setBusy(true);
    try {
      const r = await api.post(`/learner/analyze/${id}`);
      setStatus(`PROPOSAL READY · confidence=${r.data?.proposal?.confidence}`);
      load();
      openDetail(id);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
      setStatus("ANALYZE FAILED");
    } finally { setBusy(false); }
  };

  const openDetail = async (id) => {
    setSelected(id);
    try {
      const r = await api.get(`/learner/payload/${id}`);
      setDetail(r.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    }
  };

  const reject = async (id) => {
    const reason = window.prompt("Reject reason (optional):", "");
    if (reason === null) return;
    try {
      await api.post(`/learner/reject/${id}`, { reason });
      setStatus(`REJECTED · ${id.slice(0, 8)}`);
      setDetail(null); setSelected(null); load();
    } catch (e) { setErr(e?.response?.data?.detail || e.message); }
  };

  const approve = async (id) => {
    const approval_notes = window.prompt("Approval notes (optional):", "");
    if (approval_notes === null) return;
    setStatus(`RUNNING REGRESSION + APPROVING ${id.slice(0, 8)}... (up to 90s)`);
    setBusy(true);
    try {
      const r = await api.post(`/learner/approve/${id}`, { approval_notes });
      if (!r.data?.ok) {
        setErr(r.data?.reason || "regression failed");
        setStatus("APPROVAL BLOCKED · regression FAILED");
      } else {
        const im = r.data.impact || {};
        setStatus(`MERGED · pass=${im.passed} fail=${im.failed} · Δcoverage=${im.coverage_delta}`);
        setDetail(null); setSelected(null); load();
      }
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
      setStatus("APPROVE FAILED");
    } finally { setBusy(false); }
  };

  return (
    <div>
      <div className="nvx-card" style={{ marginBottom: 12 }}>
        <div className="nvx-card-head">
          <div className="nvx-card-title">Submit Failed Payload</div>
          <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
            Analyst provides the RAW payload + the EXPECTED decoded output.
          </div>
        </div>
        <div className="nvx-card-body" style={{ display: "grid", gap: 8 }}>
          <textarea
            data-testid="learner-raw-textarea"
            placeholder="Paste the RAW payload NivXRay failed on…"
            value={raw}
            onChange={e => setRaw(e.target.value)}
            onBlur={checkDupes}
            rows={5}
            spellCheck={false}
            style={inputStyle}
          />
          <textarea
            data-testid="learner-expected-textarea"
            placeholder="What NivXRay SHOULD have produced (expected decoded output)…"
            value={expected}
            onChange={e => setExpected(e.target.value)}
            rows={3}
            spellCheck={false}
            style={inputStyle}
          />
          <input
            data-testid="learner-notes-input"
            placeholder="Notes (optional)"
            value={notes}
            onChange={e => setNotes(e.target.value)}
            style={{ ...inputStyle, height: 30 }}
          />
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <label style={{ fontSize: 11, color: "var(--text-dim)" }}>Dataset:</label>
            <select value={source} onChange={e => setSource(e.target.value)}
                    data-testid="learner-source-select"
                    style={{ background: "var(--bg-mute)", color: "var(--text)",
                              border: "1px solid var(--border)", borderRadius: 4,
                              padding: "3px 8px", fontFamily: "JetBrains Mono", fontSize: 11 }}>
              <option value="manual">manual</option>
              <option value="pcap">pcap-capture</option>
              <option value="sandbox">sandbox</option>
              <option value="edr">edr-alert</option>
              <option value="customer">customer-report</option>
            </select>
            <button className="nvx-btn sm primary" onClick={submit}
                    data-testid="learner-submit-btn"
                    disabled={busy || !raw.trim()}>
              <Upload size={12} /> SUBMIT
            </button>
          </div>

          {dupes.length > 0 && (
            <div data-testid="learner-dupes-panel"
                 style={{ padding: 8, background: "var(--bg-mute)",
                          border: "1px dashed #f59e0b", borderRadius: 6 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#f59e0b",
                             marginBottom: 6, display: "flex", alignItems: "center", gap: 6 }}>
                <AlertTriangle size={12} /> POSSIBLE DUPLICATES
              </div>
              {dupes.map(d => (
                <div key={d.id} style={{ fontSize: 11, color: "var(--text-dim)",
                                          marginBottom: 4, fontFamily: "JetBrains Mono" }}>
                  {d.similarity}% · {d.status} · {d.archetype_id || "no-archetype"} · {d.preview}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="nvx-card">
        <div className="nvx-card-head">
          <div className="nvx-card-title">Inbox ({rows.length})</div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <button
              className="nvx-btn xs"
              style={{ background: "#0f766e", color: "#fff", borderColor: "#134e4a" }}
              data-testid="learner-ingest-feedback-btn"
              onClick={async () => {
                try {
                  setStatus?.("ingesting decode_feedback…");
                  const r = await api.post(`/learner/ingest-feedback`);
                  setStatus?.(`ingested ${r.data.ingested} · dupes skipped ${r.data.skipped_dupes}`);
                  load();
                } catch (e) {
                  setErr?.(e?.response?.data?.detail || e?.message || "ingest failed");
                }
              }}
              title="Pull every unprocessed decode_feedback record into this inbox, deduped by SHA1"
            >
              INGEST FEEDBACK
            </button>
            <select value={filter} onChange={e => setFilter(e.target.value)}
                    data-testid="learner-filter-select"
                    style={{ background: "var(--bg-mute)", color: "var(--text)",
                              border: "1px solid var(--border)", borderRadius: 4,
                              padding: "3px 8px", fontFamily: "JetBrains Mono", fontSize: 11 }}>
              {["inbox", "proposed", "merged", "rejected", "rolled_back", "all"].map(s =>
                <option key={s} value={s}>{s}</option>
              )}
            </select>
          </div>
        </div>
        <div className="nvx-card-body">
          <table style={tableStyle}>
            <thead>
              <tr>
                <th>ID</th><th>Cluster</th><th>Status</th><th>Source</th><th>Preview</th><th>Suggested Recipe</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.id} data-testid={`learner-inbox-row-${r.id}`}>
                  <td className="mono">{r.id.slice(0, 8)}</td>
                  <td
                    className="mono"
                    data-testid={`learner-cluster-${r.id}`}
                    style={{
                      // Feb-2026 · disable ligatures so `|-` in the cluster
                      // key does not render as `⊢` (JetBrains Mono ligature)
                      // in the cluster column. The stored key is ASCII-only
                      // (`printable|small|-|-|-`); the ligature substitution
                      // was purely visual.
                      fontVariantLigatures: "none",
                      fontFeatureSettings: '"liga" 0, "calt" 0',
                    }}
                  >
                    {r.cluster_key}
                  </td>
                  <td><StatusBadge s={r.status} /></td>
                  <td>
                    {r.dataset_source === "decode_feedback" ? (
                      <span
                        data-testid={`learner-source-feedback-${r.id}`}
                        title={r.source_feedback_id ? `feedback id: ${r.source_feedback_id}` : "auto-ingested from REPORT BAD DECODE"}
                        style={{
                          background: "#7f1d1d", color: "#fff", padding: "2px 8px",
                          borderRadius: 999, fontSize: 10, letterSpacing: 0.4,
                          display: "inline-block",
                        }}
                      >
                        FEEDBACK
                      </span>
                    ) : (
                      <span className="mono" style={{ color: "var(--text-dim)", fontSize: 10 }}>
                        {r.dataset_source || "manual"}
                      </span>
                    )}
                  </td>
                  <td className="mono" style={{ maxWidth: 300, overflow: "hidden",
                                                textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {r.preview}
                  </td>
                  <td>
                    {Array.isArray(r.ai_suggested_recipe) && r.ai_suggested_recipe.length > 0 ? (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 3, maxWidth: 240 }}>
                        {r.ai_suggested_recipe.slice(0, 4).map((op, i) => (
                          <span
                            key={i}
                            data-testid={`learner-recipe-chip-${r.id}-${i}`}
                            style={{
                              background: "#134e4a", color: "#a7f3d0",
                              padding: "1px 6px", borderRadius: 3, fontSize: 9,
                              fontFamily: "JetBrains Mono",
                            }}
                          >
                            {op}
                          </span>
                        ))}
                        {r.ai_suggested_recipe.length > 4 && (
                          <span style={{ fontSize: 9, color: "var(--text-dim)" }}>
                            +{r.ai_suggested_recipe.length - 4}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span style={{ fontSize: 10, color: "var(--text-dim)" }}>—</span>
                    )}
                  </td>
                  <td>
                    <button className="nvx-btn xs ghost" onClick={() => analyze(r.id)}
                            data-testid={`learner-analyze-${r.id}`}
                            disabled={busy}>
                      <Play size={11} /> ANALYZE
                    </button>
                    <button className="nvx-btn xs ghost" onClick={() => openDetail(r.id)}
                            data-testid={`learner-open-${r.id}`}
                            style={{ marginLeft: 4 }}>
                      OPEN
                    </button>
                  </td>
                </tr>
              ))}
              {!rows.length && (
                <tr><td colSpan={7} style={{ padding: 24, textAlign: "center", color: "var(--text-dim)" }}>
                  No entries. Submit a failed payload above or click INGEST FEEDBACK to pull analyst REPORT BAD DECODE reports.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {detail && (
        <DetailModal detail={detail} onClose={() => { setDetail(null); setSelected(null); }}
                     onApprove={() => approve(selected)}
                     onReject={() => reject(selected)}
                     onAnalyze={() => analyze(selected)} />
      )}
    </div>
  );
}


// ─── CLUSTERS TAB ──────────────────────────────────────────────────────

function ClustersTab({ setStatus, setErr }) {
  const [rows, setRows] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const [members, setMembers]   = useState({});

  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/learner/clusters");
        setRows(r.data.clusters || []);
      } catch (e) { setErr(e?.response?.data?.detail || e.message); }
    })();
  }, [setErr]);

  const toggle = async (ck) => {
    if (expanded === ck) { setExpanded(null); return; }
    setExpanded(ck);
    if (!members[ck]) {
      try {
        const r = await api.get(`/learner/cluster/${encodeURIComponent(ck)}`);
        setMembers(prev => ({ ...prev, [ck]: r.data.rows || [] }));
      } catch (e) { setErr(e?.response?.data?.detail || e.message); }
    }
  };

  return (
    <div className="nvx-card" data-testid="learner-clusters-card">
      <div className="nvx-card-head">
        <div className="nvx-card-title">Clusters ({rows.length})</div>
        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
          Similar failures grouped by feature-hash. Click to expand siblings.
        </div>
      </div>
      <div className="nvx-card-body">
        <table style={tableStyle}>
          <thead>
            <tr><th>Cluster Key</th><th>Count</th><th>Status split</th><th>Last</th></tr>
          </thead>
          <tbody>
            {rows.map(c => (
              <ClusterRows key={c.cluster_key} c={c} expanded={expanded}
                            members={members} toggle={toggle} />
            ))}
            {!rows.length && (
              <tr><td colSpan={4} style={{ padding: 24, textAlign: "center", color: "var(--text-dim)" }}>
                No clusters yet.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}


// ─── PROPOSALS TAB ─────────────────────────────────────────────────────

function ClusterRows({ c, expanded, members, toggle }) {
  return (
    <>
      <tr onClick={() => toggle(c.cluster_key)}
          data-testid={`learner-cluster-row-${c.cluster_key}`}
          style={{ cursor: "pointer" }}>
        <td className="mono">{c.cluster_key}</td>
        <td className="mono">{c.count}</td>
        <td className="mono" style={{ fontSize: 11 }}>
          {Object.entries(c.stats || {}).map(([k, v]) =>
            <span key={k} style={{ marginRight: 8, color: STATUS_COLOR[k] || "var(--text-dim)" }}>
              {k}:{v}
            </span>)}
        </td>
        <td className="mono" style={{ fontSize: 11 }}>{(c.last || "").slice(0, 19)}</td>
      </tr>
      {expanded === c.cluster_key && (members[c.cluster_key] || []).map(m => (
        <tr key={m.id} style={{ background: "var(--bg-mute)" }}
            data-testid={`learner-cluster-member-${m.id}`}>
          <td colSpan={4} className="mono" style={{ fontSize: 11, padding: "4px 10px" }}>
            <StatusBadge s={m.status} /> · {m.id.slice(0, 8)} · {m.preview}
          </td>
        </tr>
      ))}
    </>
  );
}

function ProposalsTab({ setStatus, setErr }) {
  const [rows, setRows] = useState([]);
  const [detail, setDetail] = useState(null);
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.get("/learner/proposals", { params: { limit: 200 } });
      setRows(r.data.rows || []);
    } catch (e) { setErr(e?.response?.data?.detail || e.message); }
  }, [setErr]);

  useEffect(() => { load(); }, [load]);

  const open = async (id) => {
    setSelected(id);
    try {
      const r = await api.get(`/learner/payload/${id}`);
      setDetail(r.data);
    } catch (e) { setErr(e?.response?.data?.detail || e.message); }
  };

  const approve = async (id) => {
    const approval_notes = window.prompt("Approval notes (optional):", "");
    if (approval_notes === null) return;
    setStatus(`REGRESSION + APPROVE ${id.slice(0, 8)}…`);
    setBusy(true);
    try {
      const r = await api.post(`/learner/approve/${id}`, { approval_notes });
      if (!r.data?.ok) {
        setErr(r.data?.reason || "blocked");
        setStatus("APPROVAL BLOCKED · regression FAILED");
      } else {
        const im = r.data.impact || {};
        setStatus(`MERGED · pass=${im.passed} fail=${im.failed} · Δ${im.coverage_delta}`);
        setDetail(null); setSelected(null); load();
      }
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
      setStatus("APPROVE FAILED");
    } finally { setBusy(false); }
  };

  const reject = async (id) => {
    const reason = window.prompt("Reject reason:", "");
    if (reason === null) return;
    try {
      await api.post(`/learner/reject/${id}`, { reason });
      setStatus(`REJECTED · ${id.slice(0, 8)}`);
      setDetail(null); setSelected(null); load();
    } catch (e) { setErr(e?.response?.data?.detail || e.message); }
  };

  return (
    <div className="nvx-card" data-testid="learner-proposals-card">
      <div className="nvx-card-head">
        <div className="nvx-card-title">Proposals ({rows.length})</div>
        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
          Analyzed candidates awaiting human approval.
        </div>
      </div>
      <div className="nvx-card-body">
        <table style={tableStyle}>
          <thead>
            <tr><th>ID</th><th>Archetype</th><th>Confidence</th><th>Chain</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id} data-testid={`learner-proposal-row-${r.id}`}>
                <td className="mono">{r.id.slice(0, 8)}</td>
                <td className="mono">{r.proposal?.archetype_id || "—"}</td>
                <td><ConfidenceChip val={r.proposal?.confidence || 0} /></td>
                <td className="mono" style={{ fontSize: 11 }}>
                  {(r.proposal?.decode_chain || []).join(" → ")}
                </td>
                <td>
                  <button className="nvx-btn xs ghost" onClick={() => open(r.id)}
                          data-testid={`learner-proposal-open-${r.id}`}>
                    OPEN
                  </button>
                  <button className="nvx-btn xs" onClick={() => approve(r.id)}
                          data-testid={`learner-proposal-approve-${r.id}`}
                          disabled={busy}
                          style={{ marginLeft: 4, background: "#10b98122", color: "#10b981" }}>
                    <Check size={11} /> APPROVE
                  </button>
                  <button className="nvx-btn xs ghost" onClick={() => reject(r.id)}
                          data-testid={`learner-proposal-reject-${r.id}`}
                          style={{ marginLeft: 4, color: "#ef4444" }}>
                    <X size={11} /> REJECT
                  </button>
                </td>
              </tr>
            ))}
            {!rows.length && (
              <tr><td colSpan={5} style={{ padding: 24, textAlign: "center", color: "var(--text-dim)" }}>
                No proposals awaiting approval.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {detail && (
        <DetailModal detail={detail} onClose={() => { setDetail(null); setSelected(null); }}
                     onApprove={() => approve(selected)}
                     onReject={() => reject(selected)}
                     onAnalyze={null} />
      )}
    </div>
  );
}


// ─── APPROVED TAB ──────────────────────────────────────────────────────

function ApprovedTab({ setStatus, setErr }) {
  const [rows, setRows] = useState([]);
  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/learner/approved");
        setRows(r.data.rows || []);
      } catch (e) { setErr(e?.response?.data?.detail || e.message); }
    })();
  }, [setErr]);

  return (
    <div className="nvx-card" data-testid="learner-approved-card">
      <div className="nvx-card-head">
        <div className="nvx-card-title">Approved Archetypes ({rows.length})</div>
      </div>
      <div className="nvx-card-body">
        <table style={tableStyle}>
          <thead>
            <tr><th>Approved At</th><th>Archetype</th><th>By</th><th>Impact</th></tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id} data-testid={`learner-approved-row-${r.id}`}>
                <td className="mono" style={{ fontSize: 11 }}>{(r.approved_at || "").slice(0, 19)}</td>
                <td className="mono">{r.proposal?.archetype_id || "—"}</td>
                <td className="mono" style={{ fontSize: 11 }}>{r.approved_by}</td>
                <td className="mono" style={{ fontSize: 11 }}>
                  ✓{r.impact?.passed || 0} · ✗{r.impact?.failed || 0} · Δ{r.impact?.coverage_delta || 0}
                </td>
              </tr>
            ))}
            {!rows.length && (
              <tr><td colSpan={4} style={{ padding: 24, textAlign: "center", color: "var(--text-dim)" }}>
                No archetypes approved yet.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}


// ─── HISTORY TAB ───────────────────────────────────────────────────────

function HistoryTab({ setStatus, setErr }) {
  const [rows, setRows] = useState([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.get("/learner/history");
      setRows(r.data.rows || []);
    } catch (e) { setErr(e?.response?.data?.detail || e.message); }
  }, [setErr]);

  useEffect(() => { load(); }, [load]);

  const rollback = async (id) => {
    if (!window.confirm("Rollback this archetype version? It will be removed from staging."))
      return;
    setBusy(true); setStatus(`ROLLING BACK ${id.slice(0, 8)}…`);
    try {
      await api.post(`/learner/rollback/${id}`);
      setStatus(`ROLLED BACK · ${id.slice(0, 8)}`);
      load();
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
      setStatus("ROLLBACK FAILED");
    } finally { setBusy(false); }
  };

  return (
    <div className="nvx-card" data-testid="learner-history-card">
      <div className="nvx-card-head">
        <div className="nvx-card-title">Version History ({rows.length})</div>
      </div>
      <div className="nvx-card-body">
        <table style={tableStyle}>
          <thead>
            <tr><th>When</th><th>Archetype</th><th>By</th><th>Regression</th><th>State</th><th></th></tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id} data-testid={`learner-history-row-${r.id}`}>
                <td className="mono" style={{ fontSize: 11 }}>{(r.created_at || "").slice(0, 19)}</td>
                <td className="mono">{r.archetype_id}</td>
                <td className="mono" style={{ fontSize: 11 }}>{r.approved_by}</td>
                <td className="mono" style={{ fontSize: 11 }}>
                  ✓{r.regression?.passed || 0} · ✗{r.regression?.failed || 0}
                </td>
                <td>
                  <StatusBadge s={r.rolled_back ? "rolled_back" : "merged"} />
                </td>
                <td>
                  {!r.rolled_back && (
                    <button className="nvx-btn xs ghost" onClick={() => rollback(r.id)}
                            data-testid={`learner-rollback-${r.id}`}
                            disabled={busy} style={{ color: "#a855f7" }}>
                      <RotateCcw size={11} /> ROLLBACK
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {!rows.length && (
              <tr><td colSpan={6} style={{ padding: 24, textAlign: "center", color: "var(--text-dim)" }}>
                No version history yet.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}


// ─── SHARED · DetailModal ──────────────────────────────────────────────

function DetailModal({ detail, onClose, onApprove, onReject, onAnalyze }) {
  if (!detail) return null;
  const p = detail.proposal;
  const copy = (s) => { try { navigator.clipboard.writeText(s || ""); } catch (_) {} };
  return (
    <div data-testid="learner-detail-modal"
         style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)",
                  display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}
         onClick={onClose}>
      <div onClick={e => e.stopPropagation()}
           style={{ background: "var(--surface)", border: "1px solid var(--border)",
                    width: "min(1100px, 95vw)", maxHeight: "90vh", overflow: "auto",
                    borderRadius: 8, padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
          <div>
            <div style={{ fontSize: 16, color: "var(--text)" }}>
              Payload {detail.id?.slice(0, 8)} · <StatusBadge s={detail.status} />
            </div>
            <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>
              cluster={detail.cluster_key} · created_by={detail.created_by}
            </div>
          </div>
          <button className="nvx-btn sm ghost" onClick={onClose}
                  data-testid="learner-detail-close">CLOSE</button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div>
            <div style={sectionTitle}>Raw Payload</div>
            <pre style={preStyle}>{detail.raw_payload}</pre>
          </div>
          <div>
            <div style={sectionTitle}>Expected Output</div>
            <pre style={preStyle}>{detail.expected_output || "(none provided)"}</pre>
          </div>
        </div>

        {detail.notes && (
          <div style={{ marginTop: 10 }}>
            <div style={sectionTitle}>Notes</div>
            <div className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>{detail.notes}</div>
          </div>
        )}

        <div style={{ marginTop: 14, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div>
            <div style={sectionTitle}>Features</div>
            <pre style={preStyle}>{JSON.stringify(detail.features, null, 2)}</pre>
          </div>
          <div>
            <div style={sectionTitle}>Duplicate Hits (at submit)</div>
            <pre style={preStyle}>{JSON.stringify(detail.dupes || [], null, 2)}</pre>
          </div>
        </div>

        {p ? (
          <div style={{ marginTop: 14 }}>
            <div style={sectionTitle}>Proposal · {p.archetype_id}</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <div>
                <div className="mono" style={{ fontSize: 11, marginBottom: 6 }}>
                  <b>Confidence:</b> <ConfidenceChip val={p.confidence} />
                </div>
                <div className="mono" style={{ fontSize: 11 }}>
                  <b>Chain:</b> {(p.decode_chain || []).join(" → ")}
                </div>
                <div className="mono" style={{ fontSize: 11, marginTop: 6 }}>
                  <b>Wrapper regex:</b> {p.wrapper_regex || "(none)"}
                </div>
                <div className="mono" style={{ fontSize: 11, marginTop: 6 }}>
                  <b>Why:</b> {p.why}
                </div>
              </div>
              <div>
                <div style={sectionTitle}>Confidence Breakdown</div>
                <ConfidenceBreakdown b={p.confidence_breakdown || {}} />
                {p.why_not?.missing?.length ? (
                  <div style={{ marginTop: 8, padding: 8, background: "var(--bg-mute)",
                                 border: "1px dashed #a855f7", borderRadius: 6, fontSize: 11 }}>
                    <div style={{ fontWeight: 700, color: "#a855f7", marginBottom: 4 }}>
                      Why not higher?
                    </div>
                    <ul style={{ margin: 0, paddingLeft: 16, color: "var(--text-dim)" }}>
                      {p.why_not.missing.map((m, i) => <li key={i}>{m}</li>)}
                    </ul>
                    <div style={{ marginTop: 6, color: "var(--text)" }}>
                      {p.why_not.recommendation}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
            <div style={{ marginTop: 10 }}>
              <div style={sectionTitle}>
                Candidate Code
                <button className="nvx-btn xs ghost" onClick={() => copy(p.code)}
                        data-testid="learner-detail-copy-code"
                        style={{ marginLeft: 8 }}>
                  <Copy size={11} /> COPY
                </button>
              </div>
              <pre style={{ ...preStyle, maxHeight: 260 }}>{p.code}</pre>
            </div>

            {detail.impact && (
              <div style={{ marginTop: 10 }}>
                <div style={sectionTitle}>Regression Impact</div>
                <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>
                  passed={detail.impact.passed} · failed={detail.impact.failed} ·
                  Δpassed={detail.impact.passed_delta} · Δcoverage={detail.impact.coverage_delta}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div style={{ marginTop: 14, padding: 10, border: "1px dashed var(--border)",
                         borderRadius: 6, fontSize: 12, color: "var(--text-dim)" }}>
            No proposal yet. Run <b>ANALYZE</b> to generate one.
          </div>
        )}

        <div style={{ marginTop: 14, display: "flex", gap: 8 }}>
          {onAnalyze && (
            <button className="nvx-btn sm" onClick={onAnalyze}
                    data-testid="learner-detail-analyze">
              <Play size={12} /> {p ? "RE-ANALYZE" : "ANALYZE"}
            </button>
          )}
          {p && (
            <button className="nvx-btn sm primary" onClick={onApprove}
                    data-testid="learner-detail-approve">
              <Check size={12} /> RUN REGRESSION + APPROVE
            </button>
          )}
          <button className="nvx-btn sm ghost" onClick={onReject}
                  data-testid="learner-detail-reject"
                  style={{ color: "#ef4444" }}>
            <X size={12} /> REJECT
          </button>
        </div>
      </div>
    </div>
  );
}


// ─── SHARED · small components ─────────────────────────────────────────

function StatusBadge({ s }) {
  const color = STATUS_COLOR[s] || "var(--text-dim)";
  return (
    <span className="mono" style={{ fontSize: 10, padding: "2px 6px", borderRadius: 4,
                                     border: `1px solid ${color}`, color }}>
      {s || "?"}
    </span>
  );
}

function ConfidenceChip({ val }) {
  const v = val || 0;
  const c = v >= 80 ? "#10b981" : v >= 50 ? "#f59e0b" : "#ef4444";
  return (
    <span className="mono" data-testid="learner-confidence-chip"
          style={{ fontSize: 11, padding: "2px 8px", borderRadius: 10,
                    background: `${c}22`, color: c, border: `1px solid ${c}` }}>
      {v} / 100
    </span>
  );
}

function ConfidenceBreakdown({ b }) {
  const items = [
    ["Regex",        b.regex        || 0, 35],
    ["Entropy",      b.entropy      || 0, 20],
    ["Charsets",     b.charsets     || 0, 15],
    ["Decode path",  b.decode_path  || 0, 20],
    ["Corpus match", b.corpus_match || 0, 10],
  ];
  return (
    <table className="mono" style={{ fontSize: 11, width: "100%" }}>
      <tbody>
        {items.map(([k, v, mx]) => (
          <tr key={k}>
            <td style={{ color: "var(--text-dim)", width: 100 }}>{k}</td>
            <td style={{ width: "70%" }}>
              <div style={{ height: 6, background: "var(--bg-mute)", borderRadius: 3 }}>
                <div style={{ width: `${(v / mx) * 100}%`, height: 6,
                               background: "var(--accent)", borderRadius: 3 }} />
              </div>
            </td>
            <td style={{ textAlign: "right", color: "var(--text)" }}>{v} / {mx}</td>
          </tr>
        ))}
        <tr>
          <td style={{ color: "var(--text)", fontWeight: 700, paddingTop: 4 }}>Total</td>
          <td></td>
          <td style={{ textAlign: "right", color: "var(--accent)", fontWeight: 700, paddingTop: 4 }}>
            {b.total || 0} / 100
          </td>
        </tr>
      </tbody>
    </table>
  );
}


// ─── styles ────────────────────────────────────────────────────────────

const inputStyle = {
  width: "100%",
  fontFamily: "JetBrains Mono",
  fontSize: 12,
  background: "var(--bg-deep)",
  color: "var(--text)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  padding: 8,
  resize: "vertical",
};

const tableStyle = {
  width: "100%",
  borderCollapse: "collapse",
  fontSize: 12,
  color: "var(--text)",
};

const sectionTitle = {
  fontSize: 11,
  color: "var(--text-dim)",
  textTransform: "uppercase",
  letterSpacing: "0.1em",
  marginBottom: 6,
};

const preStyle = {
  fontFamily: "JetBrains Mono",
  fontSize: 11,
  background: "var(--bg-deep)",
  color: "var(--text)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  padding: 8,
  margin: 0,
  whiteSpace: "pre-wrap",
  wordBreak: "break-all",
  maxHeight: 180,
  overflow: "auto",
};
