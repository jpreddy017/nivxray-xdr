/**
 * TrainingInboxPage — /admin/training-inbox   (admin-only)
 *
 * CTI RSS Crawler inbox — reviews pending training-note drafts crawled
 * from BleepingComputer / Unit42 / DFIR Report / etc. Admin can
 *   · Filter by status (pending / promoted / dismissed / all)
 *   · Crawl-now (with or without LLM condensation)
 *   · Promote a draft → creates an active training_note in admin_models
 *   · Dismiss / delete a draft
 *
 * Backend routes: /api/threat-intel/rss/*
 */
import { useEffect, useState } from "react";
import Header from "@/components/Header";
import api from "@/lib/api";
import { RefreshCw, Check, X, Trash2, ExternalLink, Rss, Play, AlertCircle } from "lucide-react";

const STATUS_COLORS = {
  pending:   "#f59e0b",
  promoted:  "#10b981",
  dismissed: "#6b7280",
};

export default function TrainingInboxPage() {
  const [feeds, setFeeds]         = useState([]);
  const [items, setItems]         = useState([]);
  const [counts, setCounts]       = useState({});
  const [status, setStatus]       = useState("pending");
  const [busy, setBusy]           = useState(false);
  const [crawling, setCrawling]   = useState(false);
  const [err, setErr]             = useState(null);
  const [selectedFeeds, setSelectedFeeds] = useState([]);
  const [condense, setCondense]   = useState(false);   // LLM condense on manual crawl
  const [expanded, setExpanded]   = useState(null);    // id of expanded row

  const load = async () => {
    setBusy(true); setErr(null);
    try {
      const [fRes, pRes] = await Promise.all([
        api.get("/threat-intel/rss/feeds"),
        api.get(`/threat-intel/rss/pending?status=${status}&limit=100`),
      ]);
      setFeeds(fRes.data.feeds || []);
      setItems(pRes.data.items || []);
      setCounts(pRes.data.counts || {});
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  // `load` is stable; re-run only when `status` filter changes.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [status]);

  const runCrawl = async () => {
    setCrawling(true); setErr(null);
    try {
      const r = await api.post("/threat-intel/rss/crawl",
        { feed_ids: selectedFeeds.length ? selectedFeeds : null,
          condense_with_llm: condense },
        { timeout: 180_000 });
      await load();
      alert(`Crawl complete — ${r.data.total_new} new draft${r.data.total_new === 1 ? "" : "s"} added.`);
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setCrawling(false); }
  };

  const promote = async (item) => {
    const title = window.prompt("Confirm title (or press Enter to keep as-is):", item.draft_title);
    if (title === null) return;
    setBusy(true);
    try {
      await api.post(`/threat-intel/rss/pending/${item.id}/promote`,
        { title: title || item.draft_title, body: item.draft_body, tags: item.draft_tags });
      await load();
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  const dismiss = async (item) => {
    if (!window.confirm(`Dismiss "${item.article_title.slice(0, 80)}"?`)) return;
    setBusy(true);
    try {
      await api.post(`/threat-intel/rss/pending/${item.id}/dismiss`);
      await load();
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  const hardDelete = async (item) => {
    if (!window.confirm(`PERMANENTLY delete this draft? (${item.article_title.slice(0, 60)})`)) return;
    setBusy(true);
    try {
      await api.delete(`/threat-intel/rss/pending/${item.id}`);
      await load();
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  const toggleFeed = (id) => setSelectedFeeds(cur =>
    cur.includes(id) ? cur.filter(x => x !== id) : [...cur, id]);

  return (
    <div data-testid="training-inbox-page">
      <Header />
      <main style={{ maxWidth: 1400, margin: "0 auto", padding: "16px 24px" }}>
        <div style={{ marginBottom: 12 }}>
          <h1 style={{ fontSize: 22, margin: 0, color: "var(--text)", display: "flex", alignItems: "center", gap: 8 }}>
            <Rss size={20} /> CTI Training-Note Inbox
          </h1>
          <p style={{ margin: "4px 0 0", fontSize: 12, color: "var(--text-dim)" }}>
            Auto-crawled research articles from BleepingComputer, Unit 42, DFIR Report &amp; more.
            Each match is condensed into a directive-form draft. Promote high-value drafts to activate them.
          </p>
        </div>

        {/* ── Feed picker + crawl controls ────────────────────────────── */}
        <div className="nvx-card" style={{ marginBottom: 12 }}>
          <div className="nvx-card-head">
            <div className="nvx-card-title">Feeds ({feeds.length})</div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 11 }}>
              <label style={{ color: "var(--text-dim)", cursor: "pointer" }}
                     data-testid="crawl-condense-label">
                <input type="checkbox" checked={condense}
                       onChange={e => setCondense(e.target.checked)}
                       data-testid="crawl-condense-toggle" />{" "}
                Condense with LLM (slower, higher quality)
              </label>
              <button onClick={runCrawl} disabled={crawling || busy}
                      data-testid="crawl-now-btn"
                      className="nvx-btn sm primary">
                <Play size={12} /> {crawling ? "CRAWLING…" : (
                  selectedFeeds.length ? `CRAWL ${selectedFeeds.length} FEED${selectedFeeds.length===1?"":"S"}` : "CRAWL ALL FEEDS"
                )}
              </button>
            </div>
          </div>
          <div className="nvx-card-body">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 8 }}>
              {feeds.map(f => (
                <label key={f.id} data-testid={`feed-${f.id}`}
                       style={{ display: "flex", gap: 6, alignItems: "flex-start",
                                 padding: 8, borderRadius: 4, cursor: "pointer",
                                 border: "1px solid var(--border)",
                                 background: selectedFeeds.includes(f.id) ? "rgba(96,165,250,0.05)" : "transparent" }}>
                  <input type="checkbox" checked={selectedFeeds.includes(f.id)}
                         onChange={() => toggleFeed(f.id)} />
                  <div style={{ fontSize: 11, lineHeight: 1.4 }}>
                    <div style={{ color: "var(--text)", fontWeight: 500 }}>{f.name}</div>
                    <div style={{ color: "var(--text-dim)" }}>
                      {f.last_status
                        ? <>Last: {f.last_status} · new={f.last_new || 0} · skip={f.last_skipped || 0}</>
                        : "never crawled"}
                    </div>
                    {f.last_error && (
                      <div style={{ color: "#ef4444", fontSize: 10 }}
                           title={f.last_error}>⚠ {f.last_error.slice(0, 60)}</div>
                    )}
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>

        {/* ── Status filter tabs ─────────────────────────────────────── */}
        <div style={{ display: "flex", gap: 4, marginBottom: 8 }}>
          {["pending", "promoted", "dismissed", "all"].map(s => (
            <button key={s} onClick={() => setStatus(s)}
                    data-testid={`filter-${s}`}
                    className={`nvx-btn sm ${status === s ? "primary" : "ghost"}`}
                    style={{ textTransform: "uppercase" }}>
              {s}{" "}
              {counts[s] !== undefined && s !== "all" && (
                <span style={{ opacity: 0.6, marginLeft: 4 }}>({counts[s]})</span>
              )}
            </button>
          ))}
          <button onClick={load} disabled={busy}
                  data-testid="refresh-btn"
                  className="nvx-btn sm ghost" style={{ marginLeft: "auto" }}>
            <RefreshCw size={12} /> REFRESH
          </button>
        </div>

        {err && (
          <div style={{ padding: 10, marginBottom: 8, background: "rgba(239,68,68,0.08)",
                        border: "1px solid rgba(239,68,68,0.3)", borderRadius: 4,
                        fontSize: 12, color: "#ef4444" }}
               data-testid="inbox-error">
            <AlertCircle size={12} style={{ verticalAlign: "middle" }} /> {err}
          </div>
        )}

        {/* ── Pending items list ─────────────────────────────────────── */}
        {items.length === 0 ? (
          <div className="nvx-card">
            <div className="nvx-card-body" style={{ textAlign: "center", padding: 40, color: "var(--text-dim)" }}
                 data-testid="inbox-empty">
              {busy ? "Loading…" : `No ${status === "all" ? "" : status} drafts.`}
              {status === "pending" && !busy && (
                <div style={{ marginTop: 8, fontSize: 11 }}>Try clicking "CRAWL ALL FEEDS" above.</div>
              )}
            </div>
          </div>
        ) : (
          items.map(it => (
            <div key={it.id} className="nvx-card" style={{ marginBottom: 8 }} data-testid={`inbox-item-${it.id}`}>
              <div className="nvx-card-head" style={{ alignItems: "flex-start" }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 11, color: STATUS_COLORS[it.status] || "var(--text-dim)", textTransform: "uppercase", fontWeight: 600 }}>
                      {it.status}
                    </span>
                    <span style={{ fontSize: 10, color: "var(--text-dim)" }}>· {it.feed_name}</span>
                    <span style={{ fontSize: 10, color: "var(--text-dim)" }}>· score {it.keyword_score}</span>
                    {it.condensed && (
                      <span style={{ fontSize: 10, color: "var(--accent)" }}>· LLM-condensed</span>
                    )}
                    {(it.keywords_hit || []).slice(0, 4).map(k => (
                      <span key={k} style={{ fontSize: 9, padding: "1px 5px", borderRadius: 2,
                                              background: "rgba(96,165,250,0.1)", color: "var(--accent)" }}>{k}</span>
                    ))}
                  </div>
                  <div style={{ fontSize: 13, color: "var(--text)", marginTop: 4, fontWeight: 500 }}>
                    {it.article_title}
                  </div>
                  <a href={it.source_url} target="_blank" rel="noreferrer"
                     style={{ fontSize: 11, color: "var(--accent)", display: "inline-flex", alignItems: "center", gap: 3, marginTop: 2 }}>
                    <ExternalLink size={10} /> {it.source_url}
                  </a>
                </div>
                <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                  {it.status === "pending" && (
                    <>
                      <button onClick={() => promote(it)} disabled={busy}
                              data-testid={`promote-${it.id}`}
                              className="nvx-btn sm primary">
                        <Check size={12} /> PROMOTE
                      </button>
                      <button onClick={() => dismiss(it)} disabled={busy}
                              data-testid={`dismiss-${it.id}`}
                              className="nvx-btn sm ghost">
                        <X size={12} /> DISMISS
                      </button>
                    </>
                  )}
                  <button onClick={() => hardDelete(it)} disabled={busy}
                          data-testid={`delete-${it.id}`}
                          className="nvx-btn sm ghost" title="Delete permanently">
                    <Trash2 size={12} />
                  </button>
                  <button onClick={() => setExpanded(expanded === it.id ? null : it.id)}
                          data-testid={`expand-${it.id}`}
                          className="nvx-btn sm ghost">
                    {expanded === it.id ? "HIDE" : "PREVIEW"}
                  </button>
                </div>
              </div>
              {expanded === it.id && (
                <div className="nvx-card-body" style={{ borderTop: "1px solid var(--border)" }}>
                  <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 4 }}>
                    <strong>Draft title:</strong> {it.draft_title}
                  </div>
                  <pre style={{ fontFamily: "JetBrains Mono", fontSize: 11,
                                background: "var(--bg-deep)", padding: 10, borderRadius: 4,
                                whiteSpace: "pre-wrap", color: "var(--text)",
                                maxHeight: 300, overflowY: "auto" }}>
                    {it.draft_body}
                  </pre>
                  {it.condense_error && (
                    <div style={{ marginTop: 6, fontSize: 10, color: "#ef4444" }}>
                      LLM condense error: {it.condense_error}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </main>
    </div>
  );
}
