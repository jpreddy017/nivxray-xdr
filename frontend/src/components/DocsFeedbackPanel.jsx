import { useEffect, useState } from "react";
import { ThumbsDown, ThumbsUp, RefreshCw, MessageSquare, ExternalLink } from "lucide-react";
import { Link } from "react-router-dom";
import api from "@/lib/api";

/**
 * DocsFeedbackPanel — surfaces the 👍/👎 signal on Docs Explain replies
 * so admins can see which docs pages need attention.
 *
 * Data source: /api/docs/explain/feedback/stats + /recent
 */
export default function DocsFeedbackPanel() {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [selectedPage, setSelectedPage] = useState(null);
  const [loading, setLoading] = useState(false);

  const load = async (pageFilter) => {
    setLoading(true);
    try {
      const [s, r] = await Promise.all([
        api.get("/docs/explain/feedback/stats"),
        api.get("/docs/explain/feedback/recent", {
          params: { vote: "down", limit: 20, ...(pageFilter ? { page: pageFilter } : {}) },
        }),
      ]);
      setStats(s.data);
      setRecent(r.data.events || []);
    } catch (e) {
      console.error("docs feedback load", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(null); }, []);
  useEffect(() => { if (selectedPage !== null) load(selectedPage); }, [selectedPage]);

  const totals = stats?.totals || { up: 0, down: 0 };
  const weakest = stats?.weakest_pages || [];

  return (
    <section className="brut-border" style={{ background: "var(--surface)" }}
             data-testid="docs-feedback-panel">
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)",
                    display: "flex", alignItems: "center", gap: 10 }}>
        <div className="mono" style={{ fontSize: 11, letterSpacing: "0.24em", color: "var(--accent)" }}>
          ▸ DOCS EXPLAIN FEEDBACK
        </div>
        <div style={{ display: "flex", gap: 6, marginLeft: 12 }}>
          <span style={{ fontSize: 11, color: "#7ee3c9", display: "flex", alignItems: "center", gap: 4 }}
                data-testid="docs-feedback-total-up">
            <ThumbsUp size={11} /> {totals.up}
          </span>
          <span style={{ fontSize: 11, color: "#f43f5e", display: "flex", alignItems: "center", gap: 4 }}
                data-testid="docs-feedback-total-down">
            <ThumbsDown size={11} /> {totals.down}
          </span>
        </div>
        <button onClick={() => { setSelectedPage(null); load(null); }}
                disabled={loading}
                className="nvx-btn sm ghost"
                style={{ marginLeft: "auto", fontSize: 10, display: "flex", alignItems: "center", gap: 4 }}
                data-testid="docs-feedback-refresh">
          <RefreshCw size={11} /> REFRESH
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr", gap: 0 }}>
        {/* Weakest pages */}
        <div style={{ borderRight: "1px solid var(--border)" }}>
          <div style={{ padding: "8px 14px", fontSize: 10, color: "#94a3b8",
                        letterSpacing: 0.4, borderBottom: "1px solid var(--border)" }}>
            WEAKEST PAGES (by net-negative score)
          </div>
          {weakest.length === 0 ? (
            <div style={{ padding: 14, fontSize: 11, color: "#94a3b8", fontStyle: "italic" }}>
              No feedback yet. Analysts vote 👍/👎 on the /docs Explain assistant to populate this.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)", color: "#94a3b8" }}>
                  <th style={{ textAlign: "left", padding: "6px 10px" }}>PAGE</th>
                  <th style={{ textAlign: "right", padding: "6px 6px", width: 40 }}>👍</th>
                  <th style={{ textAlign: "right", padding: "6px 6px", width: 40 }}>👎</th>
                  <th style={{ textAlign: "right", padding: "6px 10px", width: 50 }}>NET</th>
                </tr>
              </thead>
              <tbody>
                {weakest.map((w) => {
                  const isSel = selectedPage === w.page;
                  const netColor = w.net_negative > 0 ? "#f43f5e"
                                 : w.net_negative < 0 ? "#7ee3c9" : "#94a3b8";
                  return (
                    <tr key={w.page}
                        onClick={() => setSelectedPage(isSel ? null : w.page)}
                        data-testid={`docs-feedback-row-${w.page}`}
                        style={{
                          borderBottom: "1px solid rgba(148,163,184,0.10)",
                          cursor: "pointer",
                          background: isSel ? "rgba(126,227,201,0.06)" : "transparent",
                        }}>
                      <td style={{ padding: "6px 10px", color: "#c9d1d9" }}>
                        <code style={{ fontSize: 10 }}>{w.page}</code>
                      </td>
                      <td style={{ padding: "6px 6px", textAlign: "right", color: "#7ee3c9" }}>{w.up}</td>
                      <td style={{ padding: "6px 6px", textAlign: "right", color: "#f43f5e" }}>{w.down}</td>
                      <td style={{ padding: "6px 10px", textAlign: "right",
                                   color: netColor, fontWeight: 600 }}>
                        {w.net_negative > 0 ? `+${w.net_negative}` : w.net_negative}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Recent 👎 events with details */}
        <div>
          <div style={{ padding: "8px 14px", fontSize: 10, color: "#94a3b8",
                        letterSpacing: 0.4, borderBottom: "1px solid var(--border)",
                        display: "flex", alignItems: "center", gap: 6 }}>
            RECENT 👎 {selectedPage && (
              <>
                — filter: <code style={{ fontSize: 10, color: "#f59e0b" }}>{selectedPage}</code>
                <button onClick={() => setSelectedPage(null)}
                        className="nvx-btn sm ghost"
                        style={{ fontSize: 9, padding: "1px 6px", marginLeft: 4 }}>×</button>
              </>
            )}
          </div>
          {recent.length === 0 ? (
            <div style={{ padding: 14, fontSize: 11, color: "#94a3b8", fontStyle: "italic" }}>
              No recent 👎 events for the current filter.
            </div>
          ) : (
            <div style={{ maxHeight: 320, overflowY: "auto" }}>
              {recent.map((ev) => (
                <div key={ev.id}
                     data-testid={`docs-feedback-event-${ev.id}`}
                     style={{
                       padding: "10px 14px", borderBottom: "1px solid rgba(148,163,184,0.10)",
                       fontSize: 11, color: "#c9d1d9",
                     }}>
                  <div style={{ display: "flex", justifyContent: "space-between",
                                alignItems: "center", marginBottom: 4 }}>
                    <span>
                      <code style={{ fontSize: 10, color: "#f59e0b" }}>{ev.page}</code>
                      <span style={{ color: "#94a3b8", marginLeft: 8, fontSize: 10 }}>
                        {ev.analyst_id || "anon"} · via {ev.provider || "?"}
                      </span>
                    </span>
                    <span style={{ fontSize: 10, color: "#64748b" }}>
                      {(ev.created_at || "").slice(0, 19).replace("T", " ")}
                    </span>
                  </div>
                  {ev.question && (
                    <div style={{ marginTop: 4, fontStyle: "italic", color: "#94a3b8" }}>
                      <MessageSquare size={10} style={{ display: "inline", marginRight: 4 }} />
                      Q: {ev.question}
                    </div>
                  )}
                  {ev.reply_snippet && (
                    <div style={{ marginTop: 4, padding: "6px 8px",
                                  background: "rgba(15,23,42,0.5)", borderRadius: 3,
                                  borderLeft: "2px solid #f43f5e", fontSize: 10 }}>
                      {ev.reply_snippet}
                    </div>
                  )}
                  {ev.comment && (
                    <div style={{ marginTop: 4, color: "#f59e0b", fontSize: 10 }}>
                      💬 {ev.comment}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={{ padding: "8px 14px", borderTop: "1px solid var(--border)",
                    fontSize: 10, color: "#94a3b8", display: "flex", justifyContent: "space-between" }}>
        <span>Signal source: <code>learning_events</code> · <code>event_type="docs_explain_feedback"</code></span>
        <Link to="/docs" style={{ color: "#7ee3c9", display: "flex", alignItems: "center", gap: 4 }}>
          Open Docs <ExternalLink size={10} />
        </Link>
      </div>
    </section>
  );
}
