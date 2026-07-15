import { useState, useEffect } from "react";
import { Search, BookOpen, ArrowRight, Sparkles, Download, Link2, ThumbsUp, ThumbsDown } from "lucide-react";
import api from "@/lib/api";
import ReactMarkdown from "react-markdown";
import Header from "@/components/Header";

/**
 * DocsPage — Feb-2026 Phase 1 auto-generated documentation.
 *
 * Left pane:  category tree + search
 * Center:     Markdown-rendered guide OR a single feature detail
 * Right:      "Explain this page" AI helper
 */
export default function DocsPage() {
  const [features, setFeatures] = useState([]);
  const [workflows, setWorkflows] = useState([]);
  const [selected, setSelected] = useState(null); // {kind: "feature"|"workflow", id}
  const [detail, setDetail] = useState(null);
  const [guide, setGuide] = useState("");
  const [audience, setAudience] = useState("user");
  const [q, setQ] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  // Phase 2 chat state — thread is a list of {role: "assistant"|"user", text, suggested?}
  const [thread, setThread] = useState([]);
  const [sessionId, setSessionId] = useState(null);
  const [followup, setFollowup] = useState("");
  const [explaining, setExplaining] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [flowSvg, setFlowSvg] = useState("");

  useEffect(() => {
    // Fetch the 5W1H flow SVG via the authed axios client so it renders
    // even when the assets endpoint requires a Bearer token.
    api.get("/docs/assets/analyst_flow.svg", { responseType: "text" })
       .then((r) => setFlowSvg(typeof r.data === "string" ? r.data : ""))
       .catch(() => setFlowSvg(""));
  }, []);

  const downloadExport = async (fmt) => {
    setDownloading(true);
    try {
      const responseType = fmt === "html" ? "text" : "blob";
      const r = await api.get(`/docs/export/${fmt}?audience=${audience}`, { responseType });
      const mime = fmt === "pdf" ? "application/pdf"
                 : fmt === "html" ? "text/html"
                 : "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
      const blob = new Blob([r.data], { type: mime });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `nivxray-${audience}-guide.${fmt}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      console.error(`${fmt} download failed`, e);
    } finally {
      setDownloading(false);
    }
  };
  const downloadPdf = () => downloadExport("pdf");

  useEffect(() => {
    api.get("/docs/features").then((r) => setFeatures(r.data.features || []));
    api.get("/docs/workflows").then((r) => setWorkflows(r.data.workflows || []));
  }, []);

  useEffect(() => {
    api.get(`/docs/guide?audience=${audience}`).then((r) => setGuide(r.data.markdown));
  }, [audience]);

  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    const path = selected.kind === "feature"
      ? `/docs/features/${selected.id}`
      : `/docs/workflows/${selected.id}`;
    api.get(path).then((r) => setDetail(r.data));
  }, [selected]);

  const runSearch = async (query) => {
    setQ(query);
    if (!query.trim()) { setSearchResults(null); return; }
    const r = await api.get(`/docs/search?q=${encodeURIComponent(query)}`);
    setSearchResults(r.data);
  };

  const runExplain = async (question) => {
    if (!selected) return;
    setExplaining(true);
    // If it's a follow-up (question set), append the user turn immediately.
    if (question) {
      setThread((t) => [...t, { role: "user", text: question }]);
    }
    try {
      const payload = { page: selected.id };
      if (question) payload.question = question;
      if (sessionId) payload.session_id = sessionId;
      const r = await api.post("/docs/explain", payload);
      setSessionId(r.data.session_id || null);
      setThread((t) => [
        ...t,
        {
          role: "assistant",
          text: r.data.explanation || "",
          provider: r.data.provider,
          suggested: r.data.suggested_questions || [],
          related: r.data.related_pages || [],
        },
      ]);
    } catch {
      setThread((t) => [...t, { role: "assistant", text: "Explanation failed.", provider: "error" }]);
    } finally {
      setExplaining(false);
    }
  };

  // Reset chat when the selected page changes
  useEffect(() => {
    setThread([]);
    setSessionId(null);
    setFollowup("");
  }, [selected?.id]);

  const sendFollowup = async () => {
    const q = followup.trim();
    if (!q || explaining) return;
    setFollowup("");
    await runExplain(q);
  };

  const submitVote = async (msgIndex, vote) => {
    const msg = thread[msgIndex];
    if (!msg || msg.role !== "assistant") return;
    try {
      await api.post("/docs/explain/feedback", {
        page: selected?.id || "",
        session_id: sessionId || "",
        message_index: msgIndex,
        vote,
        provider: msg.provider || null,
        question: msgIndex > 0 && thread[msgIndex - 1]?.role === "user"
          ? thread[msgIndex - 1].text : null,
        reply_snippet: (msg.text || "").slice(0, 500),
      });
      // Toggle-mark the message locally so UI reflects the vote.
      setThread((t) => t.map((m, i) =>
        i === msgIndex ? { ...m, vote: m.vote === vote ? null : vote } : m
      ));
    } catch (e) {
      console.error("vote failed", e);
    }
  };

  // Group features by category
  const byCategory = {};
  for (const f of features) {
    const c = f.category || "Uncategorised";
    byCategory[c] = byCategory[c] || [];
    byCategory[c].push(f);
  }

  return (
    <div className="App">
      <Header />
      <div style={{ display: "flex", gap: 16, padding: 16, minHeight: "calc(100vh - 80px)" }} data-testid="docs-page">
      {/* Left nav */}
      <div className="nvx-card" style={{ width: 280, flexShrink: 0, height: "fit-content" }}>
        <div className="nvx-card-head">
          <div className="nvx-card-title"><span className="dot" /> DOCS</div>
        </div>
        <div className="nvx-card-body">
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10 }}>
            <Search size={12} color="#94a3b8" />
            <input
              className="nvx-input"
              placeholder="Search docs…"
              value={q}
              onChange={(e) => runSearch(e.target.value)}
              style={{ flex: 1, fontSize: 12 }}
              data-testid="docs-search"
            />
          </div>
          <div style={{ display: "flex", gap: 4, marginBottom: 10 }}>
            {["user", "admin", "developer"].map((a) => (
              <button
                key={a}
                onClick={() => setAudience(a)}
                className={`nvx-btn sm ${audience === a ? "" : "ghost"}`}
                style={{ flex: 1, fontSize: 10, textTransform: "uppercase" }}
                data-testid={`docs-audience-${a}`}
              >
                {a}
              </button>
            ))}
          </div>

          {searchResults ? (
            <div>
              <div style={{ fontSize: 10, color: "#7ee3c9", fontWeight: 600, marginBottom: 4 }}>
                RESULTS ({searchResults.features.length + searchResults.workflows.length})
              </div>
              {searchResults.features.map((f) => (
                <div key={f.id}
                     onClick={() => setSelected({ kind: "feature", id: f.id })}
                     style={{
                       fontSize: 11, padding: "4px 6px", cursor: "pointer",
                       borderRadius: 3, color: "#c9d1d9",
                       background: selected?.id === f.id ? "rgba(126,227,201,0.08)" : "transparent",
                     }}
                     data-testid={`docs-result-${f.id}`}
                >
                  {f.title}
                </div>
              ))}
              {searchResults.workflows.map((w) => (
                <div key={w.id}
                     onClick={() => setSelected({ kind: "workflow", id: w.id })}
                     style={{ fontSize: 11, padding: "4px 6px", cursor: "pointer",
                              borderRadius: 3, color: "#f59e0b" }}>
                  🔀 {w.title}
                </div>
              ))}
            </div>
          ) : (
            <>
              <div style={{ fontSize: 10, color: "#7ee3c9", fontWeight: 600, marginBottom: 4 }}>
                WORKFLOWS ({workflows.length})
              </div>
              {workflows.map((w) => (
                <div key={w.id}
                     onClick={() => setSelected({ kind: "workflow", id: w.id })}
                     style={{
                       fontSize: 11, padding: "4px 6px", cursor: "pointer",
                       borderRadius: 3, color: "#f59e0b",
                       background: selected?.id === w.id ? "rgba(245,158,11,0.08)" : "transparent",
                       marginBottom: 2,
                     }}
                     data-testid={`docs-workflow-${w.id}`}
                >
                  🔀 {w.title}
                </div>
              ))}

              {Object.entries(byCategory).map(([cat, feats]) => (
                <div key={cat} style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 10, color: "#7ee3c9", fontWeight: 600, marginBottom: 4 }}>
                    {cat.toUpperCase()} ({feats.length})
                  </div>
                  {feats.map((f) => (
                    <div key={f.id}
                         onClick={() => setSelected({ kind: "feature", id: f.id })}
                         style={{
                           fontSize: 11, padding: "4px 6px", cursor: "pointer",
                           borderRadius: 3, color: "#c9d1d9",
                           background: selected?.id === f.id ? "rgba(126,227,201,0.10)" : "transparent",
                           marginBottom: 2,
                         }}
                         data-testid={`docs-feature-${f.id}`}
                    >
                      {f.title}
                    </div>
                  ))}
                </div>
              ))}
            </>
          )}
        </div>
      </div>

      {/* Center content */}
      <div className="nvx-card" style={{ flex: 1, minHeight: 400 }}>
        <div className="nvx-card-head">
          <div className="nvx-card-title">
            <BookOpen size={13} style={{ marginRight: 6 }} />
            {detail ? (detail.title || detail.id) : `${audience.toUpperCase()} GUIDE`}
          </div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
            <button
              className="nvx-btn sm"
              onClick={() => downloadExport("pdf")}
              disabled={downloading}
              style={{ fontSize: 10, display: "flex", alignItems: "center", gap: 4 }}
              title={`Download the ${audience} guide as PDF`}
              data-testid="docs-download-pdf"
            >
              <Download size={11} />
              {downloading ? "…" : "PDF"}
            </button>
            <button
              className="nvx-btn sm ghost"
              onClick={() => downloadExport("html")}
              disabled={downloading}
              style={{ fontSize: 10 }}
              title={`Download the ${audience} guide as HTML`}
              data-testid="docs-download-html"
            >
              HTML
            </button>
            <button
              className="nvx-btn sm ghost"
              onClick={() => downloadExport("docx")}
              disabled={downloading}
              style={{ fontSize: 10 }}
              title={`Download the ${audience} guide as DOCX`}
              data-testid="docs-download-docx"
            >
              DOCX
            </button>
            {selected && (
              <button
                className="nvx-btn sm ghost"
                onClick={() => { setSelected(null); setDetail(null); }}
                style={{ fontSize: 10 }}
                data-testid="docs-back-to-guide"
              >
                ← Back to guide
              </button>
            )}
          </div>
        </div>
        <div className="nvx-card-body" style={{ fontSize: 13, color: "#c9d1d9", lineHeight: 1.6 }}>
          {detail ? (
            <FeatureDetail detail={detail} kind={selected.kind} />
          ) : (
            <div className="docs-md">
              {/* 5W1H analyst flow — inline SVG banner */}
              <div
                data-testid="docs-analyst-flow-banner"
                style={{
                  margin: "0 0 20px", padding: 14,
                  background: "rgba(126,227,201,0.05)",
                  border: "1px solid rgba(126,227,201,0.15)",
                  borderRadius: 4,
                }}>
                <div style={{ fontSize: 12, color: "#7ee3c9",
                              letterSpacing: 0.6, marginBottom: 4 }}>
                  ANALYST FLOW · 5W1H
                </div>
                <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 8 }}>
                  Follow the arrows. Every step answers one of the six analyst
                  questions (What · Where · When · Why · How · Which) and loops
                  back into the learning system.
                </div>
                <img
                  src={`${process.env.REACT_APP_BACKEND_URL || ""}/api/docs/assets/analyst_flow.svg`}
                  alt="NivXRay analyst flow — 5W1H"
                  style={{ width: "100%", height: "auto",
                           background: "#0b1220", borderRadius: 3,
                           display: flowSvg ? "none" : "block" }}
                />
                {flowSvg && (
                  <div
                    data-testid="docs-analyst-flow-svg"
                    style={{ width: "100%", background: "#0b1220",
                             borderRadius: 3, overflow: "hidden" }}
                    dangerouslySetInnerHTML={{ __html: flowSvg }}
                  />
                )}
              </div>
              <ReactMarkdown>{guide}</ReactMarkdown>
            </div>
          )}
        </div>
      </div>

      {/* Right AI helper — Phase 2 chat-style */}
      <div className="nvx-card" style={{ width: 320, flexShrink: 0, display: "flex", flexDirection: "column", maxHeight: "calc(100vh - 120px)" }} data-testid="docs-explain-panel">
        <div className="nvx-card-head">
          <div className="nvx-card-title">
            <Sparkles size={12} style={{ marginRight: 6, color: "#f59e0b" }} />
            EXPLAIN
          </div>
          {thread.length > 0 && (
            <button
              className="nvx-btn sm ghost"
              onClick={() => { setThread([]); setSessionId(null); }}
              style={{ marginLeft: "auto", fontSize: 9 }}
              data-testid="docs-explain-reset"
            >
              RESET
            </button>
          )}
        </div>
        <div className="nvx-card-body" style={{ flex: 1, overflowY: "auto", padding: 10 }}>
          {!selected ? (
            <div style={{ fontSize: 11, color: "#94a3b8", padding: 10, textAlign: "center" }}>
              Select a feature or workflow to unlock the AI explainer.
            </div>
          ) : thread.length === 0 ? (
            <button
              className="nvx-btn sm"
              onClick={() => runExplain()}
              disabled={explaining}
              style={{ width: "100%" }}
              data-testid="docs-explain-btn"
            >
              {explaining ? "Explaining…" : "Explain this page"}
            </button>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {thread.map((msg, i) => (
                <div key={i}
                     data-testid={`docs-explain-msg-${msg.role}-${i}`}
                     style={{
                       padding: 8, borderRadius: 3, fontSize: 11,
                       color: "#c9d1d9",
                       background: msg.role === "user"
                         ? "rgba(126,227,201,0.06)"
                         : "rgba(15,23,42,0.5)",
                       borderLeft: msg.role === "user"
                         ? "2px solid #7ee3c9"
                         : "2px solid #f59e0b",
                     }}>
                  <div style={{ color: "#94a3b8", fontSize: 9, marginBottom: 3, textTransform: "uppercase", letterSpacing: 0.4, display: "flex", alignItems: "center" }}>
                    <span>{msg.role === "user" ? "you" : `via ${msg.provider || "assistant"}`}</span>
                    {msg.role === "assistant" && sessionId && (
                      <span style={{ marginLeft: "auto", display: "flex", gap: 4 }}>
                        <button
                          onClick={() => submitVote(i, "up")}
                          data-testid={`docs-explain-vote-up-${i}`}
                          title="This reply helped"
                          style={{
                            background: msg.vote === "up" ? "rgba(126,227,201,0.20)" : "transparent",
                            border: "1px solid rgba(148,163,184,0.20)",
                            borderRadius: 3, padding: "2px 4px", cursor: "pointer",
                            color: msg.vote === "up" ? "#7ee3c9" : "#94a3b8",
                          }}
                        >
                          <ThumbsUp size={10} />
                        </button>
                        <button
                          onClick={() => submitVote(i, "down")}
                          data-testid={`docs-explain-vote-down-${i}`}
                          title="This reply missed the mark"
                          style={{
                            background: msg.vote === "down" ? "rgba(244,63,94,0.20)" : "transparent",
                            border: "1px solid rgba(148,163,184,0.20)",
                            borderRadius: 3, padding: "2px 4px", cursor: "pointer",
                            color: msg.vote === "down" ? "#f43f5e" : "#94a3b8",
                          }}
                        >
                          <ThumbsDown size={10} />
                        </button>
                      </span>
                    )}
                  </div>
                  <div className="docs-md" style={{ fontSize: 11 }}>
                    <ReactMarkdown>{msg.text || ""}</ReactMarkdown>
                  </div>
                  {msg.role === "assistant" && msg.related && msg.related.length > 0 && i === thread.length - 1 && (
                    <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                      <div style={{ fontSize: 9, color: "#a78bfa", letterSpacing: 0.4, display: "flex", alignItems: "center", gap: 4 }}>
                        <Link2 size={9} /> RELATED (RAG)
                      </div>
                      {msg.related.map((rp, j) => (
                        <button key={rp.id}
                                onClick={() => setSelected({ kind: rp.kind, id: rp.id })}
                                data-testid={`docs-explain-related-${j}`}
                                title={`Jump to ${rp.title} (${rp.kind}, score ${rp.score})`}
                                style={{
                                  fontSize: 10, padding: "4px 6px", textAlign: "left",
                                  background: "rgba(167,139,250,0.06)",
                                  border: "1px solid rgba(167,139,250,0.20)",
                                  borderRadius: 3, color: "#c9d1d9", cursor: "pointer",
                                  display: "flex", alignItems: "center", justifyContent: "space-between", gap: 6,
                                }}>
                          <span>
                            <span style={{ color: rp.kind === "workflow" ? "#f59e0b" : "#7ee3c9", marginRight: 4 }}>
                              {rp.kind === "workflow" ? "🔀" : "▸"}
                            </span>
                            {rp.title}
                          </span>
                          <span style={{ fontSize: 8, color: "#94a3b8" }}>{rp.score}</span>
                        </button>
                      ))}
                    </div>
                  )}
                  {msg.role === "assistant" && msg.suggested && msg.suggested.length > 0 && i === thread.length - 1 && (
                    <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                      <div style={{ fontSize: 9, color: "#7ee3c9", letterSpacing: 0.4 }}>SUGGESTED</div>
                      {msg.suggested.map((sq, j) => (
                        <button key={j}
                                onClick={() => runExplain(sq)}
                                disabled={explaining}
                                data-testid={`docs-explain-suggested-${j}`}
                                style={{
                                  fontSize: 10, padding: "4px 6px", textAlign: "left",
                                  background: "rgba(148,163,184,0.06)",
                                  border: "1px solid rgba(148,163,184,0.15)",
                                  borderRadius: 3, color: "#c9d1d9", cursor: "pointer",
                                }}>
                          {sq}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {explaining && (
                <div style={{ fontSize: 10, color: "#94a3b8", padding: 4 }} data-testid="docs-explain-loading">
                  <ArrowRight size={10} /> thinking…
                </div>
              )}
            </div>
          )}
        </div>
        {selected && thread.length > 0 && (
          <div style={{ padding: 8, borderTop: "1px solid rgba(148,163,184,0.10)", display: "flex", gap: 4 }}>
            <input
              className="nvx-input"
              value={followup}
              onChange={(e) => setFollowup(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") sendFollowup(); }}
              placeholder="Ask a follow-up…"
              disabled={explaining}
              style={{ flex: 1, fontSize: 11 }}
              data-testid="docs-explain-followup"
            />
            <button
              className="nvx-btn sm"
              onClick={sendFollowup}
              disabled={explaining || !followup.trim()}
              style={{ fontSize: 10 }}
              data-testid="docs-explain-send"
            >
              SEND
            </button>
          </div>
        )}
      </div>
      </div>
    </div>
  );
}

function FeatureDetail({ detail, kind }) {
  const [screenshots, setScreenshots] = useState([]);
  useEffect(() => {
    if (kind !== "workflow" || !detail?.id) { setScreenshots([]); return; }
    api.get(`/docs/screenshots/${detail.id}`)
      .then((r) => setScreenshots(r.data?.screenshots || []))
      .catch(() => setScreenshots([]));
  }, [kind, detail?.id]);

  if (kind === "workflow") {
    const shotByStep = {};
    for (const s of screenshots) shotByStep[s.step] = s;
    const backend = process.env.REACT_APP_BACKEND_URL || "";
    return (
      <div>
        <div style={{ color: "#94a3b8", fontStyle: "italic", marginBottom: 12 }}>
          {detail.purpose}
        </div>
        {(detail.steps || []).map((step, i) => {
          const shot = shotByStep[i + 1];
          return (
          <div key={i} style={{ marginBottom: 14, padding: 12, background: "rgba(15,23,42,0.5)", borderRadius: 4 }}>
            <div style={{ color: "#7ee3c9", fontWeight: 600, marginBottom: 4 }}>
              STEP {i + 1} — {step.title}
            </div>
            <div style={{ fontSize: 12 }}>
              <div><b>Action:</b> {step.action}</div>
              <div style={{ marginTop: 4, color: "#94a3b8" }}><b>Expected:</b> {step.expected}</div>
            </div>
            {shot && (
              <img
                src={`${backend}${shot.url}`}
                alt={`Step ${i + 1} screenshot`}
                data-testid={`docs-workflow-screenshot-${i + 1}`}
                style={{
                  marginTop: 10, width: "100%", maxHeight: 320, objectFit: "contain",
                  borderRadius: 3, border: "1px solid rgba(148,163,184,0.15)",
                  background: "#0b1220",
                }}
              />
            )}
          </div>
        );})}
        {detail.related_features && (
          <div style={{ marginTop: 16, fontSize: 12, color: "#94a3b8" }}>
            Related: {detail.related_features.map((r) => (
              <code key={r} style={{ padding: "1px 6px", background: "rgba(148,163,184,0.10)", borderRadius: 2, marginRight: 4 }}>{r}</code>
            ))}
          </div>
        )}
      </div>
    );
  }
  // Feature detail
  const sections = [
    ["Purpose", detail.purpose],
    ["When to use", detail.when_to_use],
    ["Supported formats", detail.supported_formats],
    ["Confidence rules", detail.confidence_rules],
    ["Common errors", detail.common_errors],
    ["Tips", detail.tips],
  ];
  return (
    <div>
      <div style={{ color: "#94a3b8", marginBottom: 12, fontSize: 11 }}>
        <code>{detail.id}</code> · {detail.category} · audience: {detail.audience || "user"}
      </div>
      {sections.map(([label, val]) => {
        if (!val) return null;
        if (Array.isArray(val)) {
          if (val.length === 0) return null;
          return (
            <div key={label} style={{ marginBottom: 12 }}>
              <div style={{ color: "#7ee3c9", fontWeight: 600, fontSize: 11, marginBottom: 4 }}>{label}</div>
              <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12 }}>
                {val.map((v, i) => <li key={i}>{v}</li>)}
              </ul>
            </div>
          );
        }
        return (
          <div key={label} style={{ marginBottom: 12 }}>
            <div style={{ color: "#7ee3c9", fontWeight: 600, fontSize: 11, marginBottom: 4 }}>{label}</div>
            <div style={{ fontSize: 12 }}>{val}</div>
          </div>
        );
      })}
      {detail.examples && detail.examples.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ color: "#7ee3c9", fontWeight: 600, fontSize: 11, marginBottom: 4 }}>Examples</div>
          {detail.examples.map((ex, i) => (
            <div key={i} style={{ padding: 8, background: "rgba(15,23,42,0.5)", borderRadius: 3, marginBottom: 6, fontSize: 11, fontFamily: "monospace" }}>
              <div><span style={{ color: "#94a3b8" }}>Input:</span> {ex.input}</div>
              <div><span style={{ color: "#94a3b8" }}>Output:</span> {ex.output}</div>
              {ex.notes && <div style={{ color: "#f59e0b", marginTop: 4, fontStyle: "italic", fontFamily: "sans-serif" }}>{ex.notes}</div>}
            </div>
          ))}
        </div>
      )}
      {detail.related && detail.related.length > 0 && (
        <div style={{ marginTop: 16, fontSize: 12, color: "#94a3b8" }}>
          Related: {detail.related.map((r) => (
            <code key={r} style={{ padding: "1px 6px", background: "rgba(148,163,184,0.10)", borderRadius: 2, marginRight: 4 }}>{r}</code>
          ))}
        </div>
      )}
    </div>
  );
}
