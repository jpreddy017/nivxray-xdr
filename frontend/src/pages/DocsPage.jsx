import { useState, useEffect } from "react";
import { Search, BookOpen, ArrowRight, Sparkles } from "lucide-react";
import api from "@/lib/api";
import ReactMarkdown from "react-markdown";

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
  const [explain, setExplain] = useState(null);
  const [explaining, setExplaining] = useState(false);

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

  const runExplain = async () => {
    if (!selected) return;
    setExplaining(true);
    try {
      const r = await api.post("/docs/explain", { page: selected.id });
      setExplain(r.data);
    } catch {
      setExplain({ explanation: "Explanation failed." });
    } finally {
      setExplaining(false);
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
          {selected && (
            <button
              className="nvx-btn sm ghost"
              onClick={() => { setSelected(null); setDetail(null); }}
              style={{ marginLeft: "auto", fontSize: 10 }}
              data-testid="docs-back-to-guide"
            >
              ← Back to guide
            </button>
          )}
        </div>
        <div className="nvx-card-body" style={{ fontSize: 13, color: "#c9d1d9", lineHeight: 1.6 }}>
          {detail ? (
            <FeatureDetail detail={detail} kind={selected.kind} />
          ) : (
            <div className="docs-md">
              <ReactMarkdown>{guide}</ReactMarkdown>
            </div>
          )}
        </div>
      </div>

      {/* Right AI helper */}
      <div className="nvx-card" style={{ width: 300, flexShrink: 0, height: "fit-content" }}>
        <div className="nvx-card-head">
          <div className="nvx-card-title">
            <Sparkles size={12} style={{ marginRight: 6, color: "#f59e0b" }} />
            EXPLAIN
          </div>
        </div>
        <div className="nvx-card-body">
          <button
            className="nvx-btn sm"
            onClick={runExplain}
            disabled={!selected || explaining}
            style={{ width: "100%" }}
            data-testid="docs-explain-btn"
          >
            {explaining ? "Explaining…" : selected ? "Explain this page" : "Select a feature"}
          </button>
          {explain && (
            <div
              style={{
                marginTop: 10, padding: 10, background: "rgba(15,23,42,0.5)",
                fontSize: 11, color: "#c9d1d9", borderRadius: 3,
                borderLeft: "2px solid #f59e0b",
              }}
              data-testid="docs-explain-result"
            >
              <div style={{ color: "#94a3b8", fontSize: 10, marginBottom: 4 }}>
                via {explain.provider}
              </div>
              <ReactMarkdown>{explain.explanation || ""}</ReactMarkdown>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function FeatureDetail({ detail, kind }) {
  if (kind === "workflow") {
    return (
      <div>
        <div style={{ color: "#94a3b8", fontStyle: "italic", marginBottom: 12 }}>
          {detail.purpose}
        </div>
        {(detail.steps || []).map((step, i) => (
          <div key={i} style={{ marginBottom: 14, padding: 12, background: "rgba(15,23,42,0.5)", borderRadius: 4 }}>
            <div style={{ color: "#7ee3c9", fontWeight: 600, marginBottom: 4 }}>
              STEP {i + 1} — {step.title}
            </div>
            <div style={{ fontSize: 12 }}>
              <div><b>Action:</b> {step.action}</div>
              <div style={{ marginTop: 4, color: "#94a3b8" }}><b>Expected:</b> {step.expected}</div>
            </div>
          </div>
        ))}
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
