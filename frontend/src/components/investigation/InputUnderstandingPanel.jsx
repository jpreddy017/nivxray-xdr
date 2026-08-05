/**
 * Input Understanding Panel — the top-of-Workspace card that answers,
 * BEFORE any decoder runs, the two most important analyst questions:
 *
 *   1. What did the analyst give me?     (Input Type + Contents)
 *   2. What am I going to do with it?    (Investigation Plan + Trace)
 *
 * Deterministic — the payload comes from `/api/die/understand`.  This
 * component is presentation-only.
 */
import { CheckCircle2, Circle, Cpu, Layers, Search, Sparkles,
         AlertCircle, ArrowRight, Loader2, Terminal, FileText,
         Binary, Fingerprint, Zap } from "lucide-react";

const TYPE_ICON = {
  powershell_encoded:  Layers,
  powershell_naked:    Terminal,
  nested_shell_chain:  Layers,
  command_chain:       Terminal,
  single_command:      Terminal,
  pe_file:             Binary,
  rtf_document:        FileText,
  office_ole:          FileText,
  pdf_document:        FileText,
  base64_blob:         Binary,
  hex_blob:            Binary,
  gzip_blob:           Binary,
  registry_export:     FileText,
  windows_event_log:   FileText,
  sysmon_log:          FileText,
  process_tree:        Cpu,
  vendor_json:         FileText,
  vendor_report_text:  FileText,
  url_only:            Search,
  plain_text:          FileText,
  unknown:             AlertCircle,
};

const STATUS_TONE = {
  planned: { fg: "#94a3b8", bg: "rgba(148,163,184,0.10)", bd: "rgba(148,163,184,0.30)" },
  running: { fg: "#67e8f9", bg: "rgba(103,232,249,0.10)", bd: "rgba(103,232,249,0.35)" },
  done:    { fg: "#86efac", bg: "rgba(134,239,172,0.08)", bd: "rgba(134,239,172,0.35)" },
  failed:  { fg: "#f87171", bg: "rgba(248,113,113,0.10)", bd: "rgba(248,113,113,0.35)" },
  skipped: { fg: "#64748b", bg: "rgba(100,116,139,0.08)", bd: "rgba(100,116,139,0.30)" },
};

export default function InputUnderstandingPanel({ understanding, loading, error }) {
  if (loading) {
    return (
      <section data-testid="iue-panel-loading" style={panel}>
        <div style={{ ...sectionHeader, color: "#67e8f9" }}>
          <Loader2 size={14} className="spin" /> UNDERSTANDING INPUT…
        </div>
      </section>
    );
  }
  if (error) {
    return (
      <section data-testid="iue-panel-error" style={panel}>
        <div style={{ ...sectionHeader, color: "#fca5a5" }}>
          <AlertCircle size={14} /> INPUT UNDERSTANDING FAILED
        </div>
        <div style={{ marginTop: 6, fontSize: 12, color: "#cbd5e1" }}>{String(error)}</div>
      </section>
    );
  }
  if (!understanding) return null;

  const u = understanding;
  const Icon = TYPE_ICON[u.input_type] || Sparkles;
  const cm = u.confidence_matrix || {};

  return (
    <section data-testid="iue-panel" style={panel}>
      {/* ── Hero sentence — always the FIRST line the analyst reads ── */}
      {u.hero_sentence && (
        <div data-testid="iue-hero" style={{
          padding: "10px 14px", marginBottom: 12,
          background: "rgba(103,232,249,0.08)",
          border: "1px solid rgba(103,232,249,0.35)",
          borderRadius: 8, fontSize: 14, color: "#e2e8f0",
          lineHeight: 1.5,
        }}>
          <span style={{ color: "#67e8f9", fontWeight: 700 }}>▸</span>{" "}
          {u.hero_sentence}
        </div>
      )}

      {/* ── Pipeline Flow Diagram ─────────────────────────────── */}
      {u.pipeline_flow && u.pipeline_flow.length > 0 && (
        <div data-testid="iue-pipeline-flow" style={{
          display: "flex", alignItems: "center", flexWrap: "wrap",
          gap: 6, marginBottom: 12, padding: "6px 0",
        }}>
          {u.pipeline_flow.map((stage, i) => (
            <span key={i} style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              fontSize: 11, fontFamily: "JetBrains Mono, monospace",
            }}>
              <span style={{
                padding: "3px 8px", borderRadius: 4,
                background: i === 0 ? "rgba(103,232,249,0.15)" : "rgba(103,232,249,0.06)",
                border: "1px solid rgba(103,232,249,0.35)",
                color: "#67e8f9", fontWeight: 600,
              }}>
                {stage}
              </span>
              {i < u.pipeline_flow.length - 1 && (
                <ArrowRight size={12} color="#64748b" />
              )}
            </span>
          ))}
        </div>
      )}

      {/* ── Header row · Input Type ───────────────────────────── */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: 14 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 10,
          background: "rgba(103,232,249,0.10)",
          border: "1px solid rgba(103,232,249,0.35)",
          display: "flex", alignItems: "center", justifyContent: "center",
          flexShrink: 0,
        }}>
          <Icon size={22} color="#67e8f9" />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ ...tagline, marginBottom: 2 }}>INPUT UNDERSTOOD</div>
          <div data-testid="iue-input-label" style={{
            fontSize: 18, fontWeight: 700, color: "#e2e8f0",
            letterSpacing: "0.01em",
          }}>{u.label}</div>
          <div style={{ marginTop: 4, fontSize: 12, color: "#94a3b8",
                        fontFamily: "JetBrains Mono, monospace" }}>
            <span data-testid="iue-input-type">{u.input_type}</span>
            {" · "}
            <span data-testid="iue-input-confidence">
              {Math.round((u.confidence || 0) * 100)}%&nbsp;confidence
            </span>
          </div>
          {(u.reasoning || []).length > 0 && (
            <ul style={{ margin: "8px 0 0 0", padding: 0, listStyle: "none" }}>
              {u.reasoning.map((r, i) => (
                <li key={i} style={{ display: "flex", gap: 6,
                                     fontSize: 12, color: "#cbd5e1",
                                     lineHeight: 1.55 }}>
                  <span style={{ color: "#67e8f9" }}>•</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* ── Content summary + confidence matrix ───────────────── */}
      <div style={{ display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
                    gap: 10, marginTop: 14 }}>
        <Stat testid="iue-stat-commands"      label="Commands"     value={u.contents?.commands} />
        <Stat testid="iue-stat-executables"   label="Executables"  value={u.contents?.executables} />
        <Stat testid="iue-stat-registry"      label="Registry"     value={u.contents?.registry_keys} />
        <Stat testid="iue-stat-paths"         label="Paths"        value={u.contents?.file_paths} />
        <Stat testid="iue-stat-urls"          label="URLs"         value={u.contents?.urls} />
        <Stat testid="iue-stat-ips"           label="IPs"          value={u.contents?.ips} />
        <Stat testid="iue-stat-hashes"        label="Hashes"       value={u.contents?.hashes} />
        <Stat testid="iue-stat-stages"        label="Stages"       value={u.contents?.stages} tone="cyan" />
        <Stat testid="iue-stat-edges"         label="Process edges" value={u.contents?.process_edges} />
        <Stat testid="iue-stat-decode-layers" label="Decode layers" value={u.contents?.encoded_layers} />
      </div>

      {/* ── Investigation Plan ────────────────────────────────── */}
      <div style={{ marginTop: 18, display: "grid",
                    gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <PlanBox testid="iue-decode-plan"
          title="DECODE PLAN"
          leadLabel={u.decode_required ? "Required" : "Not required"}
          leadTone={u.decode_required ? "cyan" : "muted"}
          note={u.decode_reason}>
          {u.decode_required && (u.decode_layers || []).length > 0 ? (
            <div style={{ display: "grid", gap: 6, marginTop: 8 }}>
              {u.decode_layers.map((L, i) => (
                <div key={i} data-testid={`iue-decode-layer-${L.index}`}
                     style={layerRow}>
                  <span style={layerBadge}>L{L.index}</span>
                  <span style={{ fontWeight: 600, color: "#e2e8f0" }}>{L.name}</span>
                  <ArrowRight size={12} color="#64748b" />
                  <span style={{ color: "#94a3b8", fontSize: 12 }}>{L.reason}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ marginTop: 8, fontSize: 12, color: "#86efac",
                          display: "flex", alignItems: "center", gap: 6 }}>
              <CheckCircle2 size={14} /> No decoding required
            </div>
          )}
        </PlanBox>

        <PlanBox testid="iue-next-engine"
          title="NEXT ACTION"
          leadLabel={u.next_engine}
          leadTone="cyan"
          note={u.next_engine_reason}>
          <div style={{ marginTop: 10, display: "grid",
                        gridTemplateColumns: "repeat(2, 1fr)", gap: 6 }}>
            <Mini label="Input class."     pct={cm.input_classification} />
            <Mini label="Decode path"      pct={cm.decode_path} />
            <Mini label="Language detect." pct={cm.language_detection} />
            <Mini label="Est. recovery"    pct={cm.estimated_recovery} />
          </div>
        </PlanBox>
      </div>

      {/* ── Engines selected vs skipped ─────────────────────── */}
      {(u.engines_selected?.length || u.engines_skipped?.length) && (
        <div style={{ marginTop: 18, display: "grid",
                      gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div data-testid="iue-engines-selected" style={{
            background: "rgba(134,239,172,0.06)",
            border: "1px solid rgba(134,239,172,0.30)",
            borderRadius: 8, padding: "10px 12px",
          }}>
            <div style={{ ...sectionHeader, color: "#86efac" }}>
              <CheckCircle2 size={11} /> ENGINES SELECTED
            </div>
            <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 5 }}>
              {(u.engines_selected || []).map((e) => (
                <span key={e} style={{
                  padding: "2px 8px", fontSize: 11,
                  color: "#86efac", background: "rgba(134,239,172,0.10)",
                  border: "1px solid rgba(134,239,172,0.35)",
                  borderRadius: 4,
                  fontFamily: "JetBrains Mono, monospace",
                }}>{e}</span>
              ))}
            </div>
          </div>
          <div data-testid="iue-engines-skipped" style={{
            background: "rgba(100,116,139,0.06)",
            border: "1px solid rgba(100,116,139,0.30)",
            borderRadius: 8, padding: "10px 12px",
          }}>
            <div style={{ ...sectionHeader, color: "#94a3b8" }}>
              <Circle size={11} /> ENGINES SKIPPED
            </div>
            <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 5 }}>
              {(u.engines_skipped || []).map((e) => (
                <span key={e} style={{
                  padding: "2px 8px", fontSize: 11,
                  color: "#94a3b8", background: "rgba(100,116,139,0.08)",
                  border: "1px solid rgba(100,116,139,0.30)",
                  borderRadius: 4,
                  fontFamily: "JetBrains Mono, monospace",
                  textDecoration: "line-through",
                }}>{e}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Workspace Plan Checklist + Execution Trace ────────── */}
      <div style={{ marginTop: 18 }}>
        <div style={{ ...sectionHeader, color: "#67e8f9" }}>
          <Zap size={12} /> WORKSPACE PLAN
        </div>
        <div data-testid="iue-plan-list" style={{ marginTop: 8, display: "grid", gap: 6 }}>
          {(u.execution_trace?.length ? u.execution_trace : u.plan || []).map((s, i) => {
            const tone = STATUS_TONE[s.status] || STATUS_TONE.planned;
            const isDone   = s.status === "done";
            const isFailed = s.status === "failed";
            const isRun    = s.status === "running";
            const IconC    = isDone ? CheckCircle2
                          : isFailed ? AlertCircle
                          : isRun ? Loader2
                          : Circle;
            return (
              <div key={s.id || i}
                   data-testid={`iue-plan-step-${s.id}`}
                   style={{
                     display: "grid",
                     gridTemplateColumns: "24px 220px 1fr auto",
                     alignItems: "center", gap: 10,
                     padding: "8px 12px",
                     background: tone.bg, border: `1px solid ${tone.bd}`,
                     borderRadius: 8,
                   }}>
                <IconC size={16} color={tone.fg}
                       className={isRun ? "spin" : ""} />
                <div style={{ fontSize: 13, color: "#e2e8f0", fontWeight: 500 }}>
                  {s.label}
                </div>
                <div style={{ fontSize: 12, color: "#94a3b8",
                              fontFamily: "JetBrains Mono, monospace",
                              overflow: "hidden", textOverflow: "ellipsis",
                              whiteSpace: "nowrap" }}>
                  {s.detail || ""}
                </div>
                <div style={{ fontSize: 11, color: tone.fg,
                              fontFamily: "JetBrains Mono, monospace" }}>
                  {s.ms != null ? `${s.ms.toFixed(1)}ms` : (s.engine || "").toUpperCase()}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <style>{`.spin{animation:spin 1.1s linear infinite}
               @keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </section>
  );
}

/* ── small building blocks ─────────────────────────────────── */
function Stat({ testid, label, value, tone }) {
  const v = value == null ? 0 : value;
  const fg = tone === "cyan" ? "#67e8f9" : "#e2e8f0";
  return (
    <div data-testid={testid} style={{
      background: "rgba(2,6,23,0.55)", border: "1px solid #1f2b3f",
      borderRadius: 8, padding: "8px 12px",
    }}>
      <div style={{ fontSize: 9, letterSpacing: "0.16em",
                    textTransform: "uppercase", color: "#94a3b8" }}>
        {label}
      </div>
      <div style={{ marginTop: 3, fontSize: 20, fontWeight: 700, color: fg,
                    fontFamily: "JetBrains Mono, monospace" }}>
        {v}
      </div>
    </div>
  );
}

function PlanBox({ testid, title, leadLabel, leadTone, note, children }) {
  const fg = leadTone === "cyan" ? "#67e8f9"
           : leadTone === "muted" ? "#94a3b8"
           : "#e2e8f0";
  return (
    <div data-testid={testid} style={{
      background: "rgba(2,6,23,0.55)", border: "1px solid #1f2b3f",
      borderRadius: 10, padding: "12px 14px",
    }}>
      <div style={sectionHeader}>{title}</div>
      <div style={{ marginTop: 6, fontSize: 15, fontWeight: 700, color: fg }}>
        {leadLabel}
      </div>
      {note && (
        <div style={{ marginTop: 4, fontSize: 12, color: "#94a3b8",
                      lineHeight: 1.5 }}>
          {note}
        </div>
      )}
      {children}
    </div>
  );
}

function Mini({ label, pct }) {
  const v = pct == null ? 0 : Math.round(pct * 100);
  const fg = v >= 90 ? "#86efac" : v >= 70 ? "#67e8f9" : v >= 50 ? "#fbbf24" : "#f87171";
  return (
    <div style={{ background: "rgba(2,6,23,0.45)", border: "1px solid #1f2b3f",
                  borderRadius: 6, padding: "6px 8px" }}>
      <div style={{ fontSize: 9, letterSpacing: "0.12em",
                    textTransform: "uppercase", color: "#94a3b8" }}>
        {label}
      </div>
      <div style={{ marginTop: 2, fontSize: 13, fontWeight: 700, color: fg,
                    fontFamily: "JetBrains Mono, monospace" }}>
        {v}%
      </div>
    </div>
  );
}

const panel = {
  background: "linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9))",
  border: "1px solid #1f2b3f",
  borderRadius: 12,
  padding: "16px 18px",
  marginBottom: 14,
};

const sectionHeader = {
  fontSize: 10, letterSpacing: "0.18em",
  textTransform: "uppercase", color: "#94a3b8",
  fontFamily: "JetBrains Mono, monospace",
  display: "inline-flex", alignItems: "center", gap: 6,
};

const tagline = {
  fontSize: 9, letterSpacing: "0.22em",
  textTransform: "uppercase", color: "#67e8f9",
  fontFamily: "JetBrains Mono, monospace",
};

const layerRow = {
  display: "flex", alignItems: "center", gap: 8,
  padding: "6px 8px", background: "rgba(2,6,23,0.45)",
  border: "1px solid #1f2b3f", borderRadius: 6,
  fontSize: 12,
};

const layerBadge = {
  padding: "1px 6px", fontSize: 10, fontWeight: 700,
  color: "#67e8f9", background: "rgba(103,232,249,0.12)",
  border: "1px solid rgba(103,232,249,0.35)",
  borderRadius: 4, fontFamily: "JetBrains Mono, monospace",
};
