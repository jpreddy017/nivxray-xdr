/**
 * v2/pages/IngestionPage.jsx · Investigation Ingestion Engine (Phase 4.1).
 *
 * Drag-drop uploader → detects format / source → normalizes into the
 * Canonical Event Schema → creates a fresh v2 case → opens the
 * Investigation Workspace against it.
 *
 * Also hosts the Golden Investigation Corpus seed buttons so any
 * analyst can spin up a benchmark case with one click.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import api from "@/lib/api";
import { T } from "@/v2/theme";
import Header from "@/components/Header";

// ─── Small primitives ────────────────────────────────────────────────
const Pill = ({ children, tone = "neutral" }) => {
  const tones = {
    neutral: { bg: T.paper2, fg: T.inkDim, br: T.line },
    ok:      { bg: T.amberBg, fg: T.green, br: T.amber },
    warn:    { bg: "rgba(248,113,113,0.10)", fg: T.red, br: T.red },
    info:    { bg: T.blueT, fg: T.blue, br: T.blue },
  };
  const s = tones[tone] || tones.neutral;
  return (
    <span
      style={{
        display: "inline-flex", alignItems: "center",
        padding: "2px 10px", borderRadius: 999,
        fontSize: 11, letterSpacing: "0.06em",
        background: s.bg, color: s.fg, border: `1px solid ${s.br}`,
        fontFamily: "JetBrains Mono, monospace",
      }}
    >{children}</span>
  );
};

const Card = ({ children, style }) => (
  <div
    style={{
      background: T.cardGradient,
      border: `1px solid ${T.line}`,
      borderRadius: 12,
      padding: 20,
      ...style,
    }}
  >{children}</div>
);

// ─── Ingestion metrics readout ───────────────────────────────────────
function MetricsPanel({ result }) {
  const m = result?.metrics || {};
  const rows = [
    ["Files uploaded",         m.files_uploaded ?? 0],
    ["Files parsed",           m.files_parsed ?? 0],
    ["Events parsed",          m.events_parsed ?? 0],
    ["Events normalized",      m.events_normalized ?? 0],
    ["Events persisted",       m.events_persisted ?? 0],
    ["Normalization coverage", `${m.normalization_coverage ?? 0}%`],
    ["Duration",               `${m.duration_ms ?? 0} ms`],
  ];
  const fmts = Object.entries(m.detected_formats || {});
  const srcs = Object.entries(m.detected_sources || {});
  return (
    <Card style={{ marginTop: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <div style={{ color: T.ink, fontSize: 14, fontWeight: 600 }}>Ingestion Quality Metrics</div>
        <Pill tone={result.ok ? "ok" : "warn"}>{result.ok ? "OK" : "FAILED"}</Pill>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "8px 24px" }}>
        {rows.map(([k, v]) => (
          <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
            <span style={{ color: T.inkMute, fontFamily: "JetBrains Mono, monospace" }}>{k}</span>
            <span style={{ color: T.ink, fontFamily: "JetBrains Mono, monospace", fontWeight: 600 }}>{v}</span>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 12, display: "flex", gap: 6, flexWrap: "wrap" }}>
        {fmts.map(([k, v]) => <Pill key={`f-${k}`} tone="info">format · {k} × {v}</Pill>)}
        {srcs.map(([k, v]) => <Pill key={`s-${k}`} tone="info">source · {k} × {v}</Pill>)}
      </div>
      {Array.isArray(m.unknown_event_ids) && m.unknown_event_ids.length > 0 && (
        <div style={{ marginTop: 10, fontSize: 11, color: T.amber, fontFamily: "JetBrains Mono, monospace" }}>
          Unknown event IDs: {m.unknown_event_ids.join(", ")}
        </div>
      )}
      {Array.isArray(m.parse_errors) && m.parse_errors.length > 0 && (
        <div style={{ marginTop: 6, fontSize: 11, color: T.red, fontFamily: "JetBrains Mono, monospace" }}>
          {m.parse_errors.length} parse error(s) — first: {m.parse_errors[0]}
        </div>
      )}
    </Card>
  );
}

// ─── Main page ───────────────────────────────────────────────────────
export default function IngestionPage() {
  const nav = useNavigate();
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [formats, setFormats] = useState(null);
  const [golden, setGolden] = useState([]);

  useEffect(() => {
    api.get(`/v2/ingestion/formats`)
      .then(r => setFormats(r.data))
      .catch(() => setFormats(null));
    api.get(`/v2/ingestion/golden`)
      .then(r => setGolden(r.data?.datasets || []))
      .catch(() => setGolden([]));
  }, []);

  const submitFile = useCallback(async (file) => {
    if (!file) return;
    setUploading(true);
    setResult(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const { data } = await api.post(
        `/v2/ingestion/upload`,
        form,
        { headers: { "Content-Type": "multipart/form-data" }, timeout: 120000 }
      );
      setResult(data);
      if (data.ok) {
        toast.success(`Ingested ${data.metrics?.events_persisted ?? 0} events`);
      } else {
        toast.error("Ingestion failed", { description: data.error || "unknown" });
      }
    } catch (ex) {
      toast.error("Upload failed", { description: ex?.response?.data?.detail || String(ex) });
      setResult({ ok: false, error: String(ex), metrics: {} });
    } finally {
      setUploading(false);
    }
  }, []);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer?.files?.[0];
    if (f) submitFile(f);
  }, [submitFile]);

  const seedGolden = useCallback(async (dsId) => {
    setUploading(true);
    setResult(null);
    try {
      const { data } = await api.post(
        `/v2/ingestion/golden/${dsId}`,
        new FormData(),                         // empty body
      );
      setResult(data);
      toast.success(`Seeded ${dsId}`, { description: `Case ${data.case_id}` });
    } catch (ex) {
      toast.error("Seed failed", { description: ex?.response?.data?.detail || String(ex) });
    } finally {
      setUploading(false);
    }
  }, []);

  const openWorkspace = () => {
    if (result?.workspace_url) nav(result.workspace_url);
  };

  return (
    <div
      data-testid="ingestion-page"
      style={{
        minHeight: "100vh",
        background: T.bg,
        color: T.ink,
        fontFamily: "Inter, -apple-system, BlinkMacSystemFont, sans-serif",
      }}
    >
      <Header />
      <div style={{ padding: "40px 32px" }}>
      <div style={{ maxWidth: 1120, margin: "0 auto" }}>
        {/* Header */}
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 24 }}>
          <div>
            <div style={{ fontSize: 11, color: T.inkMute, letterSpacing: "0.14em",
                          fontFamily: "JetBrains Mono, monospace" }}>
              NIVXRAY · v2 · PHASE 4.1
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, marginTop: 4 }}>
              Investigation Ingestion Engine
            </div>
            <div style={{ marginTop: 6, color: T.inkDim, fontSize: 14, maxWidth: 780 }}>
              Drop Sysmon XML, Windows Security XML, canonical JSON/NDJSON, CSV, or a ZIP
              bundle. Format &amp; source are auto-detected, events are normalized into the
              Canonical Event Schema, and the Investigation Workspace is generated
              deterministically.
            </div>
          </div>
        </div>

        {/* Drop zone */}
        <Card
          data-testid="ingestion-dropzone"
          style={{
            border: `2px dashed ${dragging ? T.amber : T.lineStr}`,
            background: dragging ? T.amberBg : T.cardGradient,
            padding: 40,
            textAlign: "center",
            cursor: "pointer",
            transition: "all 160ms ease",
          }}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
        >
          <input
            ref={inputRef}
            type="file"
            style={{ display: "none" }}
            data-testid="ingestion-file-input"
            accept=".xml,.json,.ndjson,.csv,.zip,.evtx,.txt,.log"
            onChange={(e) => submitFile(e.target.files?.[0])}
          />
          <div style={{ fontSize: 44, marginBottom: 12, color: T.amber }}>⇩</div>
          <div style={{ fontSize: 16, fontWeight: 600 }}>
            {uploading ? "Ingesting …" : "Drop a log file or click to browse"}
          </div>
          <div style={{ marginTop: 8, color: T.inkMute, fontSize: 12,
                        fontFamily: "JetBrains Mono, monospace" }}>
            Sysmon XML · Windows Security XML · JSON · NDJSON · CSV · ZIP
          </div>
        </Card>

        {/* Result */}
        {result && (
          <>
            <MetricsPanel result={result} />
            {result.workspace_url && (
              <div style={{ marginTop: 12, textAlign: "right" }}>
                <button
                  data-testid="ingestion-open-workspace"
                  onClick={openWorkspace}
                  style={{
                    background: T.amber, color: T.paper,
                    border: "none", padding: "10px 20px",
                    borderRadius: 8, fontWeight: 600, cursor: "pointer",
                    fontFamily: "JetBrains Mono, monospace",
                    letterSpacing: "0.06em", fontSize: 12,
                  }}
                >OPEN WORKSPACE →</button>
              </div>
            )}
          </>
        )}

        {/* Golden Corpus */}
        <div style={{ marginTop: 40, marginBottom: 12 }}>
          <div style={{ fontSize: 11, color: T.inkMute, letterSpacing: "0.14em",
                        fontFamily: "JetBrains Mono, monospace" }}>
            GOLDEN INVESTIGATION CORPUS
          </div>
          <div style={{ fontSize: 18, fontWeight: 600, marginTop: 4 }}>
            Benchmark investigations
          </div>
          <div style={{ marginTop: 4, color: T.inkMute, fontSize: 12 }}>
            Six deterministic datasets covering benign and malicious scenarios —
            used to validate ingestion, verdict, and story pipelines end-to-end.
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
                      gap: 12 }}>
          {golden.map(d => (
            <Card key={d.id} style={{ padding: 16 }}>
              <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
                <div style={{ fontSize: 14, fontWeight: 600, color: T.ink }}>{d.label}</div>
                <Pill tone={d.expected_verdict === "benign" ? "ok" :
                            d.expected_verdict === "critical" ? "warn" : "info"}>
                  {d.expected_verdict}
                </Pill>
              </div>
              <div style={{ marginTop: 8, fontSize: 12, color: T.inkMute, minHeight: 32 }}>
                {d.description}
              </div>
              <div style={{ marginTop: 10, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, color: T.inkFaint,
                               fontFamily: "JetBrains Mono, monospace" }}>
                  {d.event_count} events
                </span>
                <button
                  data-testid={`golden-seed-${d.id}`}
                  disabled={uploading}
                  onClick={() => seedGolden(d.id)}
                  style={{
                    background: T.paper2, color: T.ink,
                    border: `1px solid ${T.lineStr}`, padding: "6px 12px",
                    borderRadius: 6, fontSize: 11, cursor: uploading ? "wait" : "pointer",
                    fontFamily: "JetBrains Mono, monospace",
                  }}
                >SEED →</button>
              </div>
            </Card>
          ))}
        </div>

        {/* Supported formats */}
        {formats && (
          <div style={{ marginTop: 40 }}>
            <div style={{ fontSize: 11, color: T.inkMute, letterSpacing: "0.14em",
                          fontFamily: "JetBrains Mono, monospace" }}>
              SUPPORTED FORMATS · PHASE 4.1
            </div>
            <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
              {formats.formats?.map(f => (
                <Pill key={f.id} tone={f.fidelity === "high" ? "ok" : "info"}>
                  {f.label} · {f.fidelity}
                </Pill>
              ))}
            </div>
            <div style={{ marginTop: 20, fontSize: 12, color: T.inkMute }}>
              <strong style={{ color: T.inkDim }}>Roadmap ·</strong>{" "}
              Phase 4.2: {formats.roadmap?.phase_4_2?.join(", ")}. <br />
              Phase 4.3: {formats.roadmap?.phase_4_3?.join(", ")}.
            </div>
          </div>
        )}
      </div>
      </div>
    </div>
  );
}
