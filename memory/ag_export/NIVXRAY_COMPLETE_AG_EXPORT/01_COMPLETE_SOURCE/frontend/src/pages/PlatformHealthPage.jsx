/**
 * PlatformHealthPage — Phase A.5 · item 3.3
 *
 * Owner-locked 8-section Platform Health Dashboard (2026-02-16):
 *   1. Pipeline Health
 *   2. Performance
 *   3. Coverage
 *   4. Explainability Coverage
 *   5. Fingerprint Stability
 *   6. Quality
 *   7. NVKC
 *   8. Release History (from persisted snapshots timeseries)
 *
 * Pure read-only consumer of `GET /api/platform/metrics` + `.../timeseries`.
 */
import { useEffect, useState } from "react";
import Header from "@/components/Header";
import api from "@/lib/api";
import {
  Activity, Cpu, Layers, GitBranch, Radar, ShieldCheck,
  Database, TrendingUp,
} from "lucide-react";

const COL = {
  bg: "var(--bg,#0b1220)", panel: "#0f1a2c", border: "#1f2b3f",
  muted: "#94a3b8", accent: "#38bdf8", good: "#86efac",
  bad: "#f87171", warn: "#fbbf24", text: "#e5e7eb",
};

export default function PlatformHealthPage() {
  const [snap, setSnap] = useState(null);
  const [ts, setTs]     = useState([]);
  const [err, setErr]   = useState("");
  const [saving, setSaving] = useState(false);

  const load = async () => {
    setErr("");
    try {
      const [m, t] = await Promise.all([
        api.get("/platform/metrics"),
        api.get("/platform/timeseries", { params: { limit: 30 } }),
      ]);
      setSnap(m.data);
      setTs(t.data?.items || []);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message || String(e));
    }
  };
  useEffect(() => { load(); }, []);

  const snapshot = async () => {
    setSaving(true);
    try { await api.post("/platform/snapshot"); await load(); }
    finally { setSaving(false); }
  };

  return (
    <div data-testid="platform-health-page"
         style={{ minHeight: "100vh", background: COL.bg, color: COL.text }}>
      <Header />
      <div style={{ maxWidth: 1400, margin: "0 auto", padding: "28px 24px" }}>
        <TitleBar onSnapshot={snapshot} saving={saving} />
        {err && (
          <div data-testid="metrics-error"
               style={{ marginTop: 16, padding: 12, borderRadius: 8,
                        background: "#3a1d1d", color: COL.bad }}>{err}</div>
        )}
        {!snap && !err && (
          <div style={{ color: COL.muted, marginTop: 24 }}>Loading metrics…</div>
        )}
        {snap && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                        gap: 16, marginTop: 20 }}>
            <PipelineHealth s={snap.pipeline_health} />
            <Performance s={snap.performance} />
            <Coverage s={snap.coverage} />
            <Explainability s={snap.explainability} />
            <FingerprintStability s={snap.fingerprint_stability} />
            <Quality s={snap.quality} />
            <NvkcPanel s={snap.nvkc} />
            <ReleaseHistory items={ts} />
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function TitleBar({ onSnapshot, saving }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                  alignItems: "center", marginBottom: 8 }}>
      <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
        <div style={{ background: "#0e223b", padding: 10, borderRadius: 10 }}>
          <TrendingUp size={24} color={COL.accent} />
        </div>
        <div>
          <h1 data-testid="platform-health-title"
              style={{ fontSize: 26, margin: 0, letterSpacing: -0.3 }}>
            Platform Health
          </h1>
          <div style={{ color: COL.muted, fontSize: 13, marginTop: 2 }}>
            8 metric families · deterministic snapshot of the SSOT
          </div>
        </div>
      </div>
      <button data-testid="snapshot-button"
              onClick={onSnapshot} disabled={saving}
              style={{ background: COL.accent, color: "#052437",
                       border: "none", borderRadius: 10,
                       padding: "10px 18px", fontWeight: 600,
                       cursor: saving ? "wait" : "pointer" }}>
        {saving ? "Persisting…" : "Snapshot Now"}
      </button>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function Card({ icon, title, testid, children }) {
  return (
    <div data-testid={testid}
         style={{ background: COL.panel, border: `1px solid ${COL.border}`,
                  borderRadius: 12, padding: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                    fontSize: 14, fontWeight: 600, marginBottom: 12 }}>
        <span style={{ color: COL.accent }}>{icon}</span>{title}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, testid, valueColor }) {
  return (
    <div data-testid={testid}
         style={{ display: "flex", justifyContent: "space-between",
                  padding: "6px 0",
                  borderBottom: `1px dashed ${COL.border}` }}>
      <span style={{ color: COL.muted, fontSize: 13 }}>{label}</span>
      <span style={{ color: valueColor || COL.text, fontWeight: 500,
                     fontFamily: "ui-monospace, monospace", fontSize: 13 }}>
        {value ?? "—"}
      </span>
    </div>
  );
}

function Bar({ pct, colorHint }) {
  const filled = Math.max(0, Math.min(100, pct ?? 0));
  const color = colorHint ??
                (filled >= 80 ? COL.good : filled >= 40 ? COL.warn : COL.bad);
  return (
    <div style={{ height: 6, background: COL.border, borderRadius: 3,
                  overflow: "hidden" }}>
      <div style={{ width: `${filled}%`, height: "100%", background: color }} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
function PipelineHealth({ s }) {
  return (
    <Card icon={<Activity size={16} />} title="1 · Pipeline Health"
          testid="section-pipeline-health">
      <Row label="Total cases" value={s.total_cases}
           testid="pipeline-total-cases" />
      <Row label="Decode success rate"
           value={s.decode_success_rate != null ? `${s.decode_success_rate}%` : "—"}
           testid="pipeline-decode-rate" />
      <Row label="Investigation success rate"
           value={s.investigation_success_rate != null ? `${s.investigation_success_rate}%` : "—"}
           testid="pipeline-invest-rate" />
      <Row label="Golden Corpus baselines" value={s.golden_corpus_baselines}
           testid="pipeline-golden-count" />
      <div style={{ marginTop: 8, fontSize: 12, color: COL.muted }}>
        Terminal-state distribution:
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 4 }}>
        {Object.entries(s.terminal_state_distribution || {}).map(([k, v]) => (
          <span key={k}
                data-testid={`pipeline-state-${k}`}
                style={{ padding: "3px 8px", borderRadius: 6,
                         background: "#0a1526", fontSize: 11,
                         color: COL.text, fontFamily: "ui-monospace, monospace" }}>
            {k}: {v}
          </span>
        ))}
      </div>
    </Card>
  );
}

function Performance({ s }) {
  const p = s.decode_latency_ms || {};
  const d = s.recursive_depth_stats || {};
  return (
    <Card icon={<Cpu size={16} />} title="2 · Performance"
          testid="section-performance">
      <Row label="Decode latency samples" value={p.n} testid="perf-n" />
      <Row label="Decode latency mean" value={p.mean != null ? `${p.mean} ms` : "—"} />
      <Row label="p50 / p90 / p99"
           value={`${p.p50 ?? "—"} / ${p.p90 ?? "—"} / ${p.p99 ?? "—"}`} />
      <Row label="Recursive depth (mean/max)"
           value={`${d.mean ?? "—"} / ${d.max ?? "—"}`} />
    </Card>
  );
}

function Coverage({ s }) {
  return (
    <Card icon={<Layers size={16} />} title="3 · Coverage"
          testid="section-coverage">
      <Row label="Analyzer types observed" value={s.analyzer_type_count} />
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, margin: "6px 0 10px" }}>
        {(s.analyzer_types_observed || []).map(t => (
          <span key={t}
                style={{ padding: "3px 8px", borderRadius: 6,
                         background: "#0a1526", fontSize: 11,
                         fontFamily: "ui-monospace, monospace", color: COL.text }}>
            {t}
          </span>
        ))}
      </div>
      <Row label="MITRE techniques observed" value={s.mitre_id_count} />
      <div style={{ fontSize: 11, color: COL.muted, marginTop: 4,
                    fontFamily: "ui-monospace, monospace" }}>
        {(s.mitre_ids_observed || []).slice(0, 20).join(", ")}
        {(s.mitre_ids_observed || []).length > 20 &&
          ` +${(s.mitre_ids_observed).length - 20} more`}
      </div>
    </Card>
  );
}

function Explainability({ s }) {
  const m = s.metrics || {};
  const rows = [
    ["Verdicts with provenance",     m.verdicts_with_provenance],
    ["MITRE mappings backed",         m.mitre_mappings_backed],
    ["Decoded stages traced",         m.decoded_stages_traced],
    ["Child artifacts analyzed",      m.child_artifacts_analyzed],
    ["Investigations replayable",     m.investigations_replayable],
    ["Findings linked to evidence",   m.findings_linked_to_evidence],
  ];
  return (
    <Card icon={<ShieldCheck size={16} />} title="4 · Explainability Coverage"
          testid="section-explainability">
      <div style={{ fontSize: 12, color: COL.muted, marginBottom: 8 }}>
        Total cases: {s.total_cases}
      </div>
      {rows.map(([label, pct]) => (
        <div key={label}
             data-testid={`explainability-${label.replace(/\s+/g, "-").toLowerCase()}`}
             style={{ marginBottom: 8 }}>
          <div style={{ display: "flex", justifyContent: "space-between",
                        fontSize: 13, marginBottom: 3 }}>
            <span>{label}</span>
            <span style={{ fontFamily: "ui-monospace, monospace" }}>
              {pct == null ? "—" : `${pct}%`}
            </span>
          </div>
          <Bar pct={pct} />
        </div>
      ))}
    </Card>
  );
}

function FingerprintStability({ s }) {
  const gc = s.golden_corpus || {};
  const nv = s.nvkc || {};
  return (
    <Card icon={<Radar size={16} />} title="5 · Fingerprint Stability"
          testid="section-fingerprint-stability">
      <Row label="Golden Corpus with Attack Fingerprint"
           value={`${gc.with_attack_fingerprint} / ${gc.total} (${gc.coverage ?? "—"}%)`}
           testid="fps-golden" />
      <Row label="NVKC with Attack Fingerprint"
           value={`${nv.with_attack_fingerprint} / ${nv.total} (${nv.coverage ?? "—"}%)`}
           testid="fps-nvkc" />
    </Card>
  );
}

function Quality({ s }) {
  const r = s.risk_score_distribution || {};
  return (
    <Card icon={<GitBranch size={16} />} title="6 · Quality"
          testid="section-quality">
      <div style={{ fontSize: 12, color: COL.muted, marginBottom: 6 }}>
        Verdict distribution:
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10 }}>
        {Object.entries(s.verdict_distribution || {}).map(([k, v]) => (
          <span key={k}
                style={{ padding: "3px 8px", borderRadius: 6,
                         background: "#0a1526", fontSize: 11,
                         fontFamily: "ui-monospace, monospace" }}>
            {k}: {v}
          </span>
        ))}
      </div>
      <Row label="Risk-score samples" value={r.n} />
      <Row label="Risk mean" value={r.mean ?? "—"} />
      <Row label="Risk p50 / p90 / p99"
           value={`${r.p50 ?? "—"} / ${r.p90 ?? "—"} / ${r.p99 ?? "—"}`} />
    </Card>
  );
}

function NvkcPanel({ s }) {
  return (
    <Card icon={<Database size={16} />} title="7 · NVKC"
          testid="section-nvkc">
      <Row label="Total samples" value={s.total_samples} testid="nvkc-total" />
      <div style={{ marginTop: 8, fontSize: 12, color: COL.muted }}>By track:</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 4 }}>
        {Object.entries(s.by_track || {}).map(([k, v]) => (
          <span key={k}
                data-testid={`nvkc-track-${k}`}
                style={{ padding: "3px 8px", borderRadius: 6,
                         background: "#0a1526", fontSize: 11,
                         fontFamily: "ui-monospace, monospace" }}>
            {k}: {v}
          </span>
        ))}
      </div>
      <div style={{ marginTop: 8, fontSize: 12, color: COL.muted }}>Top tags:</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 4 }}>
        {Object.entries(s.top_tags || {}).map(([k, v]) => (
          <span key={k}
                style={{ padding: "3px 8px", borderRadius: 6,
                         background: "#0a1526", fontSize: 11,
                         fontFamily: "ui-monospace, monospace" }}>
            {k}({v})
          </span>
        ))}
      </div>
    </Card>
  );
}

function ReleaseHistory({ items }) {
  return (
    <Card icon={<TrendingUp size={16} />} title="8 · Release History"
          testid="section-release-history">
      {items.length === 0 && (
        <div style={{ color: COL.muted, fontSize: 13 }}>
          No persisted snapshots yet. Click "Snapshot Now" to record the
          current state as the first data point.
        </div>
      )}
      {items.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {items.map((it, i) => (
            <div key={i}
                 data-testid={`history-row-${i}`}
                 style={{ display: "grid",
                          gridTemplateColumns: "170px 1fr 1fr 1fr 1fr",
                          gap: 8, fontSize: 11,
                          fontFamily: "ui-monospace, monospace",
                          padding: "5px 0",
                          borderBottom: `1px dashed ${COL.border}` }}>
              <span style={{ color: COL.muted }}>{it.computed_at?.slice(0, 19)}</span>
              <span>cases:{it.pipeline_health?.total_cases}</span>
              <span>decode:{it.pipeline_health?.decode_success_rate}%</span>
              <span>mitre:{it.coverage?.mitre_id_count}</span>
              <span>nvkc:{it.nvkc?.total_samples}</span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
