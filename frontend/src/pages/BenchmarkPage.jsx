import { useEffect, useState } from "react";
import axios from "axios";
import Header from "@/components/Header";

const API = process.env.REACT_APP_BACKEND_URL + "/api";

const pct = (v) => (v == null ? "—" : (v * 100).toFixed(1) + "%");

export default function BenchmarkPage() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = async () => {
    try {
      const r = await axios.get(`${API}/benchmark/real-world`);
      setData(r.data);
      setErr(null);
    } catch (e) {
      setErr(e?.message || "failed to fetch");
    }
  };

  useEffect(() => { load(); }, []);

  const runRefresh = async () => {
    setRefreshing(true);
    try {
      await axios.post(`${API}/benchmark/refresh`);
      await load();
    } catch (e) {
      setErr(e?.message || "refresh failed");
    } finally {
      setRefreshing(false);
    }
  };

  if (err) return <ErrorScreen msg={err} />;
  if (!data) return <LoadingScreen />;

  const gateOk = data.gate?.ok;
  const gateColor = gateOk ? "#22c55e" : "#ef4444";

  return (
    <div data-testid="benchmark-page-wrap" style={{ minHeight: "100vh", background: "#0b0f19" }}>
      <Header />
      <div
        data-testid="benchmark-page"
        style={{
          background: "#0b0f19",
          color: "#e5e7eb",
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
          padding: "32px 6vw 48px",
        }}
      >
      <header style={{ marginBottom: 32 }}>
        <div style={{ opacity: 0.55, fontSize: 12, letterSpacing: 2 }}>
          NIVXRAY · PUBLIC BENCHMARK
        </div>
        <h1
          data-testid="benchmark-title"
          style={{ margin: "8px 0 4px", fontSize: 36, fontWeight: 700, color: gateColor }}
        >
          Real-World Stress · {gateOk ? "PASSING" : "FAILING"}
        </h1>
        <div style={{ opacity: 0.6, fontSize: 13 }}>
          {data.corpus_size} curated payloads · &ge;5 obfuscation layers each ·
          last computed{" "}
          {data.generated_at ? new Date(data.generated_at).toLocaleString() : "—"}
        </div>
      </header>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: 16,
          marginBottom: 28,
        }}
      >
        <Kpi
          label="MITRE hit-rate"
          value={pct(data.metrics.mitre_hit_rate)}
          target=">=75%"
          ok={data.metrics.mitre_hit_rate >= 0.75}
          testid="kpi-mitre"
        />
        <Kpi
          label="Undecoded rate"
          value={pct(data.metrics.undecoded_rate)}
          target="<=10%"
          ok={data.metrics.undecoded_rate <= 0.10}
          testid="kpi-undecoded"
        />
        <Kpi
          label="IOC recall"
          value={pct(data.metrics.ioc_recall)}
          target=">=70% (reported)"
          ok={(data.metrics.ioc_recall || 0) >= 0.70}
          testid="kpi-ioc"
        />
        <Kpi
          label="Marker hit-rate"
          value={pct(data.metrics.marker_hit_rate)}
          target="(informational)"
          ok
          testid="kpi-marker"
        />
        <Kpi
          label="Avg layers/entry"
          value={data.metrics.avg_layers?.toFixed(2) ?? "—"}
          target=">=5"
          ok={(data.metrics.avg_layers || 0) >= 5}
          testid="kpi-layers"
        />
        <Kpi
          label="Avg latency"
          value={`${data.metrics.avg_latency_ms || 0} ms`}
          target="p50 pipeline"
          ok
          testid="kpi-latency"
        />
      </section>

      <section style={{ marginBottom: 28, display: "flex", gap: 12, flexWrap: "wrap" }}>
        <a
          data-testid="btn-download-corpus"
          href={`${process.env.REACT_APP_BACKEND_URL}/api/benchmark/real-world/download`}
          style={btnStyle("#2563eb")}
        >
          DOWNLOAD FULL CORPUS (JSON)
        </a>
        <a
          data-testid="btn-view-html-report"
          href="/downloads/real_world_stress.html"
          target="_blank"
          rel="noopener noreferrer"
          style={btnStyle("#1f2937")}
        >
          VIEW PER-PAYLOAD HTML REPORT
        </a>
        <button
          data-testid="btn-refresh-benchmark"
          onClick={runRefresh}
          disabled={refreshing}
          style={{ ...btnStyle("#0f766e"), border: "none", cursor: refreshing ? "wait" : "pointer" }}
        >
          {refreshing ? "REFRESHING…" : "REFRESH CORPUS + RE-RUN"}
        </button>
      </section>

      <section style={{ marginBottom: 28 }}>
        <h2 style={sectionTitle}>Ground-Truth Sources</h2>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {(data.sources || []).map((s) => (
            <span key={s} style={pillStyle}>
              {s}
            </span>
          ))}
        </div>
      </section>

      <section>
        <h2 style={sectionTitle}>Per-Family Breakdown</h2>
        <div
          data-testid="family-table"
          style={{
            border: "1px solid #1f2937",
            borderRadius: 10,
            overflow: "hidden",
            fontSize: 13,
          }}
        >
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#111827", color: "#a7f3d0" }}>
                <th style={th}>Family</th>
                <th style={th}>Payloads</th>
                <th style={th}>MITRE hits</th>
                <th style={th}>Undecoded</th>
                <th style={th}>Hit-rate</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.per_family || {})
                .sort((a, b) => a[0].localeCompare(b[0]))
                .map(([fam, m]) => {
                  const rate = m.total ? m.mitre_hits / m.total : 0;
                  return (
                    <tr key={fam} style={{ borderTop: "1px solid #1f2937" }}>
                      <td style={td}>{fam}</td>
                      <td style={td}>{m.total}</td>
                      <td style={td}>{m.mitre_hits}</td>
                      <td style={td}>{m.undecoded}</td>
                      <td style={{ ...td, color: rate >= 0.75 ? "#22c55e" : "#f59e0b" }}>
                        {(rate * 100).toFixed(0)}%
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </section>

      <footer style={{ marginTop: 40, opacity: 0.5, fontSize: 11, lineHeight: 1.6 }}>
        Every payload is reconstructed from a documented public incident write-up so
        ground truth is verifiable. Corpus refreshes weekly via MalwareBazaar + Atomic
        Red Team. CI gate: MITRE hit-rate &ge; 75% + Undecoded &le; 10%.
      </footer>
      </div>
    </div>
  );
}

const btnStyle = (bg) => ({
  background: bg,
  color: "#e5e7eb",
  padding: "10px 16px",
  borderRadius: 8,
  textDecoration: "none",
  fontSize: 12,
  letterSpacing: 1.2,
  fontWeight: 600,
  border: "1px solid #333",
});
const sectionTitle = {
  color: "#a7f3d0",
  letterSpacing: 2,
  fontSize: 12,
  margin: "0 0 12px",
  textTransform: "uppercase",
};
const pillStyle = {
  padding: "4px 10px",
  border: "1px solid #333",
  borderRadius: 999,
  background: "#0f172a",
  fontSize: 11,
  letterSpacing: 1,
};
const th = { textAlign: "left", padding: "10px 14px", fontWeight: 500 };
const td = { padding: "10px 14px" };

function Kpi({ label, value, target, ok, testid }) {
  return (
    <div
      data-testid={testid}
      style={{
        border: "1px solid " + (ok ? "#166534" : "#7f1d1d"),
        borderRadius: 10,
        padding: 16,
        background: "#0f172a",
      }}
    >
      <div style={{ fontSize: 10, letterSpacing: 2, opacity: 0.6, textTransform: "uppercase" }}>
        {label}
      </div>
      <div
        style={{
          fontSize: 28,
          fontWeight: 700,
          marginTop: 4,
          color: ok ? "#22c55e" : "#ef4444",
        }}
      >
        {value}
      </div>
      <div style={{ fontSize: 10, opacity: 0.55, marginTop: 2 }}>{target}</div>
    </div>
  );
}

function LoadingScreen() {
  return (
    <div
      data-testid="benchmark-loading"
      style={{
        minHeight: "60vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        color: "#94a3b8",
        fontFamily: "ui-monospace, monospace",
      }}
    >
      loading real-world benchmark…
    </div>
  );
}

function ErrorScreen({ msg }) {
  return (
    <div
      data-testid="benchmark-error"
      style={{
        minHeight: "60vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        color: "#ef4444",
        fontFamily: "ui-monospace, monospace",
      }}
    >
      benchmark unavailable · {msg}
    </div>
  );
}
