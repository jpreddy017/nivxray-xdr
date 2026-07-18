import React, { useEffect, useState } from "react";
import Header from "@/components/Header";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { RefreshCw, CheckCircle2, XCircle, ChevronRight } from "lucide-react";

const API = process.env.REACT_APP_BACKEND_URL;

const BADGE_COLORS = {
  OK:       { fg: "#5cff9e", bg: "rgba(92,255,158,0.10)", icon: "🟢" },
  MIXED:    { fg: "#ffd85c", bg: "rgba(255,216,92,0.10)", icon: "🟡" },
  BROKEN:   { fg: "#ff5c7a", bg: "rgba(255,92,122,0.10)", icon: "🔴" },
  SALVAGED: { fg: "#5dd0ff", bg: "rgba(93,208,255,0.10)", icon: "🩵" },
};

function Pill({ label }) {
  const c = BADGE_COLORS[label] || BADGE_COLORS.OK;
  return (
    <span style={{
      color: c.fg, background: c.bg, border: `1px solid ${c.fg}30`,
      borderRadius: 999, padding: "2px 8px", fontSize: 11, fontWeight: 600,
      letterSpacing: 0.4, fontFamily: "ui-monospace, monospace",
    }}>{c.icon} {label}</span>
  );
}

export default function MultiLayerBatteryPage() {
  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [rerunning, setRerun]   = useState(false);
  const [openId, setOpenId]     = useState(null);
  const [error, setError]       = useState(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const r = await fetch(`${API}/api/benchmark/multilayer`);
      const j = await r.json();
      if (j.error) throw new Error(j.error);
      setData(j);
    } catch (e) { setError(String(e.message || e)); }
    finally { setLoading(false); }
  };
  const rerun = async () => {
    setRerun(true); setError(null);
    try {
      const r = await fetch(`${API}/api/benchmark/multilayer/rerun`, { method: "POST" });
      const j = await r.json();
      if (j.error) throw new Error(j.error);
      setData(j);
    } catch (e) { setError(String(e.message || e)); }
    finally { setRerun(false); }
  };

  useEffect(() => { load(); }, []);

  if (loading) return (<><Header /><div style={{ padding: 32, color: "var(--muted)" }} data-testid="battery-loading">Loading battery report…</div></>);
  if (error)   return (<><Header /><div style={{ padding: 32, color: "#ff5c7a" }} data-testid="battery-error">Error: {error}</div></>);
  if (!data)   return null;

  const pct = Math.round((data.pass_rate || 0) * 100);

  return (
    <>
      <Header />
      <div style={{ padding: "24px 32px", minHeight: "calc(100vh - 60px)" }} data-testid="multilayer-battery-page">
      {/* HEADER */}
      <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ fontSize: 11, letterSpacing: 2, color: "var(--muted)", marginBottom: 4 }}>
            REGRESSION SUITE · X-RAY v1.5.6
          </div>
          <h1 style={{ fontSize: 32, margin: 0, letterSpacing: -0.5 }} data-testid="battery-title">
            MULTI-LAYER OBFUSCATION BATTERY
          </h1>
          <div style={{ marginTop: 6, color: "var(--muted)", fontSize: 13, fontFamily: "ui-monospace, monospace" }}>
            {data.generated_at}
          </div>
        </div>
        <Button variant="outline" onClick={rerun} disabled={rerunning} data-testid="battery-rerun-btn">
          <RefreshCw size={14} style={{ marginRight: 6, animation: rerunning ? "spin 1s linear infinite" : "none" }} />
          {rerunning ? "Rerunning…" : "Re-run battery"}
        </Button>
      </div>

      {/* KPI TILES */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(180px, 1fr))", gap: 12, marginBottom: 24 }}>
        <Card style={{ padding: 16 }} data-testid="kpi-pass-rate">
          <div style={{ fontSize: 11, color: "var(--muted)", letterSpacing: 1.4 }}>PASS RATE</div>
          <div style={{ fontSize: 34, fontWeight: 700, color: pct === 100 ? "#5cff9e" : "#ffd85c" }}>{pct}%</div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>{data.passed} / {data.total} samples</div>
        </Card>
        <Card style={{ padding: 16 }} data-testid="kpi-avg-ms">
          <div style={{ fontSize: 11, color: "var(--muted)", letterSpacing: 1.4 }}>AVG DECODE</div>
          <div style={{ fontSize: 34, fontWeight: 700 }}>{data.avg_http_ms}<span style={{ fontSize: 16, color: "var(--muted)" }}> ms</span></div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>in-process (offline)</div>
        </Card>
        <Card style={{ padding: 16 }} data-testid="kpi-salvages">
          <div style={{ fontSize: 11, color: "var(--muted)", letterSpacing: 1.4 }}>SALVAGE DOWNGRADES</div>
          <div style={{ fontSize: 34, fontWeight: 700, color: "#5dd0ff" }}>{data.total_salvage_downgrades}</div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>BROKEN/MIXED → 🩵</div>
        </Card>
        <Card style={{ padding: 16 }} data-testid="kpi-total">
          <div style={{ fontSize: 11, color: "var(--muted)", letterSpacing: 1.4 }}>SAMPLES</div>
          <div style={{ fontSize: 34, fontWeight: 700 }}>{data.total}</div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>multi-layer wraps</div>
        </Card>
      </div>

      {/* SAMPLES LIST */}
      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div style={{
          padding: "12px 16px", borderBottom: "1px solid var(--border)",
          fontSize: 11, letterSpacing: 1.6, color: "var(--muted)", background: "rgba(255,255,255,0.02)",
        }}>SAMPLES · click a row for full trace</div>

        {data.samples?.map((s) => {
          const isOpen = openId === s.sample_id;
          return (
            <div key={s.sample_id}
                 data-testid={`sample-row-${s.sample_id}`}
                 style={{ borderBottom: "1px solid var(--border)" }}>
              <div onClick={() => setOpenId(isOpen ? null : s.sample_id)}
                   style={{
                     padding: "14px 16px", cursor: "pointer", display: "grid",
                     gridTemplateColumns: "24px 220px 240px 90px 80px 90px 90px 1fr",
                     alignItems: "center", gap: 12, fontFamily: "ui-monospace, monospace",
                   }}>
                {s.match
                  ? <CheckCircle2 size={16} color="#5cff9e" />
                  : <XCircle size={16} color="#ff5c7a" />}
                <span style={{ fontWeight: 600 }}>{s.sample_id}</span>
                <span style={{ color: "var(--muted)" }}>{s.wrap}</span>
                <Badge variant="outline" style={{ justifySelf: "start" }}>chain={s.chain_len}</Badge>
                <span style={{ color: "var(--muted)" }}>{s.http_ms} ms</span>
                <span style={{ color: "#5dd0ff" }}>↓{s.downgrades}</span>
                <span style={{ color: "var(--muted)", fontSize: 11 }}>{s.engine}</span>
                <ChevronRight size={16} style={{
                  justifySelf: "end", color: "var(--muted)",
                  transform: isOpen ? "rotate(90deg)" : "none",
                  transition: "transform 0.15s",
                }} />
              </div>

              {isOpen && (
                <div style={{ padding: "12px 24px 20px 40px",
                              background: "rgba(255,255,255,0.015)",
                              fontFamily: "ui-monospace, monospace", fontSize: 12 }}
                     data-testid={`sample-detail-${s.sample_id}`}>
                  {/* ENCODED INPUT */}
                  <div style={{ marginBottom: 8 }}>
                    <div style={{ fontSize: 10, letterSpacing: 1.4, color: "var(--muted)", marginBottom: 4 }}>
                      ENCODED INPUT · {s.input_len} chars
                    </div>
                    <div style={{
                      background: "rgba(255,92,122,0.06)", border: "1px solid rgba(255,92,122,0.25)",
                      borderRadius: 4, padding: "8px 10px", wordBreak: "break-all", color: "#ff9eb3",
                    }}>{s.encoded_input}</div>
                  </div>

                  {/* DECODED OUTPUT */}
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 10, letterSpacing: 1.4, color: "var(--muted)", marginBottom: 4 }}>
                      DECODED PLAINTEXT · expected token{" "}
                      <span style={{ color: "#5cff9e" }}>{s.expect_token}</span>
                    </div>
                    <div style={{
                      background: "rgba(92,255,158,0.06)", border: "1px solid rgba(92,255,158,0.25)",
                      borderRadius: 4, padding: "8px 10px", wordBreak: "break-all", color: "#c7ffd8",
                    }}>{s.decoded_output || s.output_first_line}</div>
                  </div>

                  {/* LAYER TABLE */}
                  <div style={{ marginTop: 8 }}>
                    <div style={{ fontSize: 10, letterSpacing: 1.4, color: "var(--muted)", marginBottom: 4 }}>
                      LAYER TRACE
                    </div>
                    <div style={{ display: "grid",
                                  gridTemplateColumns: "40px 220px 90px 130px 130px",
                                  gap: 6, fontSize: 11 }}>
                      <span style={{ color: "var(--muted)" }}>L</span>
                      <span style={{ color: "var(--muted)" }}>OP</span>
                      <span style={{ color: "var(--muted)" }}>BYTES</span>
                      <span style={{ color: "var(--muted)" }}>BEFORE (raw)</span>
                      <span style={{ color: "var(--muted)" }}>AFTER (v1.5.6)</span>
                      {s.layers?.map((L, i) => (
                        <React.Fragment key={i}>
                          <span>L{L.idx}</span>
                          <span>{L.op}</span>
                          <span>{L.bytes}</span>
                          <span><Pill label={L.before} /></span>
                          <span><Pill label={L.after} /></span>
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </Card>

      {/* FOOTER PROVENANCE */}
      <div style={{ marginTop: 20, fontSize: 11, color: "var(--muted)", fontFamily: "ui-monospace, monospace" }}>
        source: <span style={{ color: "var(--text)" }}>backend/tests/test_multilayer_battery.py</span>
        {" · "}
        API: <span style={{ color: "var(--text)" }}>GET /api/benchmark/multilayer</span>
        {" · "}
        report: <span style={{ color: "var(--text)" }}>backend/tests/reports/multilayer_battery.json</span>
      </div>
    </div>
    </>
  );
}
