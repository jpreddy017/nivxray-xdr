/**
 * CorrectionsAdminPage — /admin/corrections
 *
 * Admin-only analytics dashboard for the Feb-2026 Analyst Corrections
 * feature. Renders:
 *   • Totals & accuracy signal (approved / total)
 *   • Per-status counts (approved / pending / rejected / superseded)
 *   • Per-surface heatmap (CSS bars — no chart lib needed)
 *   • Top-reused corrections (top 10 by reuse_count)
 *   • Top corrected MITRE techniques (top 10)
 *   • Verdict distribution (correct / incorrect / partial / suggest —
 *     the v2/v3 verdict picker signal used as a rough FP/FN indicator)
 *   • Reviewer throughput
 *   • Average approval velocity
 *   • 7-day trend (created / day)
 *   • Pending admin inbox with approve / reject / rollback actions
 *
 * All backend data comes from GET /api/corrections/analytics and
 * /api/corrections/pending — see /app/backend/routers/analyst_corrections.py.
 */
import { useEffect, useState } from "react";
import { RefreshCw, Check, X, Rewind } from "lucide-react";
import Header from "@/components/Header";
import api from "@/lib/api";


function Card({ title, children, testid }) {
  return (
    <div className="nvx-card" data-testid={testid}
         style={{ marginBottom: 12 }}>
      <div className="nvx-card-head">
        <div className="nvx-card-title">{title}</div>
      </div>
      <div className="nvx-card-body">{children}</div>
    </div>
  );
}

function Bar({ label, value, max, color = "var(--accent)", testid }) {
  const pct = max ? Math.max(2, Math.round((value / max) * 100)) : 0;
  return (
    <div data-testid={testid}
         style={{ marginBottom: 5, fontFamily: "JetBrains Mono", fontSize: 11 }}>
      <div style={{ display: "flex", justifyContent: "space-between",
                    color: "var(--text-mute)" }}>
        <span>{label}</span><span style={{ color }}>{value}</span>
      </div>
      <div style={{ height: 6, background: "rgba(255,255,255,0.04)",
                    borderRadius: 2, overflow: "hidden", marginTop: 2 }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color,
                      transition: "width 250ms ease" }}/>
      </div>
    </div>
  );
}

export default function CorrectionsAdminPage() {
  const [data, setData] = useState(null);
  const [pending, setPending] = useState([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const load = async () => {
    setBusy(true); setErr(null);
    try {
      const [a, p] = await Promise.all([
        api.get("/corrections/analytics"),
        api.get("/corrections/pending"),
      ]);
      setData(a.data);
      setPending(p.data.items || []);
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { load(); }, []);

  const approve = async (id) => {
    await api.post(`/corrections/${id}/approve`);
    await load();
  };
  const reject = async (id) => {
    const reason = window.prompt("Reject reason (optional):", "");
    await api.post(`/corrections/${id}/reject`, { reason: reason || "" });
    await load();
  };
  const rollback = async (id) => {
    const v = window.prompt("Rollback to version # (integer):", "1");
    const target = parseInt(v || "1", 10);
    if (!Number.isFinite(target) || target < 1) return;
    await api.post(`/corrections/${id}/rollback`, { target_version: target });
    await load();
  };

  const surfaces = Object.entries(data?.by_surface || {})
                    .sort((a, b) => b[1] - a[1]);
  const surfaceMax = surfaces[0]?.[1] || 1;

  const verdicts = Object.entries(data?.verdict_dist || {})
                    .sort((a, b) => b[1] - a[1]);
  const verdictMax = verdicts[0]?.[1] || 1;
  const verdictColor = {
    correct:     "#4ade80",
    incorrect:   "#ef4444",
    partial:     "#f59e0b",
    suggest:     "#22d3ee",
    unspecified: "#64748b",
  };

  const trendMax = Math.max(1, ...(data?.trend_7d || []).map((t) => t.count || 0));

  return (
    <>
      <Header />
      <div style={{ padding: 16, minHeight: "calc(100vh - 60px)", background: "var(--bg)" }}>
        <div style={{ maxWidth: 1400, margin: "0 auto" }}>
          <div style={{ display: "flex", justifyContent: "space-between",
                        alignItems: "center", marginBottom: 16 }}>
            <h1 style={{ fontSize: 20, color: "var(--text)", margin: 0, fontWeight: 700 }}>
              ✎ Analyst Corrections · Admin Dashboard
            </h1>
            <button
              className="nvx-btn sm"
              data-testid="corrections-admin-refresh"
              onClick={load} disabled={busy}
            >
              <RefreshCw size={11} className={busy ? "spin" : ""}/> {busy ? "…" : "REFRESH"}
            </button>
          </div>

          {err && (
            <div data-testid="corrections-admin-error"
                 style={{ padding: 10, color: "var(--high)",
                          background: "rgba(255,90,90,0.10)",
                          fontFamily: "JetBrains Mono", fontSize: 11 }}>
              {String(err)}
            </div>
          )}

          {data && (
            <div style={{ display: "grid",
                          gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 12 }}>
              {[
                ["TOTAL",      data.totals?.total,      "var(--accent)"],
                ["APPROVED",   data.totals?.approved,   "#4ade80"],
                ["PENDING",    data.totals?.pending,    "#f59e0b"],
                ["SUPERSEDED", data.totals?.superseded, "#94a3b8"],
              ].map(([label, v, color]) => (
                <div key={label} data-testid={`stat-${label.toLowerCase()}`}
                     className="nvx-card" style={{ padding: 10, textAlign: "center" }}>
                  <div style={{ fontSize: 22, color, fontWeight: 700 }}>{v || 0}</div>
                  <div style={{ fontSize: 9, color: "var(--text-mute)",
                                letterSpacing: "0.14em" }}>{label}</div>
                </div>
              ))}
            </div>
          )}

          {data && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <Card title="▸ PER-SURFACE HEATMAP" testid="card-surface-heatmap">
                {surfaces.length === 0 ? (
                  <div style={{ color: "var(--text-mute)", fontSize: 11 }}>(no data)</div>
                ) : surfaces.map(([s, n]) => (
                  <Bar key={s} label={s} value={n} max={surfaceMax}
                       testid={`bar-surface-${s}`} />
                ))}
              </Card>

              <Card title="▸ VERDICT DISTRIBUTION (FP/FN signal)" testid="card-verdict-dist">
                {verdicts.length === 0 ? (
                  <div style={{ color: "var(--text-mute)", fontSize: 11 }}>(no data)</div>
                ) : verdicts.map(([v, n]) => (
                  <Bar key={v} label={v} value={n} max={verdictMax}
                       color={verdictColor[v] || "var(--accent)"}
                       testid={`bar-verdict-${v}`} />
                ))}
                <div style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 6 }}>
                  Accuracy signal: <span style={{ color: "var(--accent)" }}>
                    {(((data.accuracy_signal || 0) * 100).toFixed(1))}%
                  </span>
                  {" · "}Avg approval: <span style={{ color: "var(--accent)" }}>
                    {Math.round((data.avg_approval_seconds || 0) / 60)}m
                  </span>
                </div>
              </Card>

              <Card title="▸ TOP-REUSED CORRECTIONS" testid="card-top-reused">
                {(data.top_reused || []).length === 0 ? (
                  <div style={{ color: "var(--text-mute)", fontSize: 11 }}>(none reused yet)</div>
                ) : (data.top_reused || []).map((c) => (
                  <div key={c.id}
                       data-testid={`top-reused-${c.id}`}
                       style={{ fontFamily: "JetBrains Mono", fontSize: 10.5,
                                padding: "4px 0", borderTop: "1px solid var(--border)" }}>
                    <div>
                      <span style={{ color: "var(--accent)" }}>×{c.reuse_count}</span>
                      {" · "}
                      <span style={{ color: "var(--text-mute)" }}>{c.surface}</span>
                      {" · "}
                      <span style={{ color: "var(--warn)" }}>conf {c.confidence}</span>
                    </div>
                    <div style={{ color: "var(--text-dim)" }}>
                      {c.wrong_finding?.kind}={String(c.wrong_finding?.value ?? "")}
                    </div>
                    <div style={{ color: "var(--text)", fontSize: 10 }}>
                      {c.correct_prompt}
                    </div>
                  </div>
                ))}
              </Card>

              <Card title="▸ TOP CORRECTED MITRE TECHNIQUES" testid="card-top-mitre">
                {Object.keys(data.top_mitre || {}).length === 0 ? (
                  <div style={{ color: "var(--text-mute)", fontSize: 11 }}>(no MITRE corrections yet)</div>
                ) : Object.entries(data.top_mitre).map(([tid, n]) => (
                  <Bar key={tid} label={tid} value={n} max={Math.max(...Object.values(data.top_mitre))}
                       color="#a5f3fc" testid={`bar-mitre-${tid}`} />
                ))}
              </Card>

              <Card title="▸ REVIEWER THROUGHPUT" testid="card-reviewer-throughput">
                {(data.reviewer_stats || []).length === 0 ? (
                  <div style={{ color: "var(--text-mute)", fontSize: 11 }}>(no approvals yet)</div>
                ) : (data.reviewer_stats).map((r) => (
                  <Bar key={r.reviewer} label={r.reviewer} value={r.approved}
                       max={Math.max(...data.reviewer_stats.map((x) => x.approved))}
                       testid={`bar-reviewer-${r.reviewer}`} />
                ))}
              </Card>

              <Card title="▸ 7-DAY TREND (submissions)" testid="card-trend-7d">
                {(data.trend_7d || []).map((t) => (
                  <Bar key={t.date} label={t.date} value={t.count} max={trendMax}
                       color="#c4b5fd" testid={`bar-trend-${t.date}`} />
                ))}
              </Card>
            </div>
          )}

          <Card title={`▸ PENDING GLOBAL-SCOPE INBOX (${pending.length})`}
                testid="card-pending-inbox">
            {pending.length === 0 ? (
              <div style={{ color: "var(--text-mute)", fontSize: 11 }}>
                (all clear — no global corrections awaiting approval)
              </div>
            ) : pending.map((c) => (
              <div key={c.id}
                   data-testid={`pending-item-${c.id}`}
                   style={{ padding: "8px 0", borderTop: "1px solid var(--border)",
                            fontFamily: "JetBrains Mono", fontSize: 11 }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                  <div style={{ flex: 1 }}>
                    <div>
                      <span style={{ color: "var(--accent)" }}>{c.id}</span>
                      {" · "}
                      <span style={{ color: "var(--text-mute)" }}>
                        {c.surface} · by {c.user_email} · v{c.version} ·
                        conf {c.confidence} · verdict {c.verdict || "incorrect"}
                      </span>
                    </div>
                    <div style={{ color: "var(--warn)", marginTop: 2 }}>
                      Wrong: {c.wrong_finding?.kind}={String(c.wrong_finding?.value ?? "")}
                    </div>
                    <div style={{ color: "var(--text)", marginTop: 2, fontSize: 10.5 }}>
                      {c.correct_prompt}
                    </div>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <button className="nvx-btn sm"
                            data-testid={`approve-${c.id}`}
                            onClick={() => approve(c.id)}>
                      <Check size={10}/> APPROVE
                    </button>
                    <button className="nvx-btn sm ghost"
                            data-testid={`reject-${c.id}`}
                            onClick={() => reject(c.id)}>
                      <X size={10}/> REJECT
                    </button>
                    <button className="nvx-btn sm ghost"
                            data-testid={`rollback-${c.id}`}
                            onClick={() => rollback(c.id)}>
                      <Rewind size={10}/> ROLLBACK
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </Card>
        </div>
      </div>
    </>
  );
}
