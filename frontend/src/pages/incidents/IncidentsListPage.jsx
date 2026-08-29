/**
 * IncidentsListPage · `/incidents`
 *
 * Dense operational table.  Reads workspace_cases through the
 * /api/incidents projection — never creates a new Incident/Alert/Case
 * model.  Clicking a row opens the canonical Incident shell.
 */
import React, { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { RefreshCw, AlertOctagon, Inbox, ChevronRight } from "lucide-react";

import Header from "@/components/Header";
import { listIncidents } from "@/lib/incidentsApi";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

// ── State color chips ───────────────────────────────────────────────
const STATE_COLORS = {
  new:         { fg: "#67e8f9", bg: "rgba(6,182,212,0.14)",  ring: "rgba(6,182,212,0.55)"  },
  in_progress: { fg: "#fcd34d", bg: "rgba(245,158,11,0.16)", ring: "rgba(245,158,11,0.55)" },
  on_hold:     { fg: "#c4b5fd", bg: "rgba(139,92,246,0.16)", ring: "rgba(139,92,246,0.55)" },
  resolved:    { fg: "#86efac", bg: "rgba(34,197,94,0.16)",  ring: "rgba(34,197,94,0.55)"  },
  closed:      { fg: "rgba(148,163,184,0.9)", bg: "rgba(148,163,184,0.12)",
                   ring: "rgba(148,163,184,0.35)" },
};

const PRIORITY_COLORS = {
  P1: { fg: "#fecaca", bg: "rgba(239,68,68,0.16)",  ring: "rgba(239,68,68,0.55)" },
  P2: { fg: "#fdba74", bg: "rgba(249,115,22,0.15)", ring: "rgba(249,115,22,0.5)" },
  P3: { fg: "#fcd34d", bg: "rgba(245,158,11,0.14)", ring: "rgba(245,158,11,0.45)" },
  P4: { fg: "#86efac", bg: "rgba(34,197,94,0.14)",  ring: "rgba(34,197,94,0.45)" },
  P5: { fg: "rgba(148,163,184,0.9)", bg: "rgba(148,163,184,0.10)",
          ring: "rgba(148,163,184,0.35)" },
};

const SEVERITY_COLORS = {
  malicious:   "#fca5a5",
  suspicious:  "#fcd34d",
  benign:      "#86efac",
  unknown:     "rgba(148,163,184,0.9)",
};

function Chip({ tone, children, testId }) {
  return (
    <span
      data-testid={testId}
      style={{
        display: "inline-flex", alignItems: "center", gap: 4,
        padding: "2px 8px",
        borderRadius: 4,
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 10, letterSpacing: "0.08em",
        textTransform: "uppercase",
        color: tone.fg,
        background: tone.bg,
        border: `1px solid ${tone.ring}`,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toISOString().replace("T", " ").slice(0, 16) + "Z";
  } catch { return iso; }
}

export default function IncidentsListPage() {
  const navigate = useNavigate();
  const [rows, setRows]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await listIncidents({ limit: 200 });
      setRows(res.incidents || []);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load incidents.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg, #020617)", color: "#e2e8f0" }}>
      <Header />
      <main
        data-testid={T.listPage}
        style={{ maxWidth: 1400, margin: "0 auto", padding: "28px 22px" }}
      >
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 20 }}>
          <div>
            <div style={{
              fontFamily: "JetBrains Mono, monospace", fontSize: 11,
              letterSpacing: "0.24em", color: "rgba(148,163,184,0.75)",
              textTransform: "uppercase",
            }}>
              Operations · Incidents
            </div>
            <h1 style={{
              margin: "6px 0 0",
              fontFamily: "Chivo, ui-sans-serif, system-ui",
              fontSize: 32, fontWeight: 800, letterSpacing: "-0.01em",
            }}>
              Incident Queue
            </h1>
            <div style={{
              marginTop: 6, fontSize: 13, color: "rgba(148,163,184,0.75)",
              maxWidth: 720, lineHeight: 1.5,
            }}>
              Dense operational view of every saved incident. Row → canonical Incident shell.
              Backed by <code style={{ color: "#c4b5fd" }}>workspace_cases</code> — no parallel model.
            </div>
          </div>
          <button
            data-testid={T.listRefresh}
            onClick={load}
            disabled={loading}
            className="nvx-btn sm ghost"
            style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
          >
            <RefreshCw size={13} style={{
              transformOrigin: "center",
              animation: loading ? "spin 1s linear infinite" : "none",
            }} />
            REFRESH
          </button>
        </div>

        <section style={{
          marginTop: 22,
          border: "1px solid rgba(148,163,184,0.14)",
          borderRadius: 10,
          overflow: "hidden",
          background: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.62))",
        }}>
          {loading && (
            <div data-testid={T.listLoading}
                 style={{ padding: "48px 22px", textAlign: "center",
                            color: "rgba(148,163,184,0.75)",
                            fontFamily: "JetBrains Mono, monospace", fontSize: 12,
                            letterSpacing: "0.14em" }}>
              LOADING INCIDENTS …
            </div>
          )}
          {!loading && error && (
            <div data-testid={T.listError}
                 style={{ padding: "24px 22px", color: "#fca5a5",
                            fontFamily: "JetBrains Mono, monospace", fontSize: 12,
                            display: "flex", gap: 10, alignItems: "flex-start" }}>
              <AlertOctagon size={16} style={{ flexShrink: 0, marginTop: 2 }} />
              <span>{String(error)}</span>
            </div>
          )}
          {!loading && !error && rows.length === 0 && (
            <div data-testid={T.listEmptyState}
                 style={{ padding: "48px 22px", textAlign: "center",
                            color: "rgba(148,163,184,0.75)" }}>
              <Inbox size={22} style={{ opacity: 0.6 }} />
              <div style={{ marginTop: 8, fontSize: 13 }}>
                No incidents yet. Save a case from the Workspace to create one.
              </div>
            </div>
          )}
          {!loading && !error && rows.length > 0 && (
            <table
              data-testid={T.listTable}
              style={{ width: "100%", borderCollapse: "collapse",
                         fontFamily: "JetBrains Mono, ui-monospace, monospace",
                         fontSize: 12 }}
            >
              <thead>
                <tr style={{
                  background: "rgba(2,6,23,0.5)",
                  color: "rgba(148,163,184,0.85)",
                  fontSize: 10, letterSpacing: "0.14em",
                  textTransform: "uppercase",
                }}>
                  <Th>Number</Th>
                  <Th>Priority</Th>
                  <Th>Severity</Th>
                  <Th>Name</Th>
                  <Th>Tenant</Th>
                  <Th>Assigned To</Th>
                  <Th>State</Th>
                  <Th>Latest Updated</Th>
                  <Th style={{ width: 32 }}></Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const state = STATE_COLORS[r.state] || STATE_COLORS.new;
                  const prio  = PRIORITY_COLORS[r.priority?.code] || PRIORITY_COLORS.P5;
                  const sevColor = SEVERITY_COLORS[r.severity] || SEVERITY_COLORS.unknown;
                  return (
                    <tr
                      key={r.id}
                      data-testid={T.listRow(r.id)}
                      onClick={() => navigate(`/incidents/${r.id}`)}
                      style={{
                        cursor: "pointer",
                        borderTop: "1px solid rgba(148,163,184,0.10)",
                        transition: "background 120ms ease",
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(148,163,184,0.06)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    >
                      <Td mono>{r.number}</Td>
                      <Td><Chip tone={prio}>{r.priority?.code} · {r.priority?.label}</Chip></Td>
                      <Td>
                        <span style={{
                          color: sevColor, fontWeight: 700,
                          textTransform: "uppercase", letterSpacing: "0.08em",
                          fontSize: 10,
                        }}>
                          {r.severity}
                        </span>
                      </Td>
                      <Td style={{ color: "#e2e8f0", fontWeight: 600 }}>{r.name}</Td>
                      <Td style={{ color: "rgba(203,213,225,0.75)" }}>{r.tenant}</Td>
                      <Td style={{ color: "rgba(203,213,225,0.75)" }}>{r.assignee || "—"}</Td>
                      <Td><Chip tone={state}>{r.state.replace("_", " ")}</Chip></Td>
                      <Td style={{ color: "rgba(148,163,184,0.75)" }}>{fmtDate(r.updated_at)}</Td>
                      <Td><ChevronRight size={14} style={{ opacity: 0.5 }} /></Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>
      </main>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

function Th({ children, style }) {
  return (
    <th style={{
      textAlign: "left",
      padding: "10px 14px",
      fontWeight: 600,
      ...style,
    }}>{children}</th>
  );
}
function Td({ children, style, mono }) {
  return (
    <td style={{
      padding: "10px 14px",
      whiteSpace: "nowrap",
      fontFamily: mono ? "JetBrains Mono, ui-monospace, monospace" : undefined,
      ...style,
    }}>{children}</td>
  );
}
