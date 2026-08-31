/**
 * GoldenPipelineTrace — Round 11 · Real-time Snort → Incident replay.
 *
 * Renders the honest 13-stage NivXRay XDR pipeline trace produced by
 *   POST /api/admin/content-supply-chain/e2e/snort-golden
 *
 * Every stage carries the exact backend status:
 *   EXECUTED     — real code ran successfully
 *   NOT_CREATED  — honest refusal (e.g., verdict below incident gate)
 *   READY        — capability ready but downstream fabric not connected
 *   FAILED / BLOCKED — honest technical blocker (never fabricated)
 *
 * NO stage is invented in the UI.  If the endpoint returns fewer
 * stages, we render fewer stages.
 */
import React, { useState } from "react";
import { Play, CheckCircle2, XCircle, Circle, AlertTriangle,
                ArrowRight, ShieldAlert, Copy } from "lucide-react";
import api from "@/lib/api";
import InvestigationLanes from "@/xdr/admin/InvestigationLanes";


const STATUS_META = {
  EXECUTED:    { color: "var(--mint)",     icon: CheckCircle2 },
  READY:       { color: "#38bdf8",         icon: Circle       },
  NOT_CREATED: { color: "var(--amber)",    icon: AlertTriangle },
  BLOCKED:     { color: "#f87171",         icon: XCircle      },
  FAILED:      { color: "#f87171",         icon: XCircle      },
};


function StageChip({ s, index }) {
  const meta = STATUS_META[s.status] || {
    color: "var(--faint)", icon: Circle,
  };
  const Icon = meta.icon;
  return (
    <div data-testid={`golden-stage-${s.stage}`}
              style={{
                border: `1px solid ${meta.color}`,
                borderRadius: 4, padding: "8px 10px",
                background: "var(--panel2)", minWidth: 120,
              }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <Icon size={11} style={{ color: meta.color }} />
        <span style={{
          fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700,
          color: "var(--text)",
        }}>{s.stage}</span>
      </div>
      <div style={{
        marginTop: 4, fontFamily: "var(--mono)", fontSize: 9,
        letterSpacing: ".4px", fontWeight: 700, color: meta.color,
      }}>
        {s.status}
      </div>
      {s.reason && (
        <div style={{
          marginTop: 3, fontFamily: "var(--mono)", fontSize: 9,
          color: "var(--faint)", lineHeight: 1.4, maxWidth: 220,
        }}>
          {s.reason.length > 90 ? s.reason.slice(0, 87) + "…" : s.reason}
        </div>
      )}
    </div>
  );
}


function VerdictCard({ result }) {
  const veee = result?.veee || {};
  const inc  = result?.incident || {};
  const iue  = result?.iue || {};
  const ice  = result?.ice || {};

  const label = veee.label || "—";
  const labelColor = label === "MALICIOUS"      ? "#f87171"
                                  : label === "SUSPICIOUS"    ? "var(--amber)"
                                  : label === "LIKELY_BENIGN" ? "var(--mint)"
                                  :                                       "var(--faint)";
  return (
    <div data-testid="golden-verdict-card"
              style={{
                border: "1px solid var(--border)", borderRadius: 4,
                padding: 12, background: "var(--panel2)",
                display: "grid",
                gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 12,
                marginTop: 12,
              }}>
      <div>
        <div style={metaLabel}>IUE severity_hint</div>
        <div style={{ ...metaValue, color: "var(--text)" }}>
          {iue.severity_hint || "—"}
        </div>
        <div style={{ ...metaLabel, marginTop: 6 }}>IUE confidence</div>
        <div style={metaValue}>{iue.confidence ?? "—"}</div>
      </div>
      <div>
        <div style={metaLabel}>ICE state</div>
        <div style={{ ...metaValue, color: "var(--text)" }}>
          {ice.state || "—"}
        </div>
        <div style={{ ...metaLabel, marginTop: 6 }}>Matches</div>
        <div style={metaValue}>
          {(ice.matches || []).length}
          <span style={{ color: "var(--faint)" }}>
            {" "}/ {ice.rules_evaluated ?? 0}
          </span>
        </div>
      </div>
      <div>
        <div style={metaLabel}>VEEE label</div>
        <div style={{ ...metaValue, color: labelColor, fontSize: 15 }}>
          {label}
        </div>
        <div style={{ ...metaLabel, marginTop: 6 }}>Score</div>
        <div style={metaValue}>{veee.score ?? "—"}</div>
      </div>
      <div>
        <div style={metaLabel}>Incident</div>
        <div style={metaValue}>
          {inc.created ? (
            <span style={{ color: "var(--mint)" }}>
              <ShieldAlert size={11} /> {inc.incident_id}
            </span>
          ) : (
            <span style={{ color: "var(--faint)" }}>NOT_CREATED</span>
          )}
        </div>
        <div style={{ ...metaLabel, marginTop: 6 }}>Priority</div>
        <div style={metaValue}>{inc.priority || "—"}</div>
      </div>
    </div>
  );
}


export default function GoldenPipelineTrace({ testid }) {
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [err,     setErr]     = useState(null);

  const run = async () => {
    setLoading(true); setErr(null); setResult(null);
    try {
      const { data } = await api.post(
        "/admin/content-supply-chain/e2e/snort-golden");
      setResult(data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "unavailable");
    } finally {
      setLoading(false);
    }
  };

  const copy = () => {
    if (!result) return;
    navigator.clipboard?.writeText(JSON.stringify(result, null, 2));
  };

  const stages = result?.stages || [];

  return (
    <div data-testid={testid || "golden-pipeline-trace"}
              className="panel"
              style={{
                padding: "14px 16px", marginBottom: 14,
                borderLeft: "3px solid var(--nx-purple, #6D4EE0)",
              }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 10, marginBottom: 8,
      }}>
        <span style={{
          fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
          letterSpacing: ".6px", textTransform: "uppercase",
          color: "var(--nx-purple, var(--cyan))",
        }}>
          Golden E2E · Snort → Incident
        </span>
        <span style={{ flex: 1 }} />
        <button data-testid="golden-run-btn"
                    className="btn ghost"
                    disabled={loading}
                    onClick={run}
                    style={{ padding: "3px 12px", fontSize: 11 }}>
          <Play size={11} /> {loading ? "Running…" : "Replay Snort golden"}
        </button>
        {result && (
          <button data-testid="golden-copy-json-btn"
                       className="btn ghost"
                       onClick={copy}
                       style={{ padding: "3px 12px", fontSize: 11 }}>
            <Copy size={11} /> JSON
          </button>
        )}
      </div>

      {err && (
        <div data-testid="golden-error"
                  style={{ padding: 10, fontFamily: "var(--mono)",
                                  fontSize: 11, color: "var(--amber)" }}>
          {err}
        </div>
      )}

      {!result && !err && (
        <div style={{ padding: 10, fontFamily: "var(--mono)",
                            fontSize: 11, color: "var(--faint)",
                            lineHeight: 1.5 }}>
          Press <b>Replay Snort golden</b> to execute the deterministic
          Suricata-EVE alert through the full NivXRay XDR pipeline.
          Every stage is real code; nothing is fabricated.
        </div>
      )}

      {result && (
        <>
          <div style={{ display: "flex", gap: 12, alignItems: "center",
                              fontFamily: "var(--mono)", fontSize: 11,
                              marginBottom: 10 }}>
            <span style={{ color: "var(--text-dim)" }}>
              trace_id: <span style={{ color: "var(--cyan)" }}>
                {result.trace_id}
              </span>
            </span>
            <span style={{ color: "var(--text-dim)" }}>
              executed: <b style={{ color: "var(--mint)" }}>
                {result.executed}
              </b>
              <span style={{ color: "var(--faint)" }}>
                {" "}/ {result.total}
              </span>
            </span>
            <span style={{ color: "var(--text-dim)" }}>
              verdict: <b style={{
                color: result.verdict === "COMPLETE" ? "var(--mint)"
                                                                        : "var(--amber)",
              }}>{result.verdict}</b>
            </span>
            {result.blocker && (
              <span style={{ color: "var(--amber)" }}>
                blocker: <b>{result.blocker}</b>
              </span>
            )}
          </div>

          <div style={{ display: "grid",
                              gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
                              gap: 8, alignItems: "start" }}>
            {stages.map((s, i) => (
              <React.Fragment key={s.stage + i}>
                <StageChip s={s} index={i} />
              </React.Fragment>
            ))}
          </div>

          <VerdictCard result={result} />

          {result?.incident?.created && result?.incident?.incident_id && (
            <InvestigationLanes incidentId={result.incident.incident_id}
                                          testid="golden-investigation-lanes" />
          )}

          <div style={{ marginTop: 10, fontFamily: "var(--mono)",
                              fontSize: 9.5, color: "var(--faint)",
                              lineHeight: 1.5 }}>
            {result.honesty_note}
          </div>
        </>
      )}
    </div>
  );
}


const metaLabel = {
  fontSize: 9, color: "var(--faint)", textTransform: "uppercase",
  letterSpacing: ".4px", fontFamily: "var(--mono)", fontWeight: 700,
};
const metaValue = {
  fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700,
  color: "var(--text)",
};
