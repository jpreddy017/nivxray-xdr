/**
 * ResponseFabricPanel — Round 13 · P0.7 · Response Fabric UI (read-only).
 *
 * Renders honest state from
 *   GET /api/admin/content-supply-chain/response/:incident_id
 *
 *   Recommendations · Decision · Approval · Execution
 *
 * Never fabricates SUCCESS.  Adapter results appear only when the
 * executor genuinely reports SUCCEEDED.
 */
import React, { useEffect, useState } from "react";
import { Lightbulb, Gavel, ShieldCheck, PlayCircle,
                CheckCircle2, XCircle, Circle, AlertTriangle,
                Radar } from "lucide-react";
import api from "@/lib/api";


const DECISION_COLOR = {
  NO_RESPONSE_JUSTIFIED:         "var(--faint)",
  ANALYST_INVESTIGATION_REQUIRED: "var(--amber)",
  DIRECT_ACTION_AVAILABLE:       "var(--mint)",
  PLAYBOOK_AVAILABLE:            "#38bdf8",
  APPROVAL_REQUIRED:             "var(--amber)",
  CAPABILITY_UNAVAILABLE:        "#f87171",
};

const EXEC_COLOR = {
  SUCCEEDED:         "var(--mint)",
  RUNNING:           "#38bdf8",
  APPROVAL_REQUIRED: "var(--amber)",
  QUEUED:            "var(--faint)",
  NOT_CONFIGURED:    "#f87171",
  NOT_SUPPORTED:     "#f87171",
  FAILED:            "#f87171",
  TIMEOUT:           "#f87171",
  REJECTED:          "#f87171",
};


export default function ResponseFabricPanel({ incidentId, testid }) {
  const [data,    setData]    = useState(null);
  const [err,     setErr]     = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!incidentId) return;
    setLoading(true); setErr(null); setData(null);
    (async () => {
      try {
        const r = await api.get(
          `/admin/content-supply-chain/response/${incidentId}`);
        setData(r.data);
      } catch (e) {
        setErr(e?.response?.data?.detail || e?.message || "unavailable");
      } finally {
        setLoading(false);
      }
    })();
  }, [incidentId]);

  if (!incidentId) return null;
  if (loading) {
    return (
      <div data-testid={testid || "response-fabric"}
                className="panel"
                style={{ padding: 12, fontFamily: "var(--mono)",
                                fontSize: 11, color: "var(--faint)",
                                marginTop: 14,
                                borderLeft: "3px solid #38bdf8" }}>
        Running Response Fabric for {incidentId}…
      </div>
    );
  }
  if (err || !data) {
    return (
      <div data-testid={testid || "response-fabric"}
                className="panel"
                style={{ padding: 12, fontFamily: "var(--mono)",
                                fontSize: 11, color: "var(--amber)",
                                marginTop: 14 }}>
        {err || "no data"}
      </div>
    );
  }

  const recos    = data.recommendations || [];
  const decision = data.decision        || {};
  const approval = data.approval        || null;
  const exec     = data.execution       || null;

  return (
    <div data-testid={testid || "response-fabric"}
              className="panel"
              style={{ padding: "14px 16px", marginTop: 14,
                              borderLeft: "3px solid #38bdf8" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                          marginBottom: 10 }}>
        <span style={{
          fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
          letterSpacing: ".6px", textTransform: "uppercase",
          color: "#38bdf8",
        }}>
          Response Fabric · {data.incident_id}
        </span>
        <span style={{ flex: 1 }} />
        <span style={{ fontFamily: "var(--mono)", fontSize: 11,
                            color: "var(--text-dim)" }}>
          {recos.length} recos · decision={decision.decision}
        </span>
      </div>

      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: 10,
      }}>
        {/* Recommendations */}
        <Card icon={Lightbulb} title="Recommendations"
                 testid="response-recos">
          {recos.length === 0 && (
            <Empty reason="no recommendations for this context" />
          )}
          {recos.map((r) => (
            <div key={r.id} data-testid={`reco-${r.id}`}
                      style={rowStyle}>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <ConfidencePill c={r.confidence} />
                {r.suggested_action && (
                  <span style={actionPill}>{r.suggested_action}</span>
                )}
              </div>
              <div style={{ marginTop: 4, fontSize: 11.5,
                                  color: "var(--text-dim)",
                                  fontFamily: "var(--sans)" }}>
                {r.text}
              </div>
            </div>
          ))}
        </Card>

        {/* Decision */}
        <Card icon={Gavel} title="Response Decision"
                 testid="response-decision">
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <span style={{
              padding: "2px 8px",
              border: `1px solid ${DECISION_COLOR[decision.decision]
                                                || "var(--faint)"}`,
              color:  DECISION_COLOR[decision.decision] || "var(--faint)",
              borderRadius: 2, fontFamily: "var(--mono)",
              fontSize: 10, fontWeight: 700,
            }}>{decision.decision}</span>
            {decision.policy_status && decision.policy_status !== "NOT_APPLICABLE" && (
              <span style={{ ...actionPill, color: "var(--faint)",
                                    borderColor: "var(--faint)" }}>
                {decision.policy_status}
              </span>
            )}
          </div>
          <div style={{ marginTop: 6, fontSize: 11.5,
                              color: "var(--text-dim)",
                              fontFamily: "var(--sans)" }}>
            {decision.reason}
          </div>
          {decision.required_action && (
            <div style={{ marginTop: 6, fontFamily: "var(--mono)",
                                fontSize: 10.5, color: "var(--cyan)" }}>
              action → {decision.required_action}
            </div>
          )}
        </Card>

        {/* Approval + Execution */}
        <Card icon={ShieldCheck} title="Approval"
                 testid="response-approval">
          {!approval && <Empty reason="no approval step for this decision" />}
          {approval && (
            <>
              <div style={{ fontFamily: "var(--mono)", fontSize: 11 }}>
                <b>{approval.state}</b> · policy=<b>{approval.policy}</b>
              </div>
              <div style={{ marginTop: 4, fontSize: 11,
                                  fontFamily: "var(--sans)",
                                  color: "var(--text-dim)" }}>
                {approval.reason}
              </div>
            </>
          )}
        </Card>

        <Card icon={PlayCircle} title="Execution"
                 testid="response-execution">
          {!exec && <Empty reason="no execution recorded" />}
          {exec && (
            <>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <span style={{
                  padding: "2px 8px",
                  border: `1px solid ${EXEC_COLOR[exec.state]
                                                    || "var(--faint)"}`,
                  color:  EXEC_COLOR[exec.state] || "var(--faint)",
                  borderRadius: 2, fontFamily: "var(--mono)",
                  fontSize: 10, fontWeight: 700,
                }}>{exec.state}</span>
                <span style={{ fontFamily: "var(--mono)",
                                      fontSize: 10.5, color: "var(--faint)" }}>
                  {exec.execution_id}
                </span>
              </div>
              <div style={{ marginTop: 4, fontSize: 11,
                                  fontFamily: "var(--sans)",
                                  color: "var(--text-dim)",
                                  lineHeight: 1.5 }}>
                {exec.reason}
              </div>
              {exec.adapter_result && (
                <div style={{ marginTop: 8, padding: "6px 8px",
                                    border: "1px solid var(--border)",
                                    borderRadius: 3,
                                    background: "var(--panel2)" }}>
                  <div style={{ display: "flex", alignItems: "center",
                                        gap: 6 }}>
                    <Radar size={11} style={{ color: "var(--cyan)" }} />
                    <b style={{ fontFamily: "var(--mono)", fontSize: 10 }}>
                      Adapter result
                    </b>
                  </div>
                  <div style={{ marginTop: 3, fontFamily: "var(--mono)",
                                        fontSize: 10.5 }}>
                    verdict=<b style={{ color: "var(--mint)" }}>
                      {exec.adapter_result.verdict}
                    </b> · score={exec.adapter_result.score}
                  </div>
                  <div style={{ marginTop: 3, fontFamily: "var(--mono)",
                                        fontSize: 10, color: "var(--faint)" }}>
                    providers={(exec.adapter_result.providers || []).length}
                  </div>
                </div>
              )}
            </>
          )}
        </Card>
      </div>

      <div style={{ marginTop: 10, fontFamily: "var(--mono)",
                          fontSize: 9.5, color: "var(--faint)",
                          lineHeight: 1.5 }}>
        {data.honesty_note}
      </div>
    </div>
  );
}


function Card({ icon: Icon, title, testid, children }) {
  return (
    <div data-testid={testid}
              style={{ border: "1px solid var(--border)", borderRadius: 4,
                              padding: 10, background: "var(--panel2)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6,
                          marginBottom: 6 }}>
        <Icon size={12} style={{ color: "var(--cyan)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 12,
                          color: "var(--text)" }}>{title}</b>
      </div>
      {children}
    </div>
  );
}


function ConfidencePill({ c }) {
  const color = c === "HIGH" ? "var(--mint)"
                        : c === "MEDIUM" ? "var(--amber)"
                        :                          "var(--faint)";
  return (
    <span style={{
      padding: "1px 6px", border: `1px solid ${color}`,
      color, borderRadius: 2, fontFamily: "var(--mono)",
      fontSize: 9, fontWeight: 700,
    }}>{c}</span>
  );
}

function Empty({ reason }) {
  return (
    <div style={{ fontFamily: "var(--mono)", fontSize: 10.5,
                        color: "var(--faint)", lineHeight: 1.5 }}>
      {reason}
    </div>
  );
}


const rowStyle = {
  padding: "6px 0", borderBottom: "1px solid var(--border)",
};
const actionPill = {
  padding: "1px 6px", border: "1px solid var(--cyan)",
  color: "var(--cyan)", borderRadius: 2,
  fontFamily: "var(--mono)", fontSize: 9, fontWeight: 700,
};
