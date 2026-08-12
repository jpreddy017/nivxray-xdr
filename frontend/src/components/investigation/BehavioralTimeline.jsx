/**
 * BehavioralTimeline.jsx — P2 UI Slice · Behavioral Evidence Timeline
 * (ADR-0010t).
 *
 * READ-ONLY projection of the backend behavioral evidence produced by:
 *   · POST /api/behavioral/sysmon       (Sysmon XML)
 *   · POST /api/behavioral/sysmon/evtx  (EVTX binary transport)
 *
 * The component renders Event 1 (Process Create) and Event 3
 * (Network Connect) rows. Event 3 rows carry a correlation-state
 * chip (RESOLVED · UNRESOLVED_DANGLING · AMBIGUOUS_PID_ONLY) and,
 * when applicable, deduplication metadata (count · first_seen ·
 * last_seen · raw_refs). Clicking any row opens an inline evidence
 * inspector.
 *
 * IMPORTANT — this component is a projection only:
 *   · does NOT run a MITRE mapper
 *   · does NOT infer ATT&CK techniques
 *   · does NOT compute verdicts
 *   · does NOT persist to IKG
 * All truth flows: Evidence → Correlation → authoritative MITRE
 * (from the backend) → the existing 14-tactic Attack Chain panel.
 */
import React, { useMemo, useState, useCallback } from "react";
import axios from "axios";

const BACKEND = process.env.REACT_APP_BACKEND_URL;

function authHeaders() {
  const t = localStorage.getItem("nvx_token") || localStorage.getItem("token");
  return t ? { Authorization: `Bearer ${t}` } : {};
}

const STATE_CHIP = {
  RESOLVED: { bg: "rgba(34,197,94,0.14)", fg: "#22c55e", label: "RESOLVED" },
  UNRESOLVED_DANGLING: {
    bg: "rgba(251,191,36,0.14)", fg: "#fbbf24", label: "UNRESOLVED · DANGLING",
  },
  AMBIGUOUS_PID_ONLY: {
    bg: "rgba(239,68,68,0.14)", fg: "#ef4444", label: "AMBIGUOUS · PID ONLY",
  },
};

function StateChip({ state }) {
  const meta = STATE_CHIP[state] || { bg: "rgba(148,163,184,0.12)", fg: "#94a3b8", label: state || "—" };
  return (
    <span
      data-testid={`corr-state-${state}`}
      style={{
        display: "inline-block",
        padding: "2px 8px",
        fontSize: 10,
        fontFamily: "JetBrains Mono, monospace",
        letterSpacing: "0.08em",
        borderRadius: 3,
        background: meta.bg,
        color: meta.fg,
        marginLeft: 8,
      }}>
      ● {meta.label}
    </span>
  );
}

function Row({ label, value }) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: 8, padding: "3px 0", fontSize: 12 }}>
      <span style={{ color: "#94a3b8", fontFamily: "JetBrains Mono, monospace" }}>{label}</span>
      <span style={{ color: "#e2e8f0", wordBreak: "break-all", fontFamily: "JetBrains Mono, monospace" }}>{String(value)}</span>
    </div>
  );
}

function EvidenceInspector({ item, kind, evidenceRecords }) {
  const related = useMemo(
    () => (evidenceRecords || []).filter((r) => r.evidence_ref === item.evidence_ref),
    [evidenceRecords, item]
  );
  const advisories = related.filter((r) => r.advisory);
  return (
    <div
      data-testid="behavioral-evidence-inspector"
      style={{
        margin: "8px 0 4px 24px", padding: 12, borderRadius: 6,
        background: "rgba(15,23,42,0.65)", border: "1px solid rgba(148,163,184,0.16)",
      }}>
      <div style={{ fontSize: 11, letterSpacing: "0.14em", color: "#94a3b8", marginBottom: 8, textTransform: "uppercase" }}>
        {kind === "eid1" ? "Process Create · Inspector" : "Network Connect · Inspector"}
      </div>

      <div style={{ marginBottom: 6, fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.1em" }}>Process</div>
      <Row label="Image"        value={item.process_image || item.image} />
      <Row label="ProcessGuid"  value={item.process_guid} />
      <Row label="ProcessId"    value={item.process_pid || item.child_pid} />

      {kind === "eid3" && (
        <>
          <div style={{ margin: "10px 0 6px", fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.1em" }}>Network</div>
          <Row label="Protocol"        value={item.protocol} />
          <Row label="Initiated"       value={String(item.initiated)} />
          <Row label="Source"          value={item.source_ip && `${item.source_ip}:${item.source_port || "?"}`} />
          <Row label="Destination"     value={item.destination_ip && `${item.destination_ip}:${item.destination_port || "?"}`} />
          <Row label="DestHostname"    value={item.destination_hostname} />
          <Row label="Dest class"      value={item.destination_class} />

          <div style={{ margin: "10px 0 6px", fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.1em" }}>Correlation</div>
          <div style={{ fontSize: 12 }}><StateChip state={item.correlation_state} /></div>
          <Row label="Linked to (E1)"  value={item.correlated_with_process_create} />
        </>
      )}

      {kind === "eid1" && (
        <>
          <div style={{ margin: "10px 0 6px", fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.1em" }}>Parent</div>
          <Row label="Parent image"    value={item.parent_image} />
          <Row label="Parent PID"      value={item.parent_pid} />
          <Row label="Parent GUID"     value={item.parent_process_guid} />
          <Row label="Corroboration"   value={item.corroboration && `${item.corroboration.count} field(s) · ${item.parent_child_uncorroborated ? "insufficient" : "sufficient"}`} />
        </>
      )}

      <div style={{ margin: "10px 0 6px", fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.1em" }}>Evidence</div>
      <Row label="evidence_ref"   value={item.evidence_ref} />
      {item.count !== undefined && <Row label="count" value={item.count} />}
      {item.first_seen && <Row label="first_seen" value={item.first_seen} />}
      {item.last_seen  && <Row label="last_seen"  value={item.last_seen} />}
      {item.raw_refs && item.raw_refs.length > 0 && (
        <Row label="raw_refs" value={item.raw_refs.join(", ")} />
      )}

      {advisories.length > 0 && (
        <>
          <div style={{ margin: "10px 0 6px", fontSize: 11, color: "#fbbf24", textTransform: "uppercase", letterSpacing: "0.1em" }}>
            Advisory fields · not authoritative
          </div>
          {advisories.map((r, i) => (
            <Row key={i} label={r.field.replace("network.", "")} value={`${r.observed_value} (derivation: ${r.derivation})`} />
          ))}
        </>
      )}
    </div>
  );
}


export default function BehavioralTimeline() {
  const [xml, setXml]           = useState("");
  const [response, setResponse] = useState(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState(null);
  const [selectedKey, setSelectedKey] = useState(null);

  const submitXml = useCallback(async () => {
    if (!xml.trim()) return;
    setLoading(true); setError(null); setResponse(null); setSelectedKey(null);
    try {
      const r = await axios.post(`${BACKEND}/api/behavioral/sysmon`, { xml },
                                   { headers: authHeaders() });
      setResponse(r.data);
    } catch (e) {
      setError(e?.response?.data?.detail?.message || e?.message || "request failed");
    } finally { setLoading(false); }
  }, [xml]);

  const submitEvtx = useCallback(async (file) => {
    if (!file) return;
    setLoading(true); setError(null); setResponse(null); setSelectedKey(null);
    try {
      const buf   = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let binary  = "";
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      const b64   = btoa(binary);
      const r = await axios.post(`${BACKEND}/api/behavioral/sysmon/evtx`,
                                   { evtx_base64: b64 },
                                   { headers: authHeaders() });
      setResponse(r.data);
    } catch (e) {
      setError(e?.response?.data?.detail?.message || e?.message || "request failed");
    } finally { setLoading(false); }
  }, []);

  const processCreates = response?.parent_child_evidence?.pairs || [];
  const networkConns   = response?.network_evidence?.connections || [];
  const evidence       = response?.evidence || [];
  const techniques     = response?.mitre_technique_ids || [];

  return (
    <div data-testid="behavioral-timeline-panel"
         style={{ margin: "0 12px 12px", padding: 16, borderRadius: 8,
                  background: "rgba(15,23,42,0.55)",
                  border: "1px solid rgba(148,163,184,0.16)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 12 }}>
        <div>
          <div style={{ fontSize: 13, letterSpacing: "0.14em", color: "#e2e8f0", textTransform: "uppercase", fontWeight: 600 }}>
            Behavioral Evidence Timeline
          </div>
          <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 4 }}>
            Observed evidence (Sysmon Event 1 · Event 3 · EVTX transport) — projection only. MITRE truth lives in the Attack Chain above.
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <label data-testid="evtx-drop"
                 style={{ fontSize: 11, padding: "4px 10px", border: "1px solid rgba(148,163,184,0.2)",
                          borderRadius: 4, cursor: "pointer", color: "#94a3b8" }}>
            Drop .evtx…
            <input type="file" accept=".evtx" style={{ display: "none" }}
                   onChange={(e) => submitEvtx(e.target.files?.[0])} />
          </label>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8, marginBottom: 12 }}>
        <textarea data-testid="sysmon-xml-input"
                  rows={4} value={xml} onChange={(e) => setXml(e.target.value)}
                  placeholder="Paste Sysmon Event XML (single <Event> or <Events> wrapper) …"
                  style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11,
                           background: "rgba(2,6,23,0.7)", color: "#e2e8f0",
                           border: "1px solid rgba(148,163,184,0.18)", borderRadius: 4,
                           padding: 8, resize: "vertical" }} />
        <button data-testid="behavioral-submit-btn"
                onClick={submitXml} disabled={loading || !xml.trim()}
                style={{ padding: "6px 14px", fontSize: 12, borderRadius: 4,
                         background: loading ? "#334155" : "#38bdf8",
                         color: "#0f172a", border: 0, cursor: loading ? "wait" : "pointer",
                         alignSelf: "start" }}>
          {loading ? "Ingesting…" : "Ingest"}
        </button>
      </div>

      {error && (
        <div data-testid="behavioral-error"
             style={{ padding: 8, background: "rgba(239,68,68,0.08)",
                      border: "1px solid rgba(239,68,68,0.24)", borderRadius: 4,
                      color: "#fca5a5", fontSize: 11, marginBottom: 8, fontFamily: "JetBrains Mono, monospace" }}>
          {error}
        </div>
      )}

      {response && (
        <>
          {/* Summary strip */}
          <div style={{ display: "flex", gap: 12, marginBottom: 12, fontSize: 11, color: "#94a3b8",
                        fontFamily: "JetBrains Mono, monospace" }}>
            <span data-testid="summary-e1-count">E1 · {response.event_counts_by_id?.eid1 || 0}</span>
            <span data-testid="summary-e3-count">E3 · {response.event_counts_by_id?.eid3 || 0}</span>
            <span data-testid="summary-mitre-count">MITRE · {techniques.length}</span>
            {response.transport && (
              <span data-testid="summary-transport">transport · {response.transport.transport} · {response.transport.record_count} rec</span>
            )}
          </div>

          {/* Event 1 rows */}
          {processCreates.map((pc, i) => {
            const key = `e1-${pc.evidence_ref || i}`;
            const open = selectedKey === key;
            return (
              <div key={key}>
                <div data-testid={`e1-row-${i}`}
                     onClick={() => setSelectedKey(open ? null : key)}
                     style={{ display: "flex", alignItems: "center", padding: "8px 6px",
                              borderLeft: "3px solid #38bdf8", background: "rgba(56,189,248,0.04)",
                              cursor: "pointer", marginBottom: 4, borderRadius: 3 }}>
                  <span style={{ fontSize: 10, color: "#38bdf8", fontFamily: "JetBrains Mono, monospace",
                                 padding: "1px 6px", background: "rgba(56,189,248,0.12)", borderRadius: 2 }}>E1</span>
                  <span style={{ marginLeft: 10, fontSize: 12, color: "#e2e8f0", fontFamily: "JetBrains Mono, monospace" }}>
                    Process Create · {pc.child_image}
                  </span>
                  <span style={{ marginLeft: "auto", fontSize: 10, color: "#94a3b8",
                                 fontFamily: "JetBrains Mono, monospace" }}>
                    PID {pc.child_pid} · {pc.evidence_ref}
                  </span>
                </div>
                {open && <EvidenceInspector item={pc} kind="eid1" evidenceRecords={evidence} />}
              </div>
            );
          })}

          {/* Event 3 rows */}
          {networkConns.map((c, i) => {
            const key = `e3-${c.evidence_ref || i}`;
            const open = selectedKey === key;
            return (
              <div key={key}>
                <div data-testid={`e3-row-${i}`}
                     onClick={() => setSelectedKey(open ? null : key)}
                     style={{ display: "flex", alignItems: "center", padding: "8px 6px",
                              borderLeft: `3px solid ${c.correlation_state === "RESOLVED" ? "#22c55e" : "#fbbf24"}`,
                              background: "rgba(34,197,94,0.03)", cursor: "pointer",
                              marginBottom: 4, borderRadius: 3 }}>
                  <span style={{ fontSize: 10, color: "#22c55e", fontFamily: "JetBrains Mono, monospace",
                                 padding: "1px 6px", background: "rgba(34,197,94,0.12)", borderRadius: 2 }}>E3</span>
                  <span style={{ marginLeft: 10, fontSize: 12, color: "#e2e8f0", fontFamily: "JetBrains Mono, monospace" }}>
                    Network Connect · {c.process_image} → {c.destination_ip}:{c.destination_port}
                  </span>
                  <StateChip state={c.correlation_state} />
                  {c.count > 1 && (
                    <span data-testid={`e3-dedup-${i}`}
                          style={{ marginLeft: 8, fontSize: 10, color: "#fbbf24",
                                   fontFamily: "JetBrains Mono, monospace",
                                   padding: "1px 6px", background: "rgba(251,191,36,0.12)", borderRadius: 2 }}>
                      ×{c.count} · dedup
                    </span>
                  )}
                  <span style={{ marginLeft: "auto", fontSize: 10, color: "#94a3b8",
                                 fontFamily: "JetBrains Mono, monospace" }}>
                    {c.destination_class} · {c.evidence_ref}
                  </span>
                </div>
                {open && <EvidenceInspector item={c} kind="eid3" evidenceRecords={evidence} />}
              </div>
            );
          })}

          {processCreates.length === 0 && networkConns.length === 0 && (
            <div style={{ padding: 12, textAlign: "center", color: "#64748b", fontSize: 11 }}>
              No behavioral events emitted.
            </div>
          )}

          {/* MITRE handoff line — READ-ONLY reference to the authoritative surface */}
          {techniques.length > 0 && (
            <div data-testid="mitre-handoff"
                 style={{ marginTop: 12, padding: 10, borderRadius: 4,
                          background: "rgba(56,189,248,0.05)",
                          border: "1px dashed rgba(56,189,248,0.2)",
                          fontSize: 11, color: "#94a3b8",
                          fontFamily: "JetBrains Mono, monospace" }}>
              ↳ Authoritative MITRE surface (from Event 1 command lines):
              <span style={{ color: "#38bdf8", marginLeft: 6 }}>
                {techniques.join(" · ")}
              </span>
              <div style={{ marginTop: 4, fontSize: 10, color: "#64748b" }}>
                These techniques appear in the 14-tactic Attack Chain above. This timeline does NOT infer techniques on its own.
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
