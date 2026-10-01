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


export default function BehavioralTimeline({ caseId } = {}) {
  const [xml, setXml]           = useState("");
  const [response, setResponse] = useState(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState(null);
  const [selectedKey, setSelectedKey] = useState(null);
  // UI-Slice-2 (ADR-0010u): incoming MITRE→Evidence highlight state.
  const [highlightedTechnique, setHighlightedTechnique] = useState(null);
  // UI-Slice-3 (ADR-0010v): persistence status surfaced to the analyst.
  const [persistMeta, setPersistMeta] = useState(null);
  const timelineTopRef = React.useRef(null);

  // ─────────────────────────────────────────────────────────────────
  // Persistence hydration — when the Workspace supplies a caseId,
  // reload any envelope attached to that case. This makes the
  // Behavioral Evidence Timeline survive page refresh and case reopen
  // WITHOUT re-ingesting the Sysmon/EVTX bytes.
  // The persisted payload IS the canonical evidence envelope produced
  // by the backend adapter (evidence_ref, correlation_state, raw_refs,
  // per_event_mitre) — no rendered UI state, no client inference.
  // ─────────────────────────────────────────────────────────────────
  React.useEffect(() => {
    if (!caseId) {
      // Case cleared → drop any hydrated state so the panel starts fresh.
      setResponse(null); setPersistMeta(null); setSelectedKey(null);
      setError(null); setHighlightedTechnique(null);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const r = await axios.get(
          `${BACKEND}/api/behavioral/case/${encodeURIComponent(caseId)}`,
          { headers: authHeaders() });
        if (cancelled) return;
        if (r.data?.envelope) {
          setResponse(r.data.envelope);
          setPersistMeta({
            attached_at: r.data.attached_at,
            updated_at:  r.data.updated_at,
            adapter_history: r.data.adapter_history || [],
          });
        }
      } catch (e) {
        // 404 is the normal "nothing attached yet" case — silent.
        if (e?.response?.status !== 404) {
          // Any other error surfaces once so it doesn't loop.
          if (!cancelled) setError(
            e?.response?.data?.detail?.message || e?.message || "hydrate failed");
        }
      }
    })();
    return () => { cancelled = true; };
  }, [caseId]);

  // Backend response gives per_event_mitre[i] = { event_index, command_line,
  // techniques: [{id,...}] } for each Event-1. Build a lookup:
  //   e1_evidence_ref → set of technique ids
  //   e3_correlated_e1_ref → same techniques (RESOLVED path only)
  const {e1RefToTechs, e3RefToTechs, techToE1Refs, techToE3Refs} = useMemo(() => {
    const e1RefToTechs = new Map();
    const e3RefToTechs = new Map();
    const techToE1Refs = new Map();
    const techToE3Refs = new Map();
    if (!response) return {e1RefToTechs, e3RefToTechs, techToE1Refs, techToE3Refs};
    const pairs = response.parent_child_evidence?.pairs || [];
    const perEvent = response.per_event_mitre || [];
    pairs.forEach((pc, i) => {
      const techs = new Set((perEvent[i]?.techniques || []).map(t => t.id));
      e1RefToTechs.set(pc.evidence_ref, techs);
      techs.forEach(tid => {
        if (!techToE1Refs.has(tid)) techToE1Refs.set(tid, new Set());
        techToE1Refs.get(tid).add(pc.evidence_ref);
      });
    });
    (response.network_evidence?.connections || []).forEach(c => {
      // Only RESOLVED connections inherit their E1's techniques.
      if (c.correlation_state === "RESOLVED" && c.correlated_with_process_create) {
        const techs = e1RefToTechs.get(c.correlated_with_process_create) || new Set();
        e3RefToTechs.set(c.evidence_ref, techs);
        techs.forEach(tid => {
          if (!techToE3Refs.has(tid)) techToE3Refs.set(tid, new Set());
          techToE3Refs.get(tid).add(c.evidence_ref);
        });
      } else {
        e3RefToTechs.set(c.evidence_ref, new Set());
      }
    });
    return {e1RefToTechs, e3RefToTechs, techToE1Refs, techToE3Refs};
  }, [response]);

  // Inbound: listen for MITRE→Evidence selection from the Attack Chain.
  React.useEffect(() => {
    const onMitreSelected = (ev) => {
      const tid = ev.detail?.technique_id;
      if (!tid) return;
      setHighlightedTechnique(tid);
      const refs = new Set([
        ...(techToE1Refs.get(tid) || []),
        ...(techToE3Refs.get(tid) || []),
      ]);
      // Scroll the first supporting row into view.
      setTimeout(() => {
        const first = document.querySelector('[data-mitre-support="' + tid + '"]');
        if (first) first.scrollIntoView({behavior: "smooth", block: "center"});
        else if (timelineTopRef.current) timelineTopRef.current.scrollIntoView({behavior: "smooth", block: "start"});
      }, 50);
    };
    window.addEventListener("nivx:mitre-selected", onMitreSelected);
    return () => window.removeEventListener("nivx:mitre-selected", onMitreSelected);
  }, [techToE1Refs, techToE3Refs]);

  const emitEvidenceSelected = useCallback((techs) => {
    const ids = Array.from(techs || []);
    window.dispatchEvent(new CustomEvent("nivx:evidence-selected", {
      detail: { technique_ids: ids },
    }));
  }, []);

  const submitXml = useCallback(async () => {
    if (!xml.trim()) return;
    setLoading(true); setError(null); setResponse(null); setSelectedKey(null);
    try {
      const payload = caseId ? { xml, case_id: caseId } : { xml };
      const r = await axios.post(`${BACKEND}/api/behavioral/sysmon`, payload,
                                   { headers: authHeaders() });
      setResponse(r.data);
      if (caseId) {
        setPersistMeta({
          attached_at: new Date().toISOString(),
          updated_at:  new Date().toISOString(),
          adapter_history: [],  // refreshed on next hydrate
        });
      }
    } catch (e) {
      setError(e?.response?.data?.detail?.message || e?.message || "request failed");
    } finally { setLoading(false); }
  }, [xml, caseId]);

  const submitEvtx = useCallback(async (file) => {
    if (!file) return;
    setLoading(true); setError(null); setResponse(null); setSelectedKey(null);
    try {
      const buf   = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let binary  = "";
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      const b64   = btoa(binary);
      const payload = caseId
        ? { evtx_base64: b64, case_id: caseId }
        : { evtx_base64: b64 };
      const r = await axios.post(`${BACKEND}/api/behavioral/sysmon/evtx`,
                                   payload,
                                   { headers: authHeaders() });
      setResponse(r.data);
      if (caseId) {
        setPersistMeta({
          attached_at: new Date().toISOString(),
          updated_at:  new Date().toISOString(),
          adapter_history: [],
        });
      }
    } catch (e) {
      setError(e?.response?.data?.detail?.message || e?.message || "request failed");
    } finally { setLoading(false); }
  }, [caseId]);

  const detachEvidence = useCallback(async () => {
    if (!caseId) return;
    try {
      await axios.delete(`${BACKEND}/api/behavioral/case/${encodeURIComponent(caseId)}`,
                          { headers: authHeaders() });
      setResponse(null); setPersistMeta(null); setSelectedKey(null);
      setHighlightedTechnique(null);
    } catch (e) {
      setError(e?.response?.data?.detail?.message || e?.message || "detach failed");
    }
  }, [caseId]);

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
          {caseId && (
            <span data-testid="behavioral-case-scope"
                  title={`Attached to case ${caseId}`}
                  style={{ fontSize: 10, padding: "2px 8px",
                            border: "1px solid rgba(56,189,248,0.35)",
                            borderRadius: 3, color: "#38bdf8",
                            fontFamily: "JetBrains Mono, monospace",
                            letterSpacing: "0.08em" }}>
              case · {caseId.slice(0, 8)}
            </span>
          )}
          {caseId && persistMeta && (
            <button data-testid="behavioral-detach-btn"
                    onClick={detachEvidence}
                    style={{ fontSize: 10, padding: "3px 8px",
                              background: "transparent",
                              border: "1px solid rgba(148,163,184,0.2)",
                              borderRadius: 3, color: "#94a3b8",
                              cursor: "pointer",
                              fontFamily: "JetBrains Mono, monospace" }}>
              detach
            </button>
          )}
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
            {caseId && persistMeta && (
              <span data-testid="summary-persist"
                    title={`updated ${persistMeta.updated_at}`}
                    style={{ color: "#22c55e" }}>
                persisted · case {caseId.slice(0, 8)}
              </span>
            )}
          </div>

          <div ref={timelineTopRef} />
          {/* Event 1 rows */}
          {processCreates.map((pc, i) => {
            const key = `e1-${pc.evidence_ref || i}`;
            const open = selectedKey === key;
            const supportsHighlight = highlightedTechnique
              && e1RefToTechs.get(pc.evidence_ref)?.has(highlightedTechnique);
            const techList = Array.from(e1RefToTechs.get(pc.evidence_ref) || []);
            return (
              <div key={key}>
                <div data-testid={`e1-row-${i}`}
                     data-mitre-support={supportsHighlight ? highlightedTechnique : undefined}
                     onClick={() => {
                       const nowOpen = !open;
                       setSelectedKey(nowOpen ? key : null);
                       if (nowOpen) emitEvidenceSelected(e1RefToTechs.get(pc.evidence_ref));
                     }}
                     style={{ display: "flex", alignItems: "center", padding: "8px 6px",
                              borderLeft: "3px solid #38bdf8",
                              background: supportsHighlight
                                ? "rgba(251,191,36,0.14)" : "rgba(56,189,248,0.04)",
                              boxShadow: supportsHighlight ? "inset 0 0 0 1px rgba(251,191,36,0.55)" : "none",
                              cursor: "pointer", marginBottom: 4, borderRadius: 3 }}>
                  <span style={{ fontSize: 10, color: "#38bdf8", fontFamily: "JetBrains Mono, monospace",
                                 padding: "1px 6px", background: "rgba(56,189,248,0.12)", borderRadius: 2 }}>E1</span>
                  <span style={{ marginLeft: 10, fontSize: 12, color: "#e2e8f0", fontFamily: "JetBrains Mono, monospace" }}>
                    Process Create · {pc.child_image}
                  </span>
                  {techList.length > 0 && (
                    <span style={{ marginLeft: 8, fontSize: 10, color: "#94a3b8",
                                   fontFamily: "JetBrains Mono, monospace" }}>
                      supports · {techList.join(", ")}
                    </span>
                  )}
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
            const supportsHighlight = highlightedTechnique
              && e3RefToTechs.get(c.evidence_ref)?.has(highlightedTechnique);
            const techList = Array.from(e3RefToTechs.get(c.evidence_ref) || []);
            return (
              <div key={key}>
                <div data-testid={`e3-row-${i}`}
                     data-mitre-support={supportsHighlight ? highlightedTechnique : undefined}
                     onClick={() => {
                       const nowOpen = !open;
                       setSelectedKey(nowOpen ? key : null);
                       if (nowOpen) emitEvidenceSelected(e3RefToTechs.get(c.evidence_ref));
                     }}
                     style={{ display: "flex", alignItems: "center", padding: "8px 6px",
                              borderLeft: `3px solid ${c.correlation_state === "RESOLVED" ? "#22c55e" : "#fbbf24"}`,
                              background: supportsHighlight
                                ? "rgba(251,191,36,0.14)" : "rgba(34,197,94,0.03)",
                              boxShadow: supportsHighlight ? "inset 0 0 0 1px rgba(251,191,36,0.55)" : "none",
                              cursor: "pointer",
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
                  {techList.length > 0 && (
                    <span style={{ marginLeft: 8, fontSize: 10, color: "#94a3b8",
                                   fontFamily: "JetBrains Mono, monospace" }}>
                      via E1 · {techList.join(", ")}
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
              {techniques.map((tid, ti) => (
                <span key={tid}
                      data-testid={`mitre-chip-${tid}`}
                      onClick={() => {
                        setHighlightedTechnique(tid);
                        window.dispatchEvent(new CustomEvent("nivx:mitre-selected", {
                          detail: { technique_id: tid },
                        }));
                      }}
                      style={{ color: highlightedTechnique === tid ? "#fbbf24" : "#38bdf8",
                               marginLeft: 6, cursor: "pointer",
                               padding: "1px 5px", borderRadius: 2,
                               background: highlightedTechnique === tid
                                 ? "rgba(251,191,36,0.14)" : "transparent",
                               boxShadow: highlightedTechnique === tid
                                 ? "inset 0 0 0 1px rgba(251,191,36,0.55)" : "none" }}>
                  {tid}
                </span>
              ))}
              {highlightedTechnique && (
                <span data-testid="mitre-clear"
                      onClick={() => setHighlightedTechnique(null)}
                      style={{ marginLeft: 10, cursor: "pointer",
                               color: "#64748b", textDecoration: "underline" }}>
                  clear
                </span>
              )}
              <div style={{ marginTop: 4, fontSize: 10, color: "#64748b" }}>
                Click a technique above → supporting E1/E3 rows highlight. Click an evidence row → its technique(s) broadcast to the Attack Chain.
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
