/**
 * VisualExecutionStudio — evolution of the Playbook Simulator.
 *
 * Two modes:
 *   • DEBUG (dry-run)  → drives the standalone Response Engine's
 *                        /simulate-playbook route with dry_run=True.
 *                        Every step is a real Executor pass; no
 *                        vendor SDK is touched.
 *   • LIVE            → drives the standalone Response Engine's
 *                        /execute route per action node, using the
 *                        exact same execution contract as the analyst
 *                        drawer and automation rules.  Persisted state
 *                        machine — approval-required actions park in
 *                        WAITING_APPROVAL and can be approved from the
 *                        studio itself.
 *
 * Debug controls: breakpoint, pause, resume, step-over, step-into,
 *                 force TRUE/FALSE branch, action-output override.
 *
 * Owner-locked: the Studio NEVER fabricates a successful state — every
 * node's status is the actual state returned by the Response Engine.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Play, Pause, SkipForward, ChevronsRight, Circle, X, Zap, Check,
  Bug, ChevronDown, ChevronRight, AlertTriangle, Clock, FileCheck2,
} from "lucide-react";

import * as Engine from "@/xdr/respond/responseEngineApi";
import { EXEC_STATE, TERMINAL_STATES } from "@/xdr/respond/responseEngineApi";
import { getAction } from "@/xdr/respond/actionRegistry";


const NODE_STATE = {
  IDLE:              "idle",
  READY:             "ready",
  RUNNING:           "running",
  WAITING_APPROVAL:  "waiting_approval",
  OK:                "ok",
  FAIL:              "fail",
  SKIPPED:           "skipped",
  BREAKPOINT:        "breakpoint",
};


export default function VisualExecutionStudio({
  playbook, analystEmail, mode: initialMode = "debug",
}) {
  const [mode, setMode]       = useState(initialMode);      // "debug" | "live"
  const [event, setEvent]     = useState(
    '{"verdict":"malicious","severity":"critical","host_id":"HOST-A"}');
  const [running, setRunning] = useState(false);
  const [paused,  setPaused]  = useState(false);
  const [breakpoints, setBreakpoints] = useState(() => new Set());
  const [forceBranch, setForceBranch] = useState({});   // {nodeId: "yes"|"no"}
  const [statuses, setStatuses] = useState({});         // {nodeId: NODE_STATE}
  const [logs, setLogs]         = useState([]);         // trace entries
  const [selected, setSelected] = useState(null);
  const [error, setError]       = useState(null);
  const [current, setCurrent]   = useState(null);
  const stepAdvance = useRef(null);                     // resolver for step gate
  const abortRef    = useRef({ cancelled: false });

  const nodeById = useMemo(
    () => Object.fromEntries((playbook?.nodes || []).map((n) => [n.id, n])),
    [playbook]);

  // ── controls ─────────────────────────────────────────────────
  const start = useCallback(async () => {
    if (!playbook) return;
    setStatuses({}); setLogs([]); setError(null);
    setRunning(true); setPaused(false);
    abortRef.current = { cancelled: false };
    try {
      const parsed = JSON.parse(event);
      if (mode === "debug") {
        await runDebug(parsed);
      } else {
        await runLive(parsed);
      }
    } catch (e) {
      setError(e?.message || String(e));
    } finally { setRunning(false); setPaused(false); setCurrent(null); }
  }, [playbook, mode, event]);

  const stop = useCallback(() => {
    abortRef.current.cancelled = true;
    setRunning(false); setPaused(false);
    // Resolve any waiting step so the walker exits its await.
    stepAdvance.current?.();
  }, []);

  const togglePause = useCallback(() => {
    setPaused((p) => {
      if (p) { stepAdvance.current?.(); }
      return !p;
    });
  }, []);
  const stepOver = useCallback(() => { stepAdvance.current?.(); }, []);

  const toggleBreakpoint = useCallback((nodeId) => {
    setBreakpoints((s) => {
      const n = new Set(s);
      if (n.has(nodeId)) n.delete(nodeId); else n.add(nodeId);
      return n;
    });
  }, []);

  const setBranch = useCallback((nodeId, value) => {
    setForceBranch((s) => ({ ...s, [nodeId]: value }));
  }, []);

  // ── debug walker (dry-run) ───────────────────────────────────
  async function runDebug(parsedEvent) {
    let cur = nodeById[playbook.entry];
    const seen = new Set(); let step = 0;
    while (cur && !seen.has(cur.id) && step < 200 && !abortRef.current.cancelled) {
      seen.add(cur.id); step++;
      setCurrent(cur.id);
      if (breakpoints.has(cur.id) || paused) {
        _setStatus(setStatuses, cur.id, NODE_STATE.BREAKPOINT);
        _log(setLogs, { step, node_id: cur.id, kind: cur.kind,
                            state: "paused-breakpoint" });
        await _awaitStep(stepAdvance);
        if (abortRef.current.cancelled) break;
      }
      _setStatus(setStatuses, cur.id, NODE_STATE.RUNNING);
      await _delay(paused ? 0 : 220);

      if (cur.kind === "start") {
        _setStatus(setStatuses, cur.id, NODE_STATE.OK);
        _log(setLogs, { step, node_id: cur.id, kind: "start", state: "ok" });
        cur = nodeById[cur.next]; continue;
      }
      if (cur.kind === "end") {
        _setStatus(setStatuses, cur.id, NODE_STATE.OK);
        _log(setLogs, { step, node_id: cur.id, kind: "end", state: "ok", terminal: true });
        break;
      }
      if (cur.kind === "condition") {
        const forced = forceBranch[cur.id];
        const branch = forced ? forced === "yes"
                                    : _evalCondition(cur.config || {}, parsedEvent);
        const nxtId = branch ? cur.yes_next : cur.no_next;
        _setStatus(setStatuses, cur.id, NODE_STATE.OK);
        _log(setLogs, { step, node_id: cur.id, kind: "condition",
                            branch: branch ? "yes" : "no",
                            forced: !!forced,
                            config: cur.config, state: "ok" });
        cur = nodeById[nxtId]; continue;
      }
      if (cur.kind === "action") {
        try {
          const executionId = `sim-${playbook.id}-${cur.id}-${step}`;
          const res = await Engine.execute({
            execution_id:  executionId,
            tenant_id:     playbook.tenant_id || "simulate",
            invoker: { kind: "simulator", id: "playbook-simulator",
                          context: { playbook_id: playbook.id,
                                       playbook_node_id: cur.id } },
            action: { action_id: cur.action_id,
                         parameters: (cur.config || {}).parameters ||
                                          _extractParams(cur.config) },
            authorization: {
              scopes: _allScopes(cur.action_id),
              approval_ref: "sim-approval",
              approved_by:  "user:simulator",
              reason:       "Studio dry-run",
            },
            constraints: { dry_run: true },
          });
          const ok = res.state === EXEC_STATE.SUCCEEDED;
          _setStatus(setStatuses, cur.id, ok ? NODE_STATE.OK : NODE_STATE.FAIL);
          _log(setLogs, { step, node_id: cur.id, kind: "action",
                              action_id: cur.action_id, execution: res,
                              state: ok ? "ok" : "fail" });
        } catch (e) {
          _setStatus(setStatuses, cur.id, NODE_STATE.FAIL);
          _log(setLogs, { step, node_id: cur.id, kind: "action",
                              action_id: cur.action_id, state: "fail",
                              error: e?.response?.data?.detail?.error
                                        || e?.message || String(e) });
        }
        cur = nodeById[cur.next]; continue;
      }
      _setStatus(setStatuses, cur.id, NODE_STATE.SKIPPED);
      cur = nodeById[cur.next];
    }
  }

  // ── live walker ──────────────────────────────────────────────
  async function runLive(parsedEvent) {
    let cur = nodeById[playbook.entry];
    const seen = new Set(); let step = 0;
    const invoker = { kind: "playbook",
                          id: `pb:${playbook.id}`,
                          context: { playbook_id: playbook.id } };
    while (cur && !seen.has(cur.id) && step < 200 && !abortRef.current.cancelled) {
      seen.add(cur.id); step++;
      setCurrent(cur.id);
      if (breakpoints.has(cur.id)) {
        _setStatus(setStatuses, cur.id, NODE_STATE.BREAKPOINT);
        await _awaitStep(stepAdvance);
        if (abortRef.current.cancelled) break;
      }
      _setStatus(setStatuses, cur.id, NODE_STATE.RUNNING);
      if (cur.kind === "start") {
        _setStatus(setStatuses, cur.id, NODE_STATE.OK);
        cur = nodeById[cur.next]; continue;
      }
      if (cur.kind === "end") {
        _setStatus(setStatuses, cur.id, NODE_STATE.OK); break;
      }
      if (cur.kind === "condition") {
        const forced = forceBranch[cur.id];
        const branch = forced ? forced === "yes"
                                    : _evalCondition(cur.config || {}, parsedEvent);
        _setStatus(setStatuses, cur.id, NODE_STATE.OK);
        _log(setLogs, { step, node_id: cur.id, kind: "condition",
                            branch: branch ? "yes" : "no", forced: !!forced });
        cur = nodeById[branch ? cur.yes_next : cur.no_next]; continue;
      }
      if (cur.kind === "action") {
        try {
          const executionId = `exec-${playbook.id}-${cur.id}-${Date.now()}`;
          const params = (cur.config || {}).parameters || _extractParams(cur.config);
          let res = await Engine.execute({
            execution_id: executionId,
            tenant_id:    playbook.tenant_id || "acme",
            invoker,
            action:       { action_id: cur.action_id, parameters: params },
            authorization: { scopes: _allScopes(cur.action_id) },
            constraints:   { dry_run: false },
          });
          if (res.state === EXEC_STATE.WAITING_APPROVAL) {
            _setStatus(setStatuses, cur.id, NODE_STATE.WAITING_APPROVAL);
            _log(setLogs, { step, node_id: cur.id, kind: "action",
                                action_id: cur.action_id, execution: res,
                                state: "waiting_approval" });
            // Park — the run stays waiting for external approval.
            // Analyst can approve/reject from the Approvals section
            // rendered in the sidebar below.
            break;
          }
          if (!TERMINAL_STATES.has(res.state)) {
            res = await Engine.pollUntilTerminal(executionId, {
              tenantId:    playbook.tenant_id || "acme",
              invokerKind: "playbook", invokerId: invoker.id,
              onTick:      (row) => setStatuses((s) => ({ ...s,
                                       [cur.id]: row.state === EXEC_STATE.SUCCEEDED
                                                       ? NODE_STATE.OK
                                                       : NODE_STATE.RUNNING })),
            });
          }
          const ok = res.state === EXEC_STATE.SUCCEEDED;
          _setStatus(setStatuses, cur.id, ok ? NODE_STATE.OK : NODE_STATE.FAIL);
          _log(setLogs, { step, node_id: cur.id, kind: "action",
                              action_id: cur.action_id, execution: res,
                              state: ok ? "ok" : "fail" });
          if (!ok) break;
        } catch (e) {
          _setStatus(setStatuses, cur.id, NODE_STATE.FAIL);
          _log(setLogs, { step, node_id: cur.id, kind: "action",
                              action_id: cur.action_id, state: "fail",
                              error: e?.response?.data?.detail?.error
                                        || e?.message || String(e) });
          break;
        }
        cur = nodeById[cur.next]; continue;
      }
      _setStatus(setStatuses, cur.id, NODE_STATE.SKIPPED);
      cur = nodeById[cur.next];
    }
  }

  // Currently-selected node → open the execution card if we have one.
  const selectedLog = logs.find((l) => l.node_id === selected);

  return (
    <div data-testid="xdr-visual-execution-studio"
            style={{ display: "grid",
                        gridTemplateColumns: "1fr 320px",
                        gap: 12, alignItems: "start" }}>
      {/* Canvas */}
      <section className="panel" style={{ padding: 16 }}
                  data-testid="xdr-studio-canvas">
        <StudioToolbar
          mode={mode} onModeChange={setMode}
          running={running} paused={paused}
          onStart={start} onStop={stop}
          onTogglePause={togglePause} onStep={stepOver}
        />
        <div style={{ marginTop: 10, display: "flex", flexDirection: "column",
                          alignItems: "center", gap: 4 }}>
          {(playbook?.nodes || []).map((n) => (
            <NodeChip key={n.id} node={n}
                          state={statuses[n.id]}
                          isCurrent={current === n.id}
                          hasBreakpoint={breakpoints.has(n.id)}
                          forcedBranch={forceBranch[n.id]}
                          selected={selected === n.id}
                          onSelect={() => setSelected(n.id)}
                          onToggleBreakpoint={() => toggleBreakpoint(n.id)}
                          onForceBranch={(v) => setBranch(n.id, v)} />
          ))}
        </div>
      </section>

      {/* Inspector */}
      <aside className="panel" style={{ padding: 12 }}
                data-testid="xdr-studio-inspector">
        <div style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 800,
                          color: "var(--muted)", textTransform: "uppercase",
                          letterSpacing: ".3px", marginBottom: 8 }}>
          {mode === "live" ? "Live Execution" : "Debug Trace"}
        </div>

        {error && (
          <div data-testid="xdr-studio-error"
                  style={{ marginBottom: 10, padding: 8,
                              border: "1px solid #ff5b5b", borderRadius: 4,
                              background: "rgba(255,91,91,.08)",
                              color: "#ff9494", fontSize: 11 }}>
            <AlertTriangle size={11} /> {error}
          </div>
        )}

        <FieldLabel>Simulation Event (JSON)</FieldLabel>
        <textarea rows={4} value={event}
                     onChange={(e) => setEvent(e.target.value)}
                     className="x-input"
                     style={{ fontFamily: "var(--mono)", fontSize: 11 }}
                     data-testid="xdr-studio-event" />

        <FieldLabel>Trace</FieldLabel>
        <div data-testid="xdr-studio-trace"
                style={{ maxHeight: 260, overflow: "auto", border: "1px solid var(--border)",
                            borderRadius: 4, padding: 6, background: "var(--panel2)" }}>
          {logs.length === 0 && (
            <div style={{ color: "var(--faint)", fontSize: 11 }}>
              No steps yet. Press <b>Run</b> to walk the graph.
            </div>
          )}
          {logs.map((l, i) => (
            <div key={i} className="mono"
                    onClick={() => setSelected(l.node_id)}
                    style={{ padding: "3px 4px", cursor: "pointer",
                                fontSize: 10.5, borderBottom: "1px solid var(--border)",
                                color: l.state === "fail" ? "#ff9494"
                                        : l.state === "waiting_approval" ? "var(--amber)"
                                        : l.state === "paused-breakpoint" ? "var(--amber)"
                                        : "var(--text-dim)" }}>
              #{l.step} {l.kind?.toUpperCase()}
              {l.action_id ? " · " + l.action_id : ""}
              {l.branch ? " → " + l.branch + (l.forced ? " ⚑" : "") : ""}
              {" ["}{l.state}{"]"}
            </div>
          ))}
        </div>

        {selectedLog && selectedLog.execution && (
          <ExecutionInspector exec={selectedLog.execution}
                                      analystEmail={analystEmail}
                                      onDecision={() => start && start()} />
        )}
      </aside>
    </div>
  );
}


function StudioToolbar({ mode, onModeChange, running, paused,
                                onStart, onStop, onTogglePause, onStep }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                textTransform: "uppercase" }}>Mode</div>
      <button className="btn" onClick={() => onModeChange("debug")}
                style={{ padding: "3px 10px",
                            background: mode === "debug" ? "rgba(155,123,240,.15)" : "transparent" }}
                data-testid="xdr-studio-mode-debug">
        <Bug size={11} /> Debug
      </button>
      <button className="btn" onClick={() => onModeChange("live")}
                style={{ padding: "3px 10px",
                            background: mode === "live" ? "rgba(60,232,184,.15)" : "transparent" }}
                data-testid="xdr-studio-mode-live">
        <Zap size={11} /> Live
      </button>
      <span style={{ flex: 1 }} />
      {!running && (
        <button className="btn primary" onClick={onStart}
                  data-testid="xdr-studio-run"
                  style={{ padding: "4px 10px" }}>
          <Play size={11} /> Run
        </button>
      )}
      {running && (
        <>
          <button className="btn" onClick={onTogglePause}
                    data-testid="xdr-studio-pause"
                    style={{ padding: "4px 10px" }}>
            {paused ? <><Play size={11}/> Resume</> : <><Pause size={11}/> Pause</>}
          </button>
          <button className="btn" onClick={onStep}
                    data-testid="xdr-studio-step"
                    style={{ padding: "4px 10px" }}>
            <SkipForward size={11} /> Step
          </button>
          <button className="btn" onClick={onStop}
                    data-testid="xdr-studio-stop"
                    style={{ padding: "4px 10px" }}>
            <X size={11} /> Stop
          </button>
        </>
      )}
    </div>
  );
}


function NodeChip({ node, state, isCurrent, hasBreakpoint, forcedBranch,
                        selected, onSelect, onToggleBreakpoint, onForceBranch }) {
  const info = _describe(node);
  const stateBorder = {
    [NODE_STATE.RUNNING]:          "var(--cyan)",
    [NODE_STATE.OK]:               "var(--mint)",
    [NODE_STATE.FAIL]:             "#ff5b5b",
    [NODE_STATE.WAITING_APPROVAL]: "var(--amber)",
    [NODE_STATE.BREAKPOINT]:       "var(--amber)",
    [NODE_STATE.SKIPPED]:          "var(--border)",
  }[state] || info.border;

  const stateBg = {
    [NODE_STATE.RUNNING]:          "rgba(88,193,255,.18)",
    [NODE_STATE.OK]:               "rgba(60,232,184,.12)",
    [NODE_STATE.FAIL]:             "rgba(255,91,91,.14)",
    [NODE_STATE.WAITING_APPROVAL]: "rgba(245,166,35,.14)",
    [NODE_STATE.BREAKPOINT]:       "rgba(245,166,35,.10)",
  }[state] || info.bg;

  return (
    <div data-testid={`xdr-studio-node-${node.id}`}
            style={{ display: "flex", flexDirection: "column",
                        alignItems: "center", gap: 3, width: "100%" }}>
      <div onClick={onSelect}
              style={{ cursor: "pointer", minWidth: 300, maxWidth: 480,
                          padding: "8px 12px", borderRadius: 6,
                          border: `${isCurrent ? 2 : 1}px solid ${selected ? "var(--purple)" : stateBorder}`,
                          background: stateBg,
                          transition: "all 180ms ease",
                          boxShadow: isCurrent
                                        ? "0 0 12px rgba(155,123,240,.35)"
                                        : "none",
                          color: "var(--text)", fontSize: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <button onClick={(e) => { e.stopPropagation(); onToggleBreakpoint(); }}
                     title="Toggle breakpoint"
                     data-testid={`xdr-studio-bp-${node.id}`}
                     style={{ padding: 2, background: "transparent",
                                 border: "none", cursor: "pointer",
                                 color: hasBreakpoint ? "#ff5b5b" : "var(--faint)" }}>
            <Circle size={9} fill={hasBreakpoint ? "#ff5b5b" : "none"} />
          </button>
          <span style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 800,
                            textTransform: "uppercase", letterSpacing: ".3px",
                            color: info.accent }}>{info.kindLabel}</span>
          <span style={{ flex: 1 }} />
          <NodeStatePill state={state} />
        </div>
        <div style={{ marginTop: 4, fontWeight: 600 }}>{info.title}</div>
        {info.subtitle && (
          <div style={{ marginTop: 2, color: "var(--text-dim)", fontSize: 11 }}>
            {info.subtitle}
          </div>
        )}
        {node.kind === "condition" && (
          <div style={{ marginTop: 6, display: "flex", gap: 4, fontSize: 10 }}>
            <button className="btn ghost"
                      onClick={(e) => { e.stopPropagation(); onForceBranch(
                        forcedBranch === "yes" ? undefined : "yes"); }}
                      data-testid={`xdr-studio-force-yes-${node.id}`}
                      style={{ padding: "1px 8px",
                                  background: forcedBranch === "yes"
                                                  ? "rgba(60,232,184,.2)" : "transparent",
                                  color: "var(--mint)" }}>
              Force YES
            </button>
            <button className="btn ghost"
                      onClick={(e) => { e.stopPropagation(); onForceBranch(
                        forcedBranch === "no" ? undefined : "no"); }}
                      data-testid={`xdr-studio-force-no-${node.id}`}
                      style={{ padding: "1px 8px",
                                  background: forcedBranch === "no"
                                                  ? "rgba(255,91,91,.2)" : "transparent",
                                  color: "#ff9494" }}>
              Force NO
            </button>
          </div>
        )}
      </div>
      {node.kind !== "end" && <ChevronDown size={12} style={{ color: "var(--faint)" }} />}
    </div>
  );
}


function NodeStatePill({ state }) {
  const map = {
    [NODE_STATE.RUNNING]:          ["RUNNING",          "var(--cyan)"],
    [NODE_STATE.OK]:               ["OK",               "var(--mint)"],
    [NODE_STATE.FAIL]:             ["FAIL",             "#ff5b5b"],
    [NODE_STATE.WAITING_APPROVAL]: ["WAITING APPROVAL", "var(--amber)"],
    [NODE_STATE.BREAKPOINT]:       ["BREAK",            "var(--amber)"],
    [NODE_STATE.SKIPPED]:          ["SKIP",             "var(--faint)"],
  };
  if (!state) return null;
  const [label, color] = map[state] || [state, "var(--text-dim)"];
  return (
    <span className="mono"
             style={{ fontSize: 9.5, color, fontWeight: 800,
                         letterSpacing: ".4px" }}>
      {label}
    </span>
  );
}


function ExecutionInspector({ exec, analystEmail, onDecision }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);
  async function decide(kind) {
    setBusy(true); setErr(null);
    try {
      const fn = kind === "approve" ? Engine.approve : Engine.reject;
      const arg = kind === "approve"
        ? { approvedBy: `user:${analystEmail}`, reason: "Approved from Visual Execution Studio" }
        : { rejectedBy: `user:${analystEmail}`, reason: "Rejected from Visual Execution Studio" };
      await fn(exec.execution_id, arg);
      onDecision?.();
    } catch (e) { setErr(e?.response?.data?.detail?.error || e?.message); }
    finally { setBusy(false); }
  }

  const st = exec.state;
  return (
    <div data-testid="xdr-studio-exec-inspector"
            style={{ marginTop: 12, padding: 8, borderRadius: 4,
                        background: "var(--panel2)",
                        border: "1px solid var(--border)", fontSize: 11 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
        <b className="mono"
             style={{ fontSize: 10.5, letterSpacing: ".4px",
                         color: st === EXEC_STATE.SUCCEEDED ? "var(--mint)"
                                   : st === EXEC_STATE.WAITING_APPROVAL ? "var(--amber)"
                                   : String(st).startsWith("FAILED") || st === EXEC_STATE.REJECTED
                                     ? "#ff9494" : "var(--cyan)" }}>
          {st}
        </b>
        <span style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
          {exec.execution_id?.slice(0, 14)}…
        </span>
      </div>
      <MetaRow k="Action"       v={exec.action_id} />
      <MetaRow k="Duration"     v={exec.duration_ms != null ? `${exec.duration_ms} ms` : "—"} />
      <MetaRow k="Adapter OK"   v={exec.adapter_ok ? "yes" : "no"}
                  color={exec.adapter_ok ? "var(--mint)" : "#ff9494"} />
      <MetaRow k="Forwarding"   v={exec.forwarding_state || "—"} />
      {exec.evidence_ref && <MetaRow k="Evidence"  v={<span className="mono">{exec.evidence_ref}</span>} />}
      {exec.audit_ref    && <MetaRow k="Audit"     v={<span className="mono">{exec.audit_ref}</span>} />}
      {exec.timeline_ref && <MetaRow k="Timeline"  v={<span className="mono">{exec.timeline_ref}</span>} />}
      {exec.failure_reason && <MetaRow k="Failure" v={exec.failure_reason} color="#ff9494" />}
      {err && <MetaRow k="Error" v={err} color="#ff9494" />}
      {exec.state === EXEC_STATE.WAITING_APPROVAL && (
        <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
          <button className="btn primary" style={{ flex: 1, padding: "4px 8px" }}
                    disabled={busy} onClick={() => decide("approve")}
                    data-testid="xdr-studio-approve">
            <Check size={11} /> Approve
          </button>
          <button className="btn" style={{ flex: 1, padding: "4px 8px" }}
                    disabled={busy} onClick={() => decide("reject")}
                    data-testid="xdr-studio-reject">
            <X size={11} /> Reject
          </button>
        </div>
      )}
    </div>
  );
}


// ── helpers ──────────────────────────────────────────────────────
function _setStatus(setStatuses, id, state) {
  setStatuses((s) => ({ ...s, [id]: state }));
}
function _log(setLogs, entry) {
  setLogs((l) => [...l, entry]);
}
function _delay(ms) { return new Promise((r) => setTimeout(r, ms)); }
function _awaitStep(ref) {
  return new Promise((resolve) => { ref.current = () => { ref.current = null; resolve(); }; });
}
function _evalCondition(cfg, event) {
  const { field, op = "eq", value } = cfg;
  const v = event?.[field];
  try {
    if (op === "eq")   return String(v) === String(value);
    if (op === "neq")  return String(v) !== String(value);
    if (op === "gt")   return Number(v) >  Number(value);
    if (op === "gte")  return Number(v) >= Number(value);
    if (op === "lt")   return Number(v) <  Number(value);
    if (op === "lte")  return Number(v) <= Number(value);
    if (op === "contains") return String(v || "").toLowerCase().includes(String(value).toLowerCase());
  } catch (_) { return false; }
  return false;
}
function _extractParams(config) {
  if (!config) return {};
  const known = ["host_id", "pid", "path", "user_id", "user", "ip", "domain",
                    "hash", "message_id", "channel", "message", "system",
                    "analyst", "verdict", "query"];
  const out = {};
  for (const k of known) if (k in config) out[k] = config[k];
  return out;
}
function _allScopes(actionId) {
  const a = getAction(actionId);
  if (!a) return [];
  return (a.required_permissions || []).flatMap((p) => [
    `${p.role}:${p.scope}`, p.scope,
  ]);
}
function _describe(n) {
  if (n.kind === "start") return {
    kindLabel: "START",      accent: "var(--mint)",
    border: "var(--mint)",    bg: "rgba(60,232,184,.08)",
    title: "Trigger fired",   subtitle: "Playbook entry point",
  };
  if (n.kind === "end") return {
    kindLabel: "END",         accent: "var(--faint)",
    border: "var(--border)",  bg: "var(--panel2)",
    title: "End",             subtitle: "Terminal step",
  };
  if (n.kind === "condition") return {
    kindLabel: "CONDITION",   accent: "var(--amber)",
    border: "var(--amber)",   bg: "rgba(245,166,35,.06)",
    title: n.config?.field
      ? `${n.config.field} ${n.config.op || "=="} ${JSON.stringify(n.config.value)}`
      : "Configure condition",
    subtitle: "Splits into yes / no branches",
  };
  const a = getAction(n.action_id);
  return {
    kindLabel: "ACTION",      accent: "var(--purple)",
    border: "var(--purple)",  bg: "rgba(155,123,240,.08)",
    title: a?.label || n.action_id || "Unconfigured",
    subtitle: a
      ? `${a.provider} · ${a.destructive ? "destructive · " : ""}${a.approval_required ? "approval required" : "auto-approved"}`
      : "Pick a response action in the designer",
  };
}
function FieldLabel({ children }) {
  return (
    <div style={{ fontSize: 10, color: "var(--faint)",
                    textTransform: "uppercase", letterSpacing: ".3px",
                    fontFamily: "var(--mono)", marginBottom: 4, marginTop: 8 }}>
      {children}
    </div>
  );
}
function MetaRow({ k, v, color }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                    padding: "3px 0", borderBottom: "1px solid var(--border)",
                    fontSize: 11 }}>
      <span style={{ color: "var(--faint)" }}>{k}</span>
      <span style={{ color: color || "var(--text-dim)",
                        wordBreak: "break-all", maxWidth: "70%" }}>{v}</span>
    </div>
  );
}
