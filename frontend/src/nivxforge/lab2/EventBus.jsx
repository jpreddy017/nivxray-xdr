/**
 * ADR-0024 · Investigation Event Bus
 *
 * Append-only timeline of investigation lifecycle events. Not UI state.
 * Not the CIO. It records WHAT HAPPENED so we can:
 *   - audit an investigation (every step timestamped)
 *   - measure lens performance (render latency per lens)
 *   - replay a case for training / debugging
 *   - stream a live case to collaborators (Phase D)
 *   - snapshot at any point (time-travel debugging)
 *
 * Canonical event shape:
 *   { id, ts, kind, source, payload }
 *
 * Kinds are stable strings (never renamed):
 *   InvestigationStarted   · AnalyzeSubmitted · CIOReceived
 *   DecodeCompleted        · EvidenceNodeCreated · StoryUpdated
 *   GraphRendered          · TechniqueMapped     · OSINTStarted
 *   OSINTProviderResult    · OSINTFinished       · ReportGenerated
 *   LensOpened             · LensClosed          · SelectionChanged
 *   NotebookPinned         · CommandInvoked      · ErrorRaised
 */
import React, { createContext, useContext, useMemo, useRef, useState, useCallback } from "react";

let seq = 0;
function newId() { return `ev_${Date.now().toString(36)}_${(++seq).toString(36)}`; }

const Ctx = createContext(null);

export function EventBusProvider({ children, maxRing = 500 }) {
  // Ring buffer keeps memory bounded. Subscribers get every event.
  const [events, setEvents] = useState([]);
  const subs = useRef(new Set());

  const emit = useCallback((kind, payload = {}, source = "lab2") => {
    const evt = { id: newId(), ts: new Date().toISOString(), kind, source, payload };
    setEvents((prev) => {
      const next = prev.length >= maxRing ? prev.slice(prev.length - maxRing + 1) : prev.slice();
      next.push(evt);
      return next;
    });
    subs.current.forEach((fn) => {
      try { fn(evt); } catch { /* swallow subscriber errors */ }
    });
    return evt;
  }, [maxRing]);

  const subscribe = useCallback((fn) => {
    subs.current.add(fn);
    return () => subs.current.delete(fn);
  }, []);

  const clear = useCallback(() => setEvents([]), []);

  const value = useMemo(() => ({ events, emit, subscribe, clear }), [events, emit, subscribe, clear]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useEventBus() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useEventBus must be used inside <EventBusProvider>");
  return ctx;
}

/** Convenience — return just the emit function for hot paths. */
export function useEmit() {
  return useEventBus().emit;
}

// Stable event-kind constants so callers never typo.
export const EVT = Object.freeze({
  INVESTIGATION_STARTED: "InvestigationStarted",
  ANALYZE_SUBMITTED:     "AnalyzeSubmitted",
  CIO_RECEIVED:          "CIOReceived",
  DECODE_COMPLETED:      "DecodeCompleted",
  EVIDENCE_NODE_CREATED: "EvidenceNodeCreated",
  STORY_UPDATED:         "StoryUpdated",
  GRAPH_RENDERED:        "GraphRendered",
  TECHNIQUE_MAPPED:      "TechniqueMapped",
  OSINT_STARTED:         "OSINTStarted",
  OSINT_PROVIDER_RESULT: "OSINTProviderResult",
  OSINT_FINISHED:        "OSINTFinished",
  REPORT_GENERATED:      "ReportGenerated",
  LENS_OPENED:           "LensOpened",
  LENS_CLOSED:           "LensClosed",
  SELECTION_CHANGED:     "SelectionChanged",
  NOTEBOOK_PINNED:       "NotebookPinned",
  COMMAND_INVOKED:       "CommandInvoked",
  ERROR_RAISED:          "ErrorRaised",
});
