/**
 * DT2-1 · request-race protection.
 *
 * Cancellation alone is insufficient: an already-completed response can
 * still land late. Every viewport request carries a GENERATION, and only
 * the current generation may commit state.
 *
 * Window A(101) → B(102) → C(103): if A resolves after C, A cannot
 * reposition the viewport or replace the selection.
 */

export const REQ = {
  COMMITTED: "COMMITTED",
  DISCARDED_STALE: "DISCARDED_STALE",
  DISCARDED_ABORTED: "DISCARDED_ABORTED",
  DEDUPED: "DEDUPED",
};

export const MAX_PREFETCH_IN_FLIGHT = 2;

const makeAbortDefault = () => (typeof AbortController === "function"
  ? new AbortController()
  : { signal: { aborted: false }, abort() { this.signal.aborted = true; } });

/** A cache/dedupe key must carry every security-relevant dimension.
 *  Tenant and endpoint are part of the key so a cache entry can never
 *  be served across a tenant or endpoint boundary. */
export function requestKey({ tenantId, endpointId, t0, t1, laneStart,
                             laneEnd, filterKey }) {
  return [tenantId ?? "NO_TENANT", endpointId ?? "NO_ENDPOINT",
          Math.round(t0), Math.round(t1), laneStart, laneEnd,
          filterKey ?? ""].join("|");
}

export function createCoordinator({ makeAbort = makeAbortDefault } = {}) {
  let counter = 100;
  let currentGeneration = 0;
  let currentKey = null;
  const inflight = new Map();          // key → { generation, controller }
  const prefetch = new Map();          // key → controller

  const abortSuperseded = (generation) => {
    for (const [key, entry] of [...inflight.entries()]) {
      if (entry.generation !== generation) {
        entry.controller.abort();
        inflight.delete(key);
      }
    }
  };

  return {
    /** Start (or join) the authoritative viewport request. */
    begin(key) {
      const existing = inflight.get(key);
      if (existing && key === currentKey) {
        return { generation: existing.generation,
                 signal: existing.controller.signal,
                 deduped: true };
      }
      counter += 1;
      currentGeneration = counter;
      currentKey = key;
      abortSuperseded(currentGeneration);
      const controller = makeAbort();
      inflight.set(key, { generation: currentGeneration, controller });
      return { generation: currentGeneration, signal: controller.signal,
               deduped: false };
    },

    /** Only the current generation may commit. */
    commit(generation) {
      for (const [key, entry] of inflight.entries()) {
        if (entry.generation === generation) { inflight.delete(key); break; }
      }
      return generation === currentGeneration
        ? REQ.COMMITTED : REQ.DISCARDED_STALE;
    },

    /** Prefetch is bounded, cancelable and NEVER commits the viewport. */
    beginPrefetch(key) {
      if (prefetch.has(key) || inflight.has(key)) {
        return { accepted: false, reason: REQ.DEDUPED };
      }
      if (prefetch.size >= MAX_PREFETCH_IN_FLIGHT) {
        return { accepted: false, reason: "PREFETCH_BUDGET_EXHAUSTED" };
      }
      const controller = makeAbort();
      prefetch.set(key, controller);
      return { accepted: true, signal: controller.signal,
               done: () => prefetch.delete(key) };
    },

    abortAll() {
      for (const [, e] of inflight) e.controller.abort();
      for (const [, c] of prefetch) c.abort();
      inflight.clear();
      prefetch.clear();
    },

    generation: () => currentGeneration,
    inflightCount: () => inflight.size,
    prefetchCount: () => prefetch.size,
  };
}

/** Bounded adjacent-window prefetch targets — never recursive, never
 *  the whole history. */
export function prefetchTargets(view, bounds, max = MAX_PREFETCH_IN_FLIGHT) {
  const span = Math.max(1, view.t1 - view.t0);
  const out = [];
  const prev = { t0: view.t0 - span, t1: view.t0 };
  const next = { t0: view.t1, t1: view.t1 + span };
  const min = Number.isFinite(bounds?.min) ? bounds.min : -Infinity;
  const maxT = Number.isFinite(bounds?.max) ? bounds.max : Infinity;
  if (prev.t1 > min) out.push(prev);
  if (next.t0 < maxT) out.push(next);
  return out.slice(0, max);
}
