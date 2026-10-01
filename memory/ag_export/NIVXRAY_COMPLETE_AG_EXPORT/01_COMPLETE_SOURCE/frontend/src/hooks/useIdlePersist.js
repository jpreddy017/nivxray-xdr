/**
 * useIdlePersist — permanent anti-hang persistence hook.
 *
 * Serialises the given state to localStorage using ``requestIdleCallback``
 * so JSON.stringify NEVER runs on the critical render path.  Also:
 *
 *   · Skips work when the tab is hidden (`document.hidden`).
 *   · Debounces writes so rapid state changes collapse to one write.
 *   · Hard-caps the raw payload size (drops bulk sub-fields first,
 *     then aborts entirely if still too large — never blocks the tab).
 *   · Cleans up on unmount so a navigating-away tab never leaves a
 *     stringify-in-flight.
 *
 * Usage:
 *     useIdlePersist("nvx.workspace.persist", { input, output, understanding });
 */
import { useEffect, useRef } from "react";

// Hard caps.  Values chosen so a real-world 50 KB paste + 200 KB decode
// still persists cleanly; a 5 MB deep bundle is deterministically
// truncated instead of stalling the browser.
const SOFT_CAP_BYTES  = 200_000;    // trigger heavy-field drop above this
const HARD_CAP_BYTES  = 900_000;    // abort persist above this
const DEBOUNCE_MS     = 800;

// ``requestIdleCallback`` shim for Safari (no native rIC as of 2026-02).
const rIC = (typeof window !== "undefined" && window.requestIdleCallback)
  ? window.requestIdleCallback.bind(window)
  : ((cb) => setTimeout(() => cb({ timeRemaining: () => 50, didTimeout: false }), 1));
const cIC = (typeof window !== "undefined" && window.cancelIdleCallback)
  ? window.cancelIdleCallback.bind(window)
  : ((id) => clearTimeout(id));


/**
 * @param {string} key           localStorage key
 * @param {object} snapshot      the object to persist (any JSON-serialisable)
 * @param {object} [opts]
 * @param {string[]} [opts.bulkFields]  fields that should be dropped
 *                                        first when the payload exceeds
 *                                        ``SOFT_CAP_BYTES``.
 */
export function useIdlePersist(key, snapshot, opts = {}) {
  const debounceRef = useRef(null);
  const idleRef     = useRef(null);
  const bulkFields  = opts.bulkFields || [];

  useEffect(() => {
    // Bail out cheaply when tab is hidden — no writes while backgrounded.
    if (typeof document !== "undefined" && document.hidden) return;

    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (idleRef.current)     cIC(idleRef.current);

    debounceRef.current = setTimeout(() => {
      idleRef.current = rIC(() => {
        try {
          // ── Cheap size estimate — string length + best-effort
          //    approximation for objects. Without object accounting
          //    the guard never fires and JSON.stringify below can
          //    block the main thread for 10-300 s on a hydrated
          //    investigationObject / analystNarrative (owner-verified
          //    2026-08-10 SEP.csv upload freeze).
          let bulkLen = 0;
          for (const k of Object.keys(snapshot || {})) {
            const v = snapshot[k];
            if (v == null) continue;
            if (typeof v === "string") { bulkLen += v.length; continue; }
            if (typeof v === "object") {
              // Very cheap sizeof: count keys × 32 bytes + recurse one
              // level. Full stringify would defeat the whole guard.
              try {
                let est = 0;
                for (const key of Object.keys(v)) {
                  est += 32;
                  const inner = v[key];
                  if (typeof inner === "string") est += inner.length;
                  else if (Array.isArray(inner)) est += inner.length * 64;
                  else if (inner && typeof inner === "object")
                    est += Object.keys(inner).length * 64;
                }
                bulkLen += est;
              } catch { /* noop */ }
            }
          }
          // Drop the bulk fields when the raw payload is already huge.
          const effective = { ...snapshot };
          if (bulkLen > SOFT_CAP_BYTES) {
            for (const f of bulkFields) effective[f] = null;
            effective._dropped_for_size = true;
          }
          const s = JSON.stringify(effective);
          if (s.length > HARD_CAP_BYTES) {
            // Even after dropping bulk fields it's too big — abort persist
            // entirely (better than blocking the tab or filling localStorage).
            return;
          }
          localStorage.setItem(key, s);
        } catch { /* quota exceeded / cyclic / unavailable → silent */ }
      }, { timeout: 2000 });
    }, DEBOUNCE_MS);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
      if (idleRef.current)     cIC(idleRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, JSON.stringify(Object.keys(snapshot || {})),   // stable shape key
        ...Object.values(snapshot || {})]);
}


/**
 * usePageVisibilityPause — invoke the supplied ``onHidden`` callback
 * whenever the tab is backgrounded, and ``onVisible`` when the user
 * returns.  Callers use it to abort inflight LLM requests, pause
 * timers, and stop rendering intermediate state that would otherwise
 * pile up and crash the tab.
 */
export function usePageVisibilityPause(onHidden, onVisible) {
  useEffect(() => {
    const handler = () => {
      if (document.hidden) {
        try { onHidden && onHidden(); } catch {}
      } else {
        try { onVisible && onVisible(); } catch {}
      }
    };
    document.addEventListener("visibilitychange", handler);
    return () => document.removeEventListener("visibilitychange", handler);
  }, [onHidden, onVisible]);
}


export default useIdlePersist;
