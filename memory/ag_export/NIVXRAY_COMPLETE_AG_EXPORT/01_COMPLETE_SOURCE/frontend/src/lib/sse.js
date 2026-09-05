/**
 * SSE POST client — streams `text/event-stream` responses from a POST endpoint.
 * EventSource can only issue GETs, so we hand-roll a fetch + ReadableStream reader.
 *
 * Usage:
 *   const stop = streamAnalyze(payload, {
 *     onStatus:      (s) => ...,   // {phase, message}
 *     onPartial:     (p) => ...,   // {iocs, mitre, yara, lolbas, risk}
 *     onTiHits:      (h) => ...,
 *     onOsint:       (o) => ...,
 *     onAiVerdict:   (v) => ...,
 *     onDescription: (d) => ...,
 *     onHeartbeat:   (h) => ...,   // {elapsed_s, phase}
 *     onResult:      (r) => ...,   // final full analysis object
 *     onError:       (e) => ...,   // {phase, error}
 *     onDone:        ()  => ...,
 *   });
 *   // call `stop()` to abort mid-stream.
 */
import { API_BASE } from "@/lib/api";

export function streamAnalyze(body, handlers = {}) {
  const ctrl = new AbortController();
  const token = localStorage.getItem("nvx_token") || "";

  (async () => {
    let resp;
    try {
      resp = await fetch(`${API_BASE}/analyze/stream`, {
        method: "POST",
        signal: ctrl.signal,
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
      });
    } catch (e) {
      handlers.onError?.({ phase: "connect", error: e.message });
      handlers.onDone?.();
      return;
    }

    if (!resp.ok || !resp.body) {
      handlers.onError?.({
        phase: "connect",
        error: `HTTP ${resp.status} ${resp.statusText}`,
      });
      handlers.onDone?.();
      return;
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buf = "";

    const dispatch = (event, dataStr) => {
      if (event === "keepalive") return;
      let data;
      try { data = JSON.parse(dataStr); } catch { data = dataStr; }
      const map = {
        status:      handlers.onStatus,
        partial:     handlers.onPartial,
        ti_hits:     handlers.onTiHits,
        osint:       handlers.onOsint,
        ai_verdict:  handlers.onAiVerdict,
        description: handlers.onDescription,
        heartbeat:   handlers.onHeartbeat,
        result:      handlers.onResult,
        error:       handlers.onError,
        done:        handlers.onDone,
      };
      map[event]?.(data);
    };

    // Parse SSE frames — separated by blank lines. Each frame may have `event:` + `data:` lines.
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) !== -1) {
          const frame = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          if (!frame.trim() || frame.startsWith(":")) continue; // comment / keepalive
          let event = "message";
          let data = "";
          for (const line of frame.split("\n")) {
            if (line.startsWith("event:")) event = line.slice(6).trim();
            else if (line.startsWith("data:")) data += line.slice(5).trim();
          }
          dispatch(event, data);
        }
      }
    } catch (e) {
      if (e.name !== "AbortError") handlers.onError?.({ phase: "stream", error: e.message });
    } finally {
      handlers.onDone?.();
    }
  })();

  return () => ctrl.abort();
}
