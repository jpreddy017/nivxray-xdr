import { useEffect, useRef, useState } from "react";

export function useWidth(initial = 900) {
  const ref = useRef(null);
  const [w, setW] = useState(initial);
  useEffect(() => {
    if (!ref.current || typeof ResizeObserver === "undefined") return undefined;
    const ro = new ResizeObserver(([e]) => setW(Math.max(200, Math.floor(e.contentRect.width))));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

// Horizontal drag → time pan (live, no refetch per frame) and drag-to-select ranges.
export function useDrag(onMove, onEnd) {
  const st = useRef(null);
  const down = (e) => {
    if (e.button !== 0) return;
    st.current = { x: e.clientX, last: e.clientX };
    const move = (ev) => { const s = st.current; if (s) { onMove(ev.clientX - s.last, ev.clientX - s.x, ev); s.last = ev.clientX; } };
    const up = (ev) => {
      window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up);
      const s = st.current; st.current = null;
      if (s && onEnd) onEnd(ev.clientX - s.x, s.x, ev);
    };
    window.addEventListener("mousemove", move); window.addEventListener("mouseup", up);
  };
  return down;
}
