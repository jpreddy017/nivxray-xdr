/**
 * CollapsibleCard — thin, non-invasive wrapper that lets any child
 * panel be collapsed / expanded by the analyst.  The open/closed
 * state persists via localStorage so navigating away and back
 * keeps the analyst's chosen layout.
 *
 * Never mutates the wrapped child — pure additive UI.
 */
import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

export default function CollapsibleCard({
  title, storageKey, testid, children, defaultOpen = true,
}) {
  const [open, setOpen] = useState(() => {
    try {
      if (!storageKey) return defaultOpen;
      const raw = localStorage.getItem(storageKey);
      return raw == null ? defaultOpen : raw === "1";
    } catch { return defaultOpen; }
  });

  const toggle = () => {
    setOpen((cur) => {
      const next = !cur;
      try { if (storageKey) localStorage.setItem(storageKey, next ? "1" : "0"); }
      catch {}
      return next;
    });
  };

  return (
    <section data-testid={testid} style={{ margin: "0 12px 8px" }}>
      <div onClick={toggle}
           data-testid={`${testid}-toggle`}
           style={{
             display: "flex", alignItems: "center", gap: 8,
             padding: "6px 10px", cursor: "pointer",
             background: "rgba(15,23,42,0.65)",
             border: "1px solid #1f2b3f",
             borderRadius: open ? "8px 8px 0 0" : 8,
             fontSize: 10, fontWeight: 700,
             letterSpacing: "0.2em", color: "#67e8f9",
             textTransform: "uppercase",
             fontFamily: "JetBrains Mono, monospace",
             userSelect: "none",
           }}>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        {title}
      </div>
      {open && (
        <div data-testid={`${testid}-body`} style={{
          border: "1px solid #1f2b3f", borderTop: "none",
          borderRadius: "0 0 8px 8px",
          padding: "8px 0",
          background: "rgba(2,6,23,0.35)",
        }}>
          {children}
        </div>
      )}
    </section>
  );
}
