/**
 * CollapsibleSection · reusable expand/collapse wrapper
 * ─────────────────────────────────────────────────────
 * Frozen 2026-03-01 · Slice 2.1 · analyst-usability.
 *
 * Every large section / panel in the workspace can wrap its
 * contents with `<CollapsibleSection title="…">` to get a
 * consistent chevron-driven expand/collapse without each panel
 * re-implementing its own state machine.
 *
 * Props:
 *   title       — string shown in the header (or a ReactNode)
 *   subtitle    — optional smaller text under the title
 *   right       — optional element rendered right-aligned in the
 *                  header (e.g., progress %, count badge)
 *   defaultOpen — initial state (default true)
 *   testid      — data-testid for both the container and the
 *                  toggle button (`${testid}-toggle`)
 */
import React, { useState } from "react";

export default function CollapsibleSection({
  title,
  subtitle,
  right,
  defaultOpen = true,
  testid,
  children,
  style,
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section
      data-testid={testid}
      style={{
        border:       "1px solid rgba(0, 255, 128, 0.22)",
        borderRadius: 6,
        background:   "rgba(0, 22, 12, 0.55)",
        margin:       "0 12px 8px",
        fontFamily:   "ui-monospace, SFMono-Regular, Menlo, monospace",
        color:        "#c5f5d6",
        overflow:     "hidden",
        ...style,
      }}
    >
      <button
        onClick={() => setOpen(v => !v)}
        data-testid={testid ? `${testid}-toggle` : undefined}
        style={{
          background: "transparent", border: "none", padding: "10px 14px",
          cursor:     "pointer", color: "#c5f5d6", width: "100%",
          textAlign:  "left",
          display:    "flex", alignItems: "center",
          justifyContent: "space-between", gap: 12,
        }}
        aria-expanded={open}
      >
        <span style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
          <span style={{ color: "#7ee6a8", fontSize: 14,
                          width: 14, textAlign: "center",
                          transition: "transform 120ms ease" }}>
            {open ? "▾" : "▸"}
          </span>
          <span>
            <span style={{ fontSize: 11, letterSpacing: 1.6,
                            color: "#7ee6a8", opacity: 0.9 }}>
              {typeof title === "string" ? title.toUpperCase() : title}
            </span>
            {subtitle && (
              <span style={{ display: "block", fontSize: 11,
                              color: "#96c9aa", marginTop: 3,
                              fontFamily: "ui-monospace, monospace" }}>
                {subtitle}
              </span>
            )}
          </span>
        </span>
        {right && (
          <span style={{ fontSize: 11, color: "#96c9aa",
                          flexShrink: 0 }}>{right}</span>
        )}
      </button>

      {open && (
        <div style={{ padding: "0 16px 14px" }}>
          {children}
        </div>
      )}
    </section>
  );
}
