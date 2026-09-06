/**
 * EndpointActionsMenu · the compact contextual action dropdown.
 *
 * Grouped Device actions / Investigate / Response / Pivots.
 *
 * STATE-AWARE, and honest about it. Every item declares a capability
 * state and the menu renders it accordingly:
 *
 *   available    -> enabled, runs
 *   unavailable  -> disabled, prefixed ⊘, tooltip names the missing driver
 *   no_evidence  -> disabled, prefixed ◇, tooltip names the missing data
 *
 * There is no third state where a control looks live and does nothing.
 * Nothing here simulates execution, and no destructive action is offered
 * while its authorization → approval → response-safety → execution →
 * verification chain has no driver behind it.
 */
import React, { useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronUp, ExternalLink } from "lucide-react";

const EP = {
  unavailable: { ep: "capability_unavailable", glyph: "⊘" },
  no_evidence: { ep: "no_evidence", glyph: "◇" },
};

function Item({ item, onClose }) {
  if (item.state === "available") {
    return (
      <button className="btn ghost"
              onClick={() => { onClose(); item.run(); }}
              style={{ width: "100%", justifyContent: "flex-start",
                       padding: "5px 10px", fontSize: 10.5, borderRadius: 0 }}
              data-testid={`endpoint-action-${item.id}`}>
        {item.label}
        {item.external ? (
          <ExternalLink size={9} style={{ marginLeft: 5, opacity: 0.6 }} />
        ) : null}
      </button>
    );
  }
  const decor = EP[item.state] || EP.unavailable;
  return (
    <button className="btn ghost" disabled aria-disabled="true"
            title={item.reason}
            style={{ width: "100%", justifyContent: "flex-start",
                     padding: "5px 10px", fontSize: 10.5, borderRadius: 0,
                     opacity: 0.5, cursor: "not-allowed" }}
            data-testid={`endpoint-action-${item.id}`}
            data-state={item.state}>
      <span className="nx-ep" data-ep={decor.ep} data-known="true"
            style={{ marginRight: 6, fontSize: 8.5 }}>
        {decor.glyph}
      </span>
      {item.label}
    </button>
  );
}

export const EndpointActionsMenu = ({ groups }) => {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const away = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const esc = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
    };
  }, [open]);

  const unavailable = groups
    .flatMap((g) => g.items)
    .filter((i) => i.state !== "available").length;

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button className="btn" onClick={() => setOpen((o) => !o)}
              aria-haspopup="menu" aria-expanded={open}
              style={{ padding: "4px 9px", fontSize: 10.5 }}
              data-testid="endpoint-actions-trigger">
        Actions {open ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
      </button>

      {open ? (
        <div className="panel" role="menu"
             style={{ position: "absolute", top: "calc(100% + 4px)", left: 0,
                      zIndex: 60, minWidth: 232, padding: "5px 0 8px",
                      boxShadow: "0 14px 34px rgba(0,0,0,.55)",
                      maxHeight: "78vh", overflowY: "auto" }}
             data-testid="endpoint-actions-menu">
          {groups.map((g, gi) => (
            <div key={g.label}
                 style={{ borderTop: gi ? "1px solid #212B36" : "none",
                          paddingTop: gi ? 5 : 0, marginTop: gi ? 5 : 0 }}>
              <div style={{ color: "var(--faint)", fontSize: 8.5, fontWeight: 800,
                            textTransform: "uppercase", letterSpacing: ".5px",
                            padding: "3px 10px 4px" }}>
                {g.label}
              </div>
              {g.items.map((item) => (
                <Item key={item.id} item={item} onClose={() => setOpen(false)} />
              ))}
            </div>
          ))}
          {unavailable ? (
            <div style={{ borderTop: "1px solid #212B36", marginTop: 5,
                          padding: "7px 10px 4px", fontSize: 9,
                          color: "var(--faint)", lineHeight: 1.65,
                          position: "sticky", bottom: -8,
                          background: "var(--panel, #0E141A)" }}
                 data-testid="endpoint-actions-unavailable-note">
              {unavailable} disabled — capability not registered on this
              platform. Shown, never simulated.
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
};

export default EndpointActionsMenu;
