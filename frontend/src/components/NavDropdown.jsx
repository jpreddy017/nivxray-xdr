/**
 * NavDropdown — Simple click-to-toggle nav dropdown for grouping tabs.
 * Closes on outside click and on route change.
 */
import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { ChevronDown } from "lucide-react";

export default function NavDropdown({ label, icon: Icon, items, testId }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const loc = useLocation();

  // Close on route change
  useEffect(() => { setOpen(false); }, [loc.pathname]);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  const anyActive = items.some(i => loc.pathname === i.to || loc.pathname.startsWith(i.to + "/"));

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        data-testid={testId}
        onClick={() => setOpen(v => !v)}
        className="nvx-btn sm ghost"
        style={{
          color: anyActive ? "var(--accent)" : "var(--text-dim)",
          borderColor: open ? "var(--accent)" : undefined,
        }}
      >
        {Icon && <Icon size={13} />} {label}
        <ChevronDown size={11} style={{ marginLeft: 2, transform: open ? "rotate(180deg)" : "none", transition: "transform 120ms" }} />
      </button>
      {open && (
        <div
          data-testid={`${testId}-menu`}
          style={{
            position: "absolute",
            top: "calc(100% + 4px)",
            left: 0,
            minWidth: 190,
            background: "var(--surface)",
            border: "1px solid var(--border-strong)",
            boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
            padding: 4,
            zIndex: 30,
          }}
        >
          {items.map(item => {
            const active = loc.pathname === item.to || loc.pathname.startsWith(item.to + "/");
            const ItemIcon = item.icon;
            return (
              <Link
                key={item.to}
                to={item.to}
                data-testid={item.testId}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "7px 10px",
                  color: active ? "var(--accent)" : "var(--text-dim)",
                  textDecoration: "none",
                  fontFamily: "JetBrains Mono",
                  fontSize: 11,
                  letterSpacing: "0.06em",
                  borderLeft: `2px solid ${active ? "var(--accent)" : "transparent"}`,
                  transition: "background 120ms, color 120ms",
                }}
                onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-mute)"; }}
                onMouseLeave={e => { e.currentTarget.style.background = "transparent"; }}
              >
                {ItemIcon && <ItemIcon size={12} />}
                <span>{item.label}</span>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
