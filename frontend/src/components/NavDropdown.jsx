/**
 * NavDropdown — DetectFlow-styled trigger + glass dropdown menu.
 *
 * Groups related tabs behind a single primary-nav trigger. Matches the
 * shared NavTabs design language: glass container, JetBrains Mono
 * uppercase labels, accent underline on active-child state, subtle
 * hover motion. Closes on outside click and on route change.
 *
 * No behaviour / permission / routing / testid changes vs the previous
 * implementation — this is a visual refresh only.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { ChevronDown } from "lucide-react";

export default function NavDropdown({ label, icon: Icon, items, testId }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const loc = useLocation();

  // Close on route change
  useEffect(() => { setOpen(false); }, [loc.pathname]);

  // Close on outside click / Escape
  useEffect(() => {
    if (!open) return;
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const anyActive = useMemo(
    () => items.some(i => loc.pathname === i.to || loc.pathname.startsWith(i.to + "/")),
    [items, loc.pathname],
  );

  const ACCENT_FG   = "#86efac";
  const ACCENT_RING = "rgba(34,197,94,0.55)";
  const ACCENT_A    = "rgba(34,197,94,0.16)";
  const ACCENT_B    = "rgba(34,197,94,0.03)";
  const ACCENT_GLOW = "rgba(34,197,94,0.30)";

  const active = anyActive || open;
  const triggerStyle = {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    padding: "6px 10px",
    borderRadius: 6,
    fontFamily: "JetBrains Mono, ui-monospace, monospace",
    fontSize: 10,
    letterSpacing: "0.14em",
    textTransform: "uppercase",
    fontWeight: 600,
    lineHeight: 1,
    cursor: "pointer",
    color: active ? ACCENT_FG : "rgba(203,213,225,0.72)",
    background: active
      ? `linear-gradient(160deg, ${ACCENT_A}, ${ACCENT_B})`
      : "transparent",
    border: `1px solid ${active ? ACCENT_RING : "transparent"}`,
    boxShadow: active
      ? `0 0 12px ${ACCENT_GLOW}, inset 0 0 0 1px rgba(255,255,255,0.02)`
      : "none",
    transition:
      "color 160ms ease, background 200ms ease, border-color 200ms ease, "
      + "transform 160ms ease, box-shadow 200ms ease",
    whiteSpace: "nowrap",
    position: "relative",
  };

  const onHover = (e, entering) => {
    if (active) return;
    e.currentTarget.style.color = "#e2e8f0";
    e.currentTarget.style.background = entering
      ? "rgba(148,163,184,0.06)" : "transparent";
    e.currentTarget.style.transform = entering ? "translateY(-1px)" : "translateY(0)";
    e.currentTarget.style.borderColor = entering
      ? "rgba(148,163,184,0.14)" : "transparent";
  };

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        type="button"
        data-testid={testId}
        onClick={() => setOpen(v => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        onMouseEnter={(e) => onHover(e, true)}
        onMouseLeave={(e) => onHover(e, false)}
        style={triggerStyle}
      >
        {Icon && <Icon size={12} strokeWidth={1.8} />}
        <span>{label}</span>
        <ChevronDown size={11}
          style={{
            marginLeft: 2,
            transform: open ? "rotate(180deg)" : "none",
            transition: "transform 180ms ease",
            opacity: 0.85,
          }} />
        {active && (
          <span aria-hidden style={{
            position: "absolute",
            left: "20%", right: "20%", bottom: -1,
            height: 2, background: ACCENT_FG,
            boxShadow: `0 0 8px ${ACCENT_FG}`,
            borderRadius: 2,
          }} />
        )}
      </button>

      {open && (
        <div
          role="menu"
          data-testid={`${testId}-menu`}
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            left: 0,
            minWidth: 210,
            background: "linear-gradient(160deg, rgba(15,23,42,0.94), rgba(2,6,23,0.94))",
            border: "1px solid rgba(148,163,184,0.18)",
            borderRadius: 10,
            padding: 5,
            backdropFilter: "blur(18px) saturate(160%)",
            WebkitBackdropFilter: "blur(18px) saturate(160%)",
            boxShadow: "0 12px 32px rgba(2,6,23,0.55), inset 0 1px 0 rgba(255,255,255,0.04)",
            zIndex: 30,
          }}
        >
          {items.map(item => {
            const isChildActive =
              loc.pathname === item.to || loc.pathname.startsWith(item.to + "/");
            const ItemIcon = item.icon;
            const itemStyle = {
              display: "flex",
              alignItems: "center",
              gap: 9,
              padding: "8px 10px",
              borderRadius: 6,
              color: isChildActive ? ACCENT_FG : "rgba(203,213,225,0.85)",
              textDecoration: "none",
              fontFamily: "JetBrains Mono, ui-monospace, monospace",
              fontSize: 11,
              letterSpacing: "0.08em",
              background: isChildActive
                ? `linear-gradient(160deg, ${ACCENT_A}, ${ACCENT_B})`
                : "transparent",
              border: `1px solid ${isChildActive ? ACCENT_RING : "transparent"}`,
              transition:
                "background 180ms ease, color 160ms ease, transform 160ms ease, border-color 180ms ease",
              position: "relative",
            };
            return (
              <Link
                key={item.to}
                to={item.to}
                data-testid={item.testId}
                role="menuitem"
                style={itemStyle}
                onMouseEnter={(e) => {
                  if (isChildActive) return;
                  e.currentTarget.style.background = "rgba(148,163,184,0.08)";
                  e.currentTarget.style.color = "#e2e8f0";
                  e.currentTarget.style.borderColor = "rgba(148,163,184,0.18)";
                  e.currentTarget.style.transform = "translateX(2px)";
                }}
                onMouseLeave={(e) => {
                  if (isChildActive) return;
                  e.currentTarget.style.background = "transparent";
                  e.currentTarget.style.color = "rgba(203,213,225,0.85)";
                  e.currentTarget.style.borderColor = "transparent";
                  e.currentTarget.style.transform = "translateX(0)";
                }}
              >
                {ItemIcon && <ItemIcon size={12} strokeWidth={1.8} />}
                <span>{item.label}</span>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
