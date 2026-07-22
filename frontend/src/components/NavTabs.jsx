/**
 * NavTabs — NivXRay unified nav/tab primitive · DetectFlow design system.
 *
 * ONE reusable component powering:
 *   • The top Header primary nav (WORKSPACE · DASHBOARD · …)
 *   • Page-level tab strips (Training Inbox pending/promoted/dismissed/all,
 *     OutputView TEXT/HEX/B64/DIFF, Benchmark filters, etc.)
 *
 * Design language: glass-morphism container, uppercase JetBrains Mono
 * labels, subtle hover translate, glowing accent underline on the active
 * tab. Zero behaviour / routing / permission / testid changes.
 *
 * Two modes:
 *   • variant="nav"  — router links; active state derived from
 *     `location.pathname` unless explicitly overridden per item.
 *   • variant="strip" — state tabs; parent owns `activeKey` and passes
 *     an `onSelect(key)` callback.
 *
 * Item shape:
 *   { key, label, icon?, testId?, href?, count?, disabled?, title? }
 *
 * All items MUST carry a stable `testId` when replacing existing tab
 * strips, so downstream tests keep working unchanged.
 */
import { Link, useLocation } from "react-router-dom";
import { useMemo } from "react";

// -- Design tokens ---------------------------------------------------
const TONES = {
  accent: {
    fg: "#86efac",
    ring: "rgba(34,197,94,0.55)",
    fillA: "rgba(34,197,94,0.16)",
    fillB: "rgba(34,197,94,0.03)",
    glow: "rgba(34,197,94,0.30)",
  },
  violet: {
    fg: "#c4b5fd",
    ring: "rgba(139,92,246,0.55)",
    fillA: "rgba(139,92,246,0.16)",
    fillB: "rgba(139,92,246,0.03)",
    glow: "rgba(139,92,246,0.30)",
  },
  cyan: {
    fg: "#67e8f9",
    ring: "rgba(6,182,212,0.55)",
    fillA: "rgba(6,182,212,0.16)",
    fillB: "rgba(6,182,212,0.03)",
    glow: "rgba(6,182,212,0.30)",
  },
  amber: {
    fg: "#fcd34d",
    ring: "rgba(245,158,11,0.55)",
    fillA: "rgba(245,158,11,0.16)",
    fillB: "rgba(245,158,11,0.03)",
    glow: "rgba(245,158,11,0.30)",
  },
};

const SIZES = {
  sm: {
    padY: 6, padX: 10, fontSize: 10, iconSize: 12, gap: 6, radius: 6,
    letterSpacing: "0.14em",
  },
  md: {
    padY: 8, padX: 14, fontSize: 11, iconSize: 13, gap: 7, radius: 8,
    letterSpacing: "0.14em",
  },
};

// -- Single tab item -------------------------------------------------
function Tab({ item, active, size, tone, onSelect }) {
  const s = SIZES[size] || SIZES.sm;
  const t = TONES[tone] || TONES.accent;
  const disabled = !!item.disabled;

  const base = {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: s.gap,
    padding: `${s.padY}px ${s.padX}px`,
    borderRadius: s.radius,
    fontFamily: "JetBrains Mono, ui-monospace, monospace",
    fontSize: s.fontSize,
    letterSpacing: s.letterSpacing,
    textTransform: "uppercase",
    fontWeight: 600,
    lineHeight: 1,
    textDecoration: "none",
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.45 : 1,
    color: active ? t.fg : "rgba(203,213,225,0.72)",
    background: active
      ? `linear-gradient(160deg, ${t.fillA}, ${t.fillB})`
      : "transparent",
    border: `1px solid ${active ? t.ring : "transparent"}`,
    boxShadow: active
      ? `0 0 12px ${t.glow}, inset 0 0 0 1px rgba(255,255,255,0.02)`
      : "none",
    transition:
      "color 160ms ease, background 200ms ease, border-color 200ms ease, "
      + "transform 160ms ease, box-shadow 200ms ease",
    whiteSpace: "nowrap",
    position: "relative",
  };

  const Icon = item.icon;
  const inner = (
    <>
      {Icon && <Icon size={s.iconSize} strokeWidth={1.8} aria-hidden />}
      <span>{item.label}</span>
      {item.count != null && (
        <span
          aria-label={`${item.count} items`}
          style={{
            marginLeft: 2,
            padding: "1px 5px",
            borderRadius: 3,
            fontSize: 9,
            letterSpacing: "0.05em",
            background: active ? "rgba(2,6,23,0.55)" : "rgba(148,163,184,0.14)",
            color: active ? t.fg : "rgba(203,213,225,0.75)",
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
            fontWeight: 700,
            border: `1px solid ${active ? t.ring : "transparent"}`,
          }}
        >
          {item.count}
        </span>
      )}
      {/* Active-tab bottom accent line — a tiny DetectFlow-style glow bar. */}
      {active && (
        <span
          aria-hidden
          style={{
            position: "absolute",
            left: "20%", right: "20%", bottom: -1,
            height: 2,
            background: t.fg,
            boxShadow: `0 0 8px ${t.fg}`,
            borderRadius: 2,
          }}
        />
      )}
    </>
  );

  const onHover = (e, entering) => {
    if (active || disabled) return;
    e.currentTarget.style.color = "#e2e8f0";
    e.currentTarget.style.background = entering
      ? "rgba(148,163,184,0.06)" : "transparent";
    e.currentTarget.style.transform = entering
      ? "translateY(-1px)" : "translateY(0)";
    e.currentTarget.style.borderColor = entering
      ? "rgba(148,163,184,0.14)" : "transparent";
  };

  const commonProps = {
    "data-testid": item.testId,
    "data-active": active || undefined,
    "aria-current": active ? "page" : undefined,
    "aria-disabled": disabled || undefined,
    title: item.title,
    onMouseEnter: (e) => onHover(e, true),
    onMouseLeave: (e) => onHover(e, false),
    style: base,
  };

  if (item.href && !disabled) {
    return <Link to={item.href} {...commonProps}>{inner}</Link>;
  }
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={disabled ? undefined : () => onSelect?.(item.key)}
      {...commonProps}
    >
      {inner}
    </button>
  );
}

// -- Container --------------------------------------------------------
/**
 * NavTabs
 *
 * Props:
 *   items       Array of { key, label, icon?, testId?, href?, count?, disabled?, title? }
 *   activeKey   For variant="strip". Ignored in "nav" (uses pathname).
 *   onSelect    (key) => void   For "strip" mode.
 *   variant     "nav" | "strip"  default "strip"
 *   size        "sm" | "md"      default "sm"
 *   tone        "accent" | "violet" | "cyan" | "amber"   default "accent"
 *   framed      boolean  wrap in glass container. default true.
 *   className   optional wrapper class (kept for existing style hooks)
 *   style       optional wrapper style overrides
 *   testId      wrapper data-testid
 *   ariaLabel   aria-label for the nav element
 */
export default function NavTabs({
  items = [],
  activeKey,
  onSelect,
  variant = "strip",
  size = "sm",
  tone = "accent",
  framed = true,
  className,
  style,
  testId,
  ariaLabel = "navigation tabs",
}) {
  const loc = useLocation();

  const wrapperStyle = useMemo(() => ({
    display: "inline-flex",
    alignItems: "center",
    gap: 4,
    padding: framed ? 4 : 0,
    borderRadius: framed ? 10 : 0,
    background: framed
      ? "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.62))"
      : "transparent",
    border: framed ? "1px solid rgba(148,163,184,0.14)" : "none",
    backdropFilter: framed ? "blur(14px) saturate(150%)" : undefined,
    WebkitBackdropFilter: framed ? "blur(14px) saturate(150%)" : undefined,
    boxShadow: framed
      ? "inset 0 1px 0 rgba(255,255,255,0.03), 0 4px 18px rgba(2,6,23,0.35)"
      : undefined,
    flexWrap: "wrap",
    ...style,
  }), [framed, style]);

  const isActive = (item) => {
    if (variant === "nav") {
      // Router mode — exact match on pathname (root '/' is exact-only).
      if (!item.href) return false;
      if (item.href === "/") return loc.pathname === "/";
      return loc.pathname === item.href
        || loc.pathname.startsWith(item.href + "/");
    }
    return item.key === activeKey;
  };

  return (
    <nav
      role="tablist"
      aria-label={ariaLabel}
      data-testid={testId}
      className={className}
      style={wrapperStyle}
    >
      {items.map((it) => (
        <Tab
          key={it.key || it.href || it.label}
          item={it}
          active={isActive(it)}
          size={size}
          tone={tone}
          onSelect={onSelect}
        />
      ))}
    </nav>
  );
}
