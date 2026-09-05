/**
 * PageHeader — NivXRay unified page hero.
 *
 * Typography matches the NIVXRAY wordmark: Chivo 900, uppercase,
 * letter-spaced. Optional contextual icon sits inside a small glass
 * "badge" tile to the left of the title (same visual weight as the
 * header logo). Right-slot is for actions / stat pills.
 *
 * Behavioural neutrality: no routing, no data hooks, no side effects.
 */
export default function PageHeader({
  eyebrow,
  title,
  subtitle,
  icon: Icon,
  tone = "accent",       // accent | violet | cyan | amber | red | neutral
  gradientTitle = true,
  rightSlot,             // React node — pills, buttons, tabs
  testId,
  actions,               // legacy alias for rightSlot
  compact = false,
}) {
  const TONES = {
    accent:  { c1: "#86efac", c2: "#a7f3d0", c3: "#c4b5fd", solid: "#4aa890" },
    violet:  { c1: "#c4b5fd", c2: "#a5b4fc", c3: "#93c5fd", solid: "#8b5cf6" },
    cyan:    { c1: "#67e8f9", c2: "#a7f3d0", c3: "#86efac", solid: "#22d3ee" },
    amber:   { c1: "#fcd34d", c2: "#fca5a5", c3: "#c4b5fd", solid: "#f59e0b" },
    red:     { c1: "#fca5a5", c2: "#fcd34d", c3: "#c4b5fd", solid: "#ef4444" },
    neutral: { c1: "#e2e8f0", c2: "#cbd5e1", c3: "#94a3b8", solid: "#94a3b8" },
  };
  const t = TONES[tone] || TONES.accent;
  const rightNode = rightSlot ?? actions;

  return (
    <header
      data-testid={testId || "page-header"}
      style={{
        marginBottom: compact ? 14 : 22,
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "space-between",
        gap: 20,
        flexWrap: "wrap",
        paddingBottom: 18,
        borderBottom: "1px solid rgba(148,163,184,0.10)",
      }}
    >
      <div style={{ display: "flex", gap: 14, alignItems: "flex-start", minWidth: 0 }}>
        {Icon && (
          <div
            data-testid={testId ? `${testId}-icon` : "page-header-icon"}
            aria-hidden
            style={{
              flexShrink: 0,
              width: compact ? 38 : 44,
              height: compact ? 38 : 44,
              borderRadius: 8,
              display: "grid",
              placeItems: "center",
              background: `linear-gradient(160deg, ${t.solid}22, ${t.solid}08)`,
              border: `1px solid ${t.solid}55`,
              boxShadow: `0 0 12px ${t.solid}22, inset 0 1px 0 rgba(255,255,255,0.04)`,
              color: t.c1,
              marginTop: 6,
            }}
          >
            <Icon size={compact ? 18 : 20} strokeWidth={1.8} />
          </div>
        )}

        <div style={{ minWidth: 0 }}>
          {eyebrow && (
            <div
              data-testid={testId ? `${testId}-eyebrow` : "page-header-eyebrow"}
              style={{
                fontFamily: "JetBrains Mono, ui-monospace, monospace",
                fontSize: 10,
                color: "rgba(148,163,184,0.72)",
                letterSpacing: "0.20em",
                textTransform: "uppercase",
                marginBottom: 6,
                lineHeight: 1.2,
              }}
            >
              {eyebrow}
            </div>
          )}

          <h1
            data-testid={testId ? `${testId}-title` : "page-header-title"}
            style={{
              margin: 0,
              fontFamily: '"Chivo", ui-sans-serif, system-ui, sans-serif',
              fontSize: compact ? 22 : 26,
              fontWeight: 900,
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              lineHeight: 1.08,
              color: "#e2e8f0",
              ...(gradientTitle && {
                background: `linear-gradient(90deg, ${t.c1}, ${t.c2}, ${t.c3})`,
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }),
            }}
          >
            {title}
          </h1>

          {subtitle && (
            <p
              data-testid={testId ? `${testId}-subtitle` : "page-header-subtitle"}
              style={{
                margin: "8px 0 0",
                fontSize: 12,
                lineHeight: 1.55,
                color: "rgba(148,163,184,0.82)",
                fontFamily: "JetBrains Mono, ui-monospace, monospace",
                letterSpacing: "0.02em",
                maxWidth: 820,
              }}
            >
              {subtitle}
            </p>
          )}
        </div>
      </div>

      {rightNode && (
        <div
          data-testid={testId ? `${testId}-actions` : "page-header-actions"}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            flexWrap: "wrap",
            flexShrink: 0,
          }}
        >
          {rightNode}
        </div>
      )}
    </header>
  );
}
