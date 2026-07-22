/**
 * PageHeader — NivXRay unified page-header primitive.
 *
 * The single canonical hero pattern for every page in the platform:
 *   • Eyebrow    small · uppercase · mono · muted   (e.g. "REGRESSION SUITE · X-RAY v1.5.6")
 *   • Title      corporate hero · bold sans         (e.g. "Multi-Layer Obfuscation Battery")
 *   • Subtitle   plain description                  (e.g. "Auto-crawled research articles …")
 *   • rightSlot  right-aligned actions / stat pills / status chips
 *
 * Design tokens follow the DetectFlow aesthetic already used by the
 * Dashboard hero. Font sizes intentionally consistent across pages so
 * the platform feels like ONE product, not seven glued together.
 *
 * Behavioural neutrality: no routing, no data hooks, no side effects.
 */
export default function PageHeader({
  eyebrow,
  title,
  subtitle,
  icon: Icon,
  tone = "accent",       // accent | violet | cyan | amber | neutral
  gradientTitle = true,  // enable subtle accent gradient text on the hero
  rightSlot,             // any React node — pills, buttons, tabs
  testId,
  actions,               // alias for rightSlot (legacy convenience)
  compact = false,       // reduce vertical spacing for embedded / dense pages
}) {
  const TONES = {
    accent:  { c1: "#86efac", c2: "#a7f3d0", c3: "#c4b5fd" },
    violet:  { c1: "#c4b5fd", c2: "#a5b4fc", c3: "#93c5fd" },
    cyan:    { c1: "#67e8f9", c2: "#a7f3d0", c3: "#86efac" },
    amber:   { c1: "#fcd34d", c2: "#fca5a5", c3: "#c4b5fd" },
    neutral: { c1: "#e2e8f0", c2: "#cbd5e1", c3: "#94a3b8" },
  };
  const t = TONES[tone] || TONES.accent;

  const rightNode = rightSlot ?? actions;

  return (
    <header
      data-testid={testId || "page-header"}
      style={{
        marginBottom: compact ? 14 : 22,
        display: "flex",
        alignItems: "flex-end",
        justifyContent: "space-between",
        gap: 20,
        flexWrap: "wrap",
      }}
    >
      <div style={{ minWidth: 0 }}>
        {eyebrow && (
          <div
            data-testid={testId ? `${testId}-eyebrow` : "page-header-eyebrow"}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              fontFamily: "JetBrains Mono, ui-monospace, monospace",
              fontSize: 10,
              color: "rgba(148,163,184,0.72)",
              letterSpacing: "0.20em",
              textTransform: "uppercase",
              marginBottom: 8,
              lineHeight: 1.2,
            }}
          >
            {Icon && <Icon size={12} strokeWidth={1.9} aria-hidden />}
            <span>{eyebrow}</span>
          </div>
        )}

        <h1
          data-testid={testId ? `${testId}-title` : "page-header-title"}
          style={{
            margin: 0,
            fontSize: compact ? 24 : 28,
            fontWeight: 700,
            letterSpacing: "-0.02em",
            lineHeight: 1.12,
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
