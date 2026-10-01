/**
 * AdminHero — Shared visual primitive for all Admin Control Plane pages.
 *
 * Renders the standard header + KPI strip so every admin surface
 * converges on the Detection Registry visual grammar.
 *
 * Contract:
 *   • Never fabricates values. Passes `undefined` / 0 through honestly.
 *   • `stats` is a list of {label, value, color?, testid?}. Empty list
 *     collapses the KPI strip entirely — no ghost cards.
 *   • `actions` is a slot for right-side buttons.
 *   • `source` is the authoritative API path this surface consumes,
 *     rendered as a small monospace provenance line so operators can
 *     always see where the data comes from.
 */
import React from "react";


export default function AdminHero({
  icon: Icon,
  eyebrow,
  title,
  subtitle,
  source,
  stats,
  actions,
  testid,
}) {
  const list = Array.isArray(stats) ? stats : [];
  return (
    <div data-testid={testid || "admin-hero"}
              style={{ marginBottom: 14 }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12,
                          marginBottom: 10 }}>
        {Icon && (
          <div style={{
            width: 36, height: 36, borderRadius: 6,
            display: "flex", alignItems: "center", justifyContent: "center",
            background: "var(--panel2)",
            border: "1px solid var(--border)",
            flexShrink: 0,
          }}>
            <Icon size={16} style={{ color: "var(--nx-purple, var(--cyan))" }} />
          </div>
        )}
        <div style={{ flex: 1, minWidth: 0 }}>
          {eyebrow && (
            <div style={{
              fontFamily: "var(--mono)", fontSize: 10,
              letterSpacing: ".5px", fontWeight: 800,
              color: "var(--nx-purple, var(--cyan))",
              textTransform: "uppercase", marginBottom: 3,
            }}
                data-testid={`${testid || "admin-hero"}-eyebrow`}>
              {eyebrow}
            </div>
          )}
          <div style={{
            fontFamily: "var(--sans)", fontSize: 18, fontWeight: 800,
            color: "var(--text)", letterSpacing: "-.2px", lineHeight: 1.2,
          }}
              data-testid={`${testid || "admin-hero"}-title`}>
            {title}
          </div>
          {subtitle && (
            <div style={{
              fontFamily: "var(--sans)", fontSize: 12.5,
              color: "var(--text-dim)", marginTop: 4, lineHeight: 1.5,
              maxWidth: 780,
            }}>
              {subtitle}
            </div>
          )}
          {source && (
            <div style={{
              fontFamily: "var(--mono)", fontSize: 10,
              color: "var(--faint)", marginTop: 5, letterSpacing: ".2px",
            }}
                data-testid={`${testid || "admin-hero"}-source`}>
              source · <span style={{ color: "var(--cyan)" }}>{source}</span>
            </div>
          )}
        </div>
        {actions && (
          <div style={{ display: "flex", gap: 6, flexShrink: 0,
                              alignItems: "center" }}>
            {actions}
          </div>
        )}
      </div>

      {list.length > 0 && (
        <div data-testid={`${testid || "admin-hero"}-stats`}
                  style={{
          display: "grid",
          gridTemplateColumns: `repeat(${Math.min(list.length, 6)}, 1fr)`,
          gap: 8,
        }}>
          {list.map((s, i) => (
            <div key={s.label + i}
                      data-testid={s.testid}
                      style={{
              padding: "10px 12px",
              border: "1px solid var(--border)", borderRadius: 4,
              background: "var(--panel2)",
            }}>
              <div style={{
                fontFamily: "var(--mono)", fontSize: 9.5,
                letterSpacing: ".4px", color: "var(--faint)",
                textTransform: "uppercase", marginBottom: 4,
                fontWeight: 700,
              }}>
                {s.label}
              </div>
              <div style={{
                fontFamily: "var(--mono)", fontSize: 20, fontWeight: 800,
                color: s.value === 0 || s.value === "0"
                    ? "var(--faint)"
                    : (s.color || "var(--text)"),
                lineHeight: 1,
              }}>
                {s.value ?? "—"}
              </div>
              {s.hint && (
                <div style={{
                  fontFamily: "var(--mono)", fontSize: 9.5,
                  color: "var(--faint)", marginTop: 3, letterSpacing: ".2px",
                }}>
                  {s.hint}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
