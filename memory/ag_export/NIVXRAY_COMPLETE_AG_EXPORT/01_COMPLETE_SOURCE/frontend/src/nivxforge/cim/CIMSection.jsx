/**
 * ADR-0009 · CIMSection primitive.
 *
 * Every top-level section of an Investigation renders through this shell.
 * It enforces the read-only contract: children receive their CIM slice
 * as a prop and MAY NOT re-derive top-level fields (verdict math, MITRE
 * dedup, IOC counts). Composition happens once, in the backend composer.
 */
import React from "react";

const S = {
  section: {
    marginTop: 22,
    background: "var(--panel, #0f172a)",
    border: "1px solid var(--border, #1e293b)",
    borderRadius: 10,
    padding: 18,
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 12,
    borderBottom: "1px solid var(--border, #1e293b)",
    paddingBottom: 10,
  },
  title: {
    fontSize: 11,
    letterSpacing: "0.24em",
    color: "var(--accent, #7dd3fc)",
    textTransform: "uppercase",
    fontWeight: 700,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
  },
  count: {
    fontSize: 11,
    color: "var(--text-secondary, #94a3b8)",
    fontFamily: "ui-monospace",
  },
  empty: {
    padding: 12,
    color: "var(--text-secondary, #94a3b8)",
    fontSize: 12,
    fontFamily: "ui-monospace",
    fontStyle: "italic",
  },
};

export function CIMSection({
  kind,
  title,
  count = null,
  isEmpty = false,
  emptyText = "No data in this section.",
  children,
}) {
  return (
    <section style={S.section} data-testid={`cim-section-${kind}`}>
      <header style={S.header}>
        <span style={S.title} data-testid={`cim-section-${kind}-title`}>
          {title}
        </span>
        {count != null && (
          <span style={S.count} data-testid={`cim-section-${kind}-count`}>
            {count}
          </span>
        )}
      </header>
      {isEmpty ? (
        <div style={S.empty} data-testid={`cim-section-${kind}-empty`}>
          {emptyText}
        </div>
      ) : (
        children
      )}
    </section>
  );
}

export default CIMSection;
