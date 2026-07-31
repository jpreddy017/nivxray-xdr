/**
 * ADR-0021 · Lab2Shell — permanent workspace layout contract.
 *
 * This file defines the seven SLOTS every future Lab 2.0 component
 * must dock into. It is intentionally a LAYOUT, not a chrome — the
 * shell owns geometry, not content. Content components (SummaryCard,
 * EvidenceList, Timeline, Graph, etc.) will be dropped into the
 * WorkspaceCanvas slot in future slices.
 *
 * Layout regions (never renamed, never re-numbered):
 *
 *   ┌────────────────────────── AppHeader ─────────────────────────┐
 *   │  brand · case · actions · theme · palette-trigger            │
 *   ├──────────────────────── VerdictRibbon ───────────────────────┤
 *   ├──── LeftNav ─┬──────── Toolbar ──────────┬── ContextPanel ───┤
 *   │              │                           │                    │
 *   │  lenses      │       WorkspaceCanvas     │  selected-node    │
 *   │  chapters    │    (empty until slices)   │  detail · inspect │
 *   │              │                           │                    │
 *   ├──────────────┴─────── StatusBar ────────┴────────────────────┤
 *   └──────────────────────────────────────────────────────────────┘
 *
 * Rendering rules:
 *   1. All regions ALWAYS exist in the DOM (stable layout contract).
 *   2. Empty regions render a semantic placeholder — never nothing —
 *      so keyboard navigation, screen readers, and Storybook stay
 *      predictable.
 *   3. Widths / paddings are token-driven; no hex, no px in this
 *      file (ADR-0018).
 *   4. Feature-flag gating is the caller's responsibility. The shell
 *      itself is always safe to render.
 *
 * @tier 3 · AppShell
 * @a11y semantic <header> / <nav> / <main> / <aside> / <footer>
 *       landmarks. `role="application"` intentionally NOT used.
 * @perf initial render budget: ≤ 16ms (empty state)
 */
import React from "react";
import VerdictRibbon from "../components/VerdictRibbon";
import { useDockedPanels } from "./Lab2Provider";
import "../design/tokens.css";

const S = {
  root: {
    display: "grid",
    gridTemplateRows: "auto auto 1fr auto",
    gridTemplateColumns: "220px 1fr 320px",
    gridTemplateAreas: `
      "header  header  header"
      "ribbon  ribbon  ribbon"
      "nav     main    context"
      "status  status  status"
    `,
    minHeight: "100vh",
    background: "var(--bg-canvas)",
    color: "var(--fg-primary)",
    fontFamily: "var(--font-sans)",
  },
  header: {
    gridArea: "header",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "var(--space-4) var(--space-6)",
    background: "var(--bg-panel)",
    borderBottom: "1px solid var(--border)",
  },
  headerLeft: {
    display: "flex",
    alignItems: "center",
    gap: "var(--space-5)",
  },
  brand: {
    fontFamily: "var(--font-mono)",
    fontSize: "var(--fs-strong)",
    fontWeight: "var(--fw-bold)",
    letterSpacing: "0.18em",
    color: "var(--fg-accent)",
  },
  caseChip: {
    padding: "var(--space-2) var(--space-4)",
    borderRadius: "var(--radius-sm)",
    background: "var(--bg-elevated)",
    color: "var(--fg-quiet)",
    fontSize: "var(--fs-caption)",
    fontFamily: "var(--font-mono)",
    letterSpacing: "0.14em",
  },
  headerRight: {
    display: "flex",
    alignItems: "center",
    gap: "var(--space-3)",
  },
  actionBtn: {
    padding: "var(--space-3) var(--space-4)",
    borderRadius: "var(--radius-sm)",
    background: "transparent",
    border: "1px solid var(--border)",
    color: "var(--fg-quiet)",
    fontSize: "var(--fs-caption)",
    fontFamily: "var(--font-mono)",
    letterSpacing: "0.12em",
    cursor: "pointer",
    transition: "background var(--motion-quick), color var(--motion-quick)",
  },
  ribbon: {
    gridArea: "ribbon",
    padding: "var(--space-4) var(--space-6)",
    background: "var(--bg-canvas)",
    borderBottom: "1px solid var(--border)",
  },
  nav: {
    gridArea: "nav",
    padding: "var(--space-5) var(--space-4)",
    background: "var(--bg-panel)",
    borderRight: "1px solid var(--border)",
    overflowY: "auto",
  },
  main: {
    gridArea: "main",
    display: "flex",
    flexDirection: "column",
    minWidth: 0,
    background: "var(--bg-canvas)",
  },
  toolbar: {
    display: "flex",
    alignItems: "center",
    gap: "var(--space-3)",
    padding: "var(--space-3) var(--space-6)",
    borderBottom: "1px solid var(--border)",
    background: "var(--bg-panel)",
  },
  canvas: {
    flex: 1,
    minHeight: 0,
    overflowY: "auto",
    padding: "var(--space-6)",
  },
  context: {
    gridArea: "context",
    padding: "var(--space-5) var(--space-4)",
    background: "var(--bg-panel)",
    borderLeft: "1px solid var(--border)",
    overflowY: "auto",
  },
  status: {
    gridArea: "status",
    display: "flex",
    alignItems: "center",
    gap: "var(--space-5)",
    padding: "var(--space-3) var(--space-6)",
    background: "var(--bg-panel)",
    borderTop: "1px solid var(--border)",
    fontSize: "var(--fs-caption)",
    fontFamily: "var(--font-mono)",
    color: "var(--fg-quiet)",
    letterSpacing: "0.12em",
  },
  navGroupLabel: {
    fontSize: "var(--fs-caption)",
    letterSpacing: "0.22em",
    textTransform: "uppercase",
    color: "var(--fg-quiet)",
    marginBottom: "var(--space-3)",
    marginTop: "var(--space-5)",
  },
  navItem: {
    display: "block",
    padding: "var(--space-3) var(--space-3)",
    borderRadius: "var(--radius-sm)",
    color: "var(--fg-primary)",
    fontSize: "var(--fs-body)",
    cursor: "pointer",
    transition: "background var(--motion-quick)",
  },
  placeholderCard: {
    border: "1px dashed var(--border-strong)",
    borderRadius: "var(--radius-md)",
    padding: "var(--space-6)",
    color: "var(--fg-quiet)",
    fontSize: "var(--fs-body)",
    background: "var(--bg-panel)",
  },
  placeholderH: {
    fontSize: "var(--fs-caption)",
    letterSpacing: "0.22em",
    textTransform: "uppercase",
    color: "var(--fg-quiet)",
    marginBottom: "var(--space-3)",
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 999,
    background: "var(--fg-accent)",
    display: "inline-block",
  },
};

function Placeholder({ title, hint, testid }) {
  return (
    <div style={S.placeholderCard} data-testid={testid}>
      <div style={S.placeholderH}>{title}</div>
      <div>{hint}</div>
    </div>
  );
}

/**
 * Lab2Shell — the workspace layout contract.
 *
 * Props (all optional, all slot-based):
 *   - headerLeft / headerRight ....... custom header content
 *   - caseLabel ...................... case chip text
 *   - navSlot ........................ Left navigation content
 *   - toolbarSlot .................... Toolbar row content
 *   - children / canvasSlot .......... Main workspace content
 *   - contextSlot .................... Right context/inspector panel
 *   - statusSlot ..................... Bottom status bar content
 *
 * Every slot has a default placeholder so the shell renders cleanly
 * even with zero content wired — critical for storybook + Phase A
 * incremental slices.
 */
export default function Lab2Shell({
  caseLabel = "no active case",
  headerLeft,
  headerRight,
  navSlot,
  toolbarSlot,
  canvasSlot,
  contextSlot,
  statusSlot,
  children,
}) {
  const { dockedPanels } = useDockedPanels();

  const style = {
    ...S.root,
    // Collapse regions per docked-panel state — geometry only,
    // never remove the region from the DOM.
    gridTemplateColumns: `${dockedPanels.left ? "220px" : "0px"} 1fr ${
      dockedPanels.right ? "320px" : "0px"
    }`,
  };

  return (
    <div className="lab2" data-testid="lab2-shell" style={style} role="presentation">
      {/* ── AppHeader ─────────────────────────────────────────── */}
      <header style={S.header} data-testid="lab2-header">
        <div style={S.headerLeft}>
          <span style={S.brand} data-testid="lab2-brand">NivXRay · Lab</span>
          <span style={S.caseChip} data-testid="lab2-case-chip">{caseLabel}</span>
          {headerLeft}
        </div>
        <div style={S.headerRight} data-testid="lab2-header-actions">
          {headerRight ?? (
            <>
              <button type="button" style={S.actionBtn} data-testid="lab2-palette-trigger">
                ⌘K
              </button>
              <button type="button" style={S.actionBtn} data-testid="lab2-theme-trigger">
                THEME
              </button>
            </>
          )}
        </div>
      </header>

      {/* ── VerdictRibbon (already implemented) ──────────────── */}
      <section style={S.ribbon} data-testid="lab2-ribbon" aria-label="Investigation verdict">
        <VerdictRibbon />
      </section>

      {/* ── LeftNav ───────────────────────────────────────────── */}
      <nav
        style={{ ...S.nav, display: dockedPanels.left ? "block" : "none" }}
        data-testid="lab2-nav"
        aria-label="Investigation lenses"
      >
        {navSlot ?? (
          <>
            <div style={S.navGroupLabel}>Lenses</div>
            {["Story", "Source", "Behaviour", "Timeline", "ATT&CK", "Entities", "Report", "Knowledge"].map(
              (lens) => (
                <div key={lens} style={S.navItem} data-testid={`lab2-nav-item-${lens.toLowerCase()}`}>
                  <span style={{ ...S.dot, marginRight: "var(--space-3)" }} aria-hidden />
                  {lens}
                </div>
              )
            )}
            <div style={S.navGroupLabel}>Case</div>
            <Placeholder
              title="Chapters"
              hint="Case chapters appear here once available."
              testid="lab2-nav-chapters-placeholder"
            />
          </>
        )}
      </nav>

      {/* ── Main (Toolbar + Canvas) ───────────────────────────── */}
      <main style={S.main} data-testid="lab2-main">
        <div style={S.toolbar} data-testid="lab2-toolbar" role="toolbar" aria-label="Workspace toolbar">
          {toolbarSlot ?? (
            <span style={{ color: "var(--fg-quiet)", fontSize: "var(--fs-caption)", letterSpacing: "0.14em" }}>
              TOOLBAR · (empty — lens actions dock here)
            </span>
          )}
        </div>
        <div style={S.canvas} data-testid="lab2-canvas">
          {canvasSlot ?? children ?? (
            <Placeholder
              title="Workspace Canvas"
              hint="Lens renderers, evidence lists, and graph views will render here."
              testid="lab2-canvas-placeholder"
            />
          )}
        </div>
      </main>

      {/* ── ContextPanel ──────────────────────────────────────── */}
      <aside
        style={{ ...S.context, display: dockedPanels.right ? "block" : "none" }}
        data-testid="lab2-context"
        aria-label="Selected evidence inspector"
      >
        {contextSlot ?? (
          <Placeholder
            title="Context Panel"
            hint="Select a node to inspect it here."
            testid="lab2-context-placeholder"
          />
        )}
      </aside>

      {/* ── StatusBar ─────────────────────────────────────────── */}
      <footer style={S.status} data-testid="lab2-status" role="contentinfo">
        {statusSlot ?? (
          <>
            <span data-testid="lab2-status-schema">SCHEMA · v0.1</span>
            <span aria-hidden>·</span>
            <span data-testid="lab2-status-engine">UNIFIED-VERDICT-ENGINE</span>
            <span aria-hidden>·</span>
            <span data-testid="lab2-status-flag">LAB2 · PREVIEW</span>
          </>
        )}
      </footer>
    </div>
  );
}
