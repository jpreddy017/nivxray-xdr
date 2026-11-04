/**
 * PanelErrorBoundary — isolate render / data-shape crashes to one panel.
 *
 * Phase 5.W permanent fix · P0.b (2026-08-11)
 *
 * Motivation: the Workspace renders a tall stack of independent panels
 * (Analyst Narrative, MITRE Coverage, Attack Chain, LOLBAS, IOCs,
 *  Trajectory Diagram, Threat Analysis, …). Before this component, ANY
 * one of them crashing on unexpected data (React "Objects are not
 * valid as a React child", `undefined.map`, etc.) would blow up the
 * whole tab and force a full page reload.
 *
 * A `PanelErrorBoundary` scoped to each panel:
 *   • Catches the render error via `componentDidCatch`.
 *   • Renders a compact, informative fallback the analyst can
 *     recognise (name of the broken panel + short reason).
 *   • Logs the full stack trace to the browser console (retained
 *     for triage).
 *   • Never propagates the error upward — the other panels stay
 *     alive and usable.
 *
 * Contract:
 *   <PanelErrorBoundary panel="Analyst Narrative">
 *     <AnalystNarrativePanel narrative={…} />
 *   </PanelErrorBoundary>
 *
 * DO NOT catch data-fetch errors here — those belong in the panel's
 * own effect / query. This boundary is specifically for RENDER-time
 * exceptions.
 */
import React from "react";

class PanelErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { crashed: false, message: "" };
  }

  static getDerivedStateFromError(err) {
    return {
      crashed: true,
      message: (err && err.message) ? String(err.message).slice(0, 180) : "unknown error",
    };
  }

  componentDidCatch(err, info) {
    // Preserve the full trace in the console so an analyst can
    // paste it into a bug report.
    // eslint-disable-next-line no-console
    console.error(
      `[PanelErrorBoundary] panel="${this.props.panel || "?"}" crashed:`,
      err, info,
    );
  }

  handleReset = () => {
    this.setState({ crashed: false, message: "" });
  };

  render() {
    if (!this.state.crashed) return this.props.children;

    const panelName = this.props.panel || "Panel";
    return (
      <div
        data-testid={`panel-error-${(panelName || "").toLowerCase().replace(/\s+/g, "-")}`}
        style={{
          border:      "1px solid #7f1d1d",
          background:  "rgba(127,29,29,0.16)",
          borderRadius: 8,
          padding:      "10px 14px",
          margin:       "8px 0",
          color:        "#fecaca",
          fontFamily:   "JetBrains Mono, monospace",
          fontSize:     12.5,
        }}
      >
        <div style={{ fontWeight: 700, marginBottom: 4 }}>
          ⚠ {panelName} unavailable
        </div>
        <div style={{ opacity: 0.85, marginBottom: 6 }}>
          A render error prevented this panel from displaying. Other panels
          continue to work. Details are in the browser console.
        </div>
        <div style={{ fontSize: 11.5, opacity: 0.75, marginBottom: 6 }}>
          <code>{this.state.message}</code>
        </div>
        <button
          onClick={this.handleReset}
          data-testid={`panel-error-retry-${(panelName || "").toLowerCase().replace(/\s+/g, "-")}`}
          style={{
            padding:     "4px 10px",
            fontSize:    12,
            color:       "#fecaca",
            background:  "transparent",
            border:      "1px solid #7f1d1d",
            borderRadius: 4,
            cursor:      "pointer",
          }}
        >
          Retry render
        </button>
      </div>
    );
  }
}

export default PanelErrorBoundary;
