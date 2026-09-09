// Top-level Error Boundary for the entire Workspace.
// Phase B (2026-02-13) · No blank screens allowed. If any child throws,
// we log the crash with a diagnosable payload and render a fallback.
//
// Design rules:
//   - Never swallow — always log to console with full component stack.
//   - Include a run-id / current-state snapshot so we can correlate
//     with a specific investigation reproduction.
//   - Give the analyst a "Reload workspace" escape hatch that clears
//     the crashed subtree without a full page reload.
//   - No dependency on router, so this can wrap the outermost page.
import React from "react";

export default class PageErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, info: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Emit a structured, greppable crash record.
    // eslint-disable-next-line no-console
    console.error("[NIVXRAY · WORKSPACE CRASH]", {
      error: error && error.message,
      stack: error && error.stack,
      componentStack: info && info.componentStack,
      when: new Date().toISOString(),
      href: typeof window !== "undefined" ? window.location.href : null,
    });
    this.setState({ info });
    if (typeof this.props.onError === "function") {
      try { this.props.onError(error, info); } catch { /* ignore */ }
    }
  }

  handleReset = () => {
    this.setState({ error: null, info: null });
  };

  render() {
    if (!this.state.error) return this.props.children;
    const msg = (this.state.error && this.state.error.message) || String(this.state.error);
    const stack = (this.state.info && this.state.info.componentStack) || "";
    return (
      <div
        data-testid="workspace-crash-fallback"
        style={{
          padding: 24,
          background: "#1a0d0d",
          color: "#F5F7FA",
          minHeight: "60vh",
          fontFamily: "Helvetica Neue, sans-serif",
          borderTop: "3px solid #F87171",
        }}
      >
        <div style={{ fontSize: 12, letterSpacing: "0.18em", color: "#F87171", marginBottom: 8 }}>
          NIVXRAY · WORKSPACE ERROR
        </div>
        <div style={{ fontSize: 24, fontWeight: 700, marginBottom: 6 }}>
          Something went wrong in the workspace.
        </div>
        <div style={{ fontSize: 13, color: "#8B94A6", marginBottom: 16 }}>
          The rest of the app is unaffected. The error has been logged to the browser console
          with full component stack for triage.
        </div>
        <div style={{
          background: "#0B0F14",
          border: "1px solid #1F2A37",
          padding: 12,
          borderRadius: 4,
          fontFamily: "Menlo, monospace",
          fontSize: 12,
          color: "#F48FB2",
          maxHeight: 180,
          overflow: "auto",
          whiteSpace: "pre-wrap",
        }}>
          {msg}
          {stack ? "\n\n— Component stack —" + stack : ""}
        </div>
        <div style={{ marginTop: 16, display: "flex", gap: 12 }}>
          <button
            data-testid="workspace-crash-reset"
            onClick={this.handleReset}
            style={{
              padding: "8px 16px",
              background: "#E8B64C",
              color: "#0B0F14",
              fontWeight: 700,
              border: 0,
              cursor: "pointer",
              fontFamily: "Menlo, monospace",
              fontSize: 12,
              letterSpacing: "0.12em",
            }}
          >
            RESET WORKSPACE
          </button>
          <button
            data-testid="workspace-crash-reload"
            onClick={() => window.location.reload()}
            style={{
              padding: "8px 16px",
              background: "transparent",
              color: "#F5F7FA",
              border: "1px solid #1F2A37",
              cursor: "pointer",
              fontFamily: "Menlo, monospace",
              fontSize: 12,
              letterSpacing: "0.12em",
            }}
          >
            RELOAD PAGE
          </button>
        </div>
      </div>
    );
  }
}
