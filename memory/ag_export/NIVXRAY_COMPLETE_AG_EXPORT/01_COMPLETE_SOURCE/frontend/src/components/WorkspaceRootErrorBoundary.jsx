/**
 * WorkspaceRootErrorBoundary — final safety net (2026-08-11).
 *
 * Wraps the whole Workspace so that ANY render exception from ANY
 * descendant is caught and replaced with a helpful "reset" screen
 * instead of a blank black page.  PanelErrorBoundary already
 * isolates individual panels; this catches the residual case where
 * an error is thrown OUTSIDE a PanelErrorBoundary (e.g. from a
 * shared hook, memo, or the Workspace shell itself).
 *
 * Contract:
 *   · Never mutates Workspace state.
 *   · Provides a "Reset Workspace" button that wipes persisted
 *     localStorage keys (`nvx_*`, `xlab.*`) and reloads the page.
 *   · Logs the caught error to the console + optional telemetry hook.
 */
import React from "react";

class WorkspaceRootErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { err: null, info: null };
  }

  static getDerivedStateFromError(err) {
    return { err };
  }

  componentDidCatch(err, info) {
    this.setState({ info });
    // eslint-disable-next-line no-console
    console.error("[WorkspaceRootErrorBoundary] uncaught render error:", err, info);
    try {
      if (typeof this.props.onError === "function") this.props.onError(err, info);
    } catch (_) { /* never let the reporter itself crash */ }
  }

  handleReset = () => {
    try {
      // Wipe every localStorage key the Workspace persists.  Anything
      // else we leave alone (auth token stays in place).
      const keys = [];
      for (let i = 0; i < window.localStorage.length; i++) {
        const k = window.localStorage.key(i);
        if (!k) continue;
        if (k.startsWith("nvx_") || k.startsWith("nivx_") || k.startsWith("xlab.")
            || k.startsWith("workspace.") || k.startsWith("investigation.")) {
          keys.push(k);
        }
      }
      keys.forEach(k => window.localStorage.removeItem(k));
    } catch (_) { /* localStorage may be blocked in strict modes */ }
    window.location.reload();
  };

  handleContinue = () => {
    this.setState({ err: null, info: null });
  };

  render() {
    if (!this.state.err) return this.props.children;
    const msg = (this.state.err && this.state.err.message) || String(this.state.err || "");
    return (
      <div data-testid="workspace-root-error-boundary"
           style={{
             minHeight:      "100vh",
             padding:        "48px 32px",
             color:          "#e5e7eb",
             background:     "#0b0f19",
             fontFamily:     "system-ui, -apple-system, sans-serif",
             display:        "flex",
             flexDirection:  "column",
             alignItems:     "center",
             justifyContent: "center",
             gap:            18,
           }}>
        <div style={{ maxWidth: 640, textAlign: "left" }}>
          <div style={{ fontSize: 12, opacity: 0.55, letterSpacing: 0.6,
                        textTransform: "uppercase", marginBottom: 6 }}>
            Workspace guard
          </div>
          <h1 style={{ fontSize: 22, fontWeight: 600, margin: "0 0 6px" }}>
            The Workspace hit an unrecoverable render error.
          </h1>
          <p style={{ fontSize: 13, opacity: 0.75, margin: "0 0 12px", lineHeight: 1.6 }}>
            Your data is safe.  This screen is the safety-net that replaces the
            previous black-screen behaviour.  Choose an action below.
          </p>
          <details style={{ fontSize: 12, opacity: 0.75, marginBottom: 20,
                            padding: 10, border: "1px solid #1f2937",
                            borderRadius: 6, background: "rgba(0,0,0,0.25)" }}>
            <summary style={{ cursor: "pointer" }}>Show error details</summary>
            <pre style={{ marginTop: 8, whiteSpace: "pre-wrap", wordBreak: "break-word",
                          fontFamily: "ui-monospace, SFMono-Regular, monospace",
                          fontSize: 11 }}>
              {msg}
              {this.state.info?.componentStack ? "\n\n" + this.state.info.componentStack : ""}
            </pre>
          </details>
          <div style={{ display: "flex", gap: 10 }}>
            <button
              data-testid="workspace-root-error-reset"
              onClick={this.handleReset}
              style={{
                padding: "8px 16px", borderRadius: 4, fontSize: 13, fontWeight: 600,
                cursor: "pointer", border: "1px solid #3b82f6",
                background: "rgba(59,130,246,0.2)", color: "#bfdbfe",
              }}>
              Reset Workspace &amp; reload
            </button>
            <button
              data-testid="workspace-root-error-continue"
              onClick={this.handleContinue}
              style={{
                padding: "8px 16px", borderRadius: 4, fontSize: 13,
                cursor: "pointer", border: "1px solid #374151",
                background: "transparent", color: "inherit",
              }}>
              Try to continue
            </button>
          </div>
        </div>
      </div>
    );
  }
}

export default WorkspaceRootErrorBoundary;
