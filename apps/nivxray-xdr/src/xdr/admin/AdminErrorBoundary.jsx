/**
 * Last-resort containment for the Administration surfaces.
 *
 * A structured refusal rendered as a React child threw #31 during render and
 * blanked the entire SPA — the operator saw a black page with no indication
 * that anything had been refused. Known defects of that shape are fixed at
 * source (`lib/refusal.js`); this boundary exists so the NEXT unforeseen
 * render exception degrades to a readable panel instead of a black screen.
 *
 * It is NOT an authorization mechanism and must never behave like one:
 *   · it never converts a refusal into success
 *   · it never retries, re-scopes or substitutes a tenant
 *   · it renders no credential, token or backend internal
 * It catches UI exceptions only, and says plainly that the surface failed.
 */
import React from "react";

export default class AdminErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidUpdate(prev) {
    // A different section was selected — give it a clean attempt.
    if (prev.sectionKey !== this.props.sectionKey && this.state.error)
      this.setState({ error: null });
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    const message = String(error?.message || error);
    return (
      <div className="panel" data-testid="admin-surface-error"
           style={{ padding: 16 }}>
        <div style={{ fontSize: 12.5, color: "#f87171",
                      fontFamily: "var(--mono)", marginBottom: 6 }}>
          ADMINISTRATION SURFACE FAILED TO RENDER
        </div>
        <div style={{ fontSize: 11.5, color: "var(--text-dim)",
                      lineHeight: 1.6, marginBottom: 8 }}>
          This surface raised an exception while rendering
          {this.props.sectionKey ? ` (${this.props.sectionKey})` : ""}. Nothing
          was changed and no authorization decision was altered. Other surfaces
          remain usable.
        </div>
        <code data-testid="admin-surface-error-detail"
              style={{ display: "block", userSelect: "all", fontSize: 11,
                       color: "var(--faint)", fontFamily: "var(--mono)",
                       whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
          {message}
        </code>
      </div>
    );
  }
}
