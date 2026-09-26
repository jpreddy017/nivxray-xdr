/**
 * NxErrorBoundary · a page crash must never take the console with it.
 *
 * A single page that throws used to unmount `XdrShell` — the analyst lost
 * the navigation rail as well as the page, with no way back. The boundary
 * keeps the shell alive and states the failure honestly instead of
 * rendering a blank document.
 */
import React from "react";

export default class NxErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Keep the real trace where an engineer can read it.
    console.error("[NxErrorBoundary]", error, info?.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    if (this.props.fallback) return this.props.fallback(this.state.error);
    return (
      <div className="nx-empty nx-empty--noicon" role="alert"
           data-testid="nx-page-error-boundary">
        <div className="nx-empty__title">
          ERROR — this view failed to render
        </div>
        <div className="nx-empty__hint">
          {String(this.state.error?.message || this.state.error)}
          {" "}The navigation and the rest of the console are unaffected, and
          no data was changed. This is a rendering failure, not an empty
          dataset and not an authorization decision.
        </div>
      </div>
    );
  }
}
