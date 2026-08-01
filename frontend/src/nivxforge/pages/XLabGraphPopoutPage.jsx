import React, { useEffect, useState } from "react";
import { EvidenceGraphCanvas } from "../lab2/evidence-graph/EvidenceGraphCanvas";

/**
 * Popout page for the EvidenceGraphCanvas — opened via window.open() from
 * X-Lab's Investigation Graph toolbar. Reads the current CIO (and initial
 * view) from localStorage, so the popout works even after the opener tab
 * navigates away. Also subscribes to a BroadcastChannel so subsequent
 * investigations in the opener tab live-update the popout.
 */
const STORAGE_KEY = "xlab.graph.popout.cio";
const STORAGE_VIEW = "xlab.graph.popout.view";
const CHANNEL_NAME = "xlab-graph-popout";

export default function XLabGraphPopoutPage() {
  const [cio, setCio] = useState(null);
  const [view, setView] = useState("investigation");

  useEffect(() => {
    // Initial hydration from localStorage.
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setCio(JSON.parse(raw));
      const v = localStorage.getItem(STORAGE_VIEW);
      if (v) setView(v);
    } catch (_e) { /* ignore */ }

    // Live updates from the opener tab.
    let ch = null;
    try {
      ch = new BroadcastChannel(CHANNEL_NAME);
      ch.onmessage = (evt) => {
        const msg = evt?.data || {};
        if (msg.type === "cio" && msg.cio) setCio(msg.cio);
        if (msg.type === "view" && msg.view) setView(msg.view);
      };
    } catch (_e) { /* browsers without BroadcastChannel: silently skip */ }

    document.title = "X-Lab · Investigation Graph";
    document.body.classList.add("xlab-popout-body");
    return () => {
      document.body.classList.remove("xlab-popout-body");
      if (ch) { try { ch.close(); } catch (_e) { /* noop */ } }
    };
  }, []);

  if (!cio) {
    return (
      <div className="xlab-popout-empty" data-testid="xlab-popout-empty">
        <h2>No investigation loaded</h2>
        <p>Run an investigation in X-Lab, then click <b>Pop Out</b> from the Investigation Graph toolbar to open the canvas here.</p>
      </div>
    );
  }

  return (
    <div className="xlab-popout-wrap" data-testid="xlab-popout-wrap">
      <header className="xlab-popout-header">
        <div>
          <div className="xlab-popout-brand">NivXRay · X-Lab</div>
          <h1>Investigation Graph</h1>
        </div>
        <div className="xlab-popout-meta">
          <span className="quiet">verdict</span> <b>{cio?.verdict?.label || "—"}</b>
          <span className="dot">·</span>
          <span className="quiet">confidence</span> <b>{cio?.verdict?.confidence_pct ?? "—"}%</b>
          <span className="dot">·</span>
          <span className="quiet">nodes</span> <b>{(cio?.evidence_graph?.nodes || []).length}</b>
        </div>
      </header>
      <main className="xlab-popout-main">
        <EvidenceGraphCanvas cio={cio} defaultView={view} />
      </main>
    </div>
  );
}
