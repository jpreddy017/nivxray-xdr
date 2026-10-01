/**
 * Cross-product launcher · NivXMachines Workspace.
 *
 * Owner decision (2026-09-08): the Workspace / AutoInvestigate / Decoder
 * frontend (`/app/frontend`) is deployed SEPARATELY at its own origin and
 * calls the same authoritative backend. The two frontend codebases are
 * deliberately NOT merged, so this console cannot route to it — it can
 * only hand the analyst over to it, in a new tab.
 *
 * Why the disabled state exists rather than a hopeful link:
 * `xdr/XdrShell.jsx` already carries the lesson in writing — an
 * "Analyst Workspace" item used to point at `/analyst`, which had no
 * application, so the SPA catch-all bounced the new tab straight back
 * here. That control was removed with the note *"a control that pretends
 * to open another product and silently returns you to this one is a dead
 * control"*. So this button is live ONLY when a Workspace origin is
 * actually configured for the deployment; otherwise it says so and does
 * nothing.
 *
 * Configure with `REACT_APP_WORKSPACE_URL` (see `.env`).
 */
import React from "react";
import { ExternalLink } from "lucide-react";

export const WORKSPACE_URL =
  (process.env.REACT_APP_WORKSPACE_URL || "").trim().replace(/\/+$/, "");

export const WorkspaceLaunch = ({ label = "NivXMachines Workspace",
                                  testid = "open-nivxmachines-workspace" }) => {
  if (!WORKSPACE_URL) {
    return (
      <button
        className="btn ghost"
        disabled
        data-testid={`${testid}-unconfigured`}
        data-workspace-state="NOT_CONFIGURED"
        title={"NivXMachines Workspace runs as a separate frontend at its "
               + "own origin. No Workspace URL is configured for this "
               + "deployment (REACT_APP_WORKSPACE_URL), so this console "
               + "will not pretend to open it."}
        style={{ display: "inline-flex", alignItems: "center", gap: 6,
                 opacity: .45, cursor: "not-allowed" }}
      >
        <ExternalLink size={12} /> {label}
        <span className="mono" style={{ fontSize: 9, letterSpacing: .5 }}>
          ◇ NOT CONFIGURED
        </span>
      </button>
    );
  }
  return (
    <button
      className="btn ghost"
      data-testid={testid}
      data-workspace-state="CONFIGURED"
      data-workspace-url={WORKSPACE_URL}
      onClick={() => window.open(WORKSPACE_URL, "_blank",
                                 "noopener,noreferrer")}
      title={`Open ${label} in a new tab (${WORKSPACE_URL}) · AutoInvestigate, `
             + "Decoder, Analyze and Lab. It is a separate origin, so you "
             + "may need to sign in there once."}
      style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
    >
      <ExternalLink size={12} /> {label}
    </button>
  );
};

export default WorkspaceLaunch;
