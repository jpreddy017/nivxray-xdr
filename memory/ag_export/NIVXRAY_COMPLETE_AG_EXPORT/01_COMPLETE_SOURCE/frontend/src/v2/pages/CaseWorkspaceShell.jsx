/**
 * v2 · Case Workspace shell.
 *
 * Placeholder for Phase 3+ — renders nothing meaningful yet. Guarded
 * by the CASE_ENGINE feature flag so it stays completely off in
 * production until the workspace is real. Hidden from top-level
 * navigation for now; only reachable via direct URL when the flag
 * is at least `shadow`.
 */
import Header from "@/components/Header";
import { isObservable } from "../flags";

export default function CaseWorkspaceShell() {
  if (!isObservable("CASE_ENGINE")) {
    return (
      <div className="min-h-screen" style={{ background: "var(--surface)" }}>
        <Header />
        <div
          data-testid="v2-workspace-disabled"
          style={{
            padding: 24,
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
            fontSize: 12,
            color: "var(--text-mute)",
          }}
        >
          v2 Case Workspace is disabled. Set{" "}
          <code>REACT_APP_NIVX_FLAG_CASE_ENGINE=shadow</code> to preview.
        </div>
      </div>
    );
  }
  return (
    <div className="min-h-screen" style={{ background: "var(--surface)" }}>
      <Header />
      <div
        data-testid="v2-workspace-shell"
        style={{
          padding: 24,
          color: "var(--text)",
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
        }}
      >
        <div
          style={{
            fontSize: 9,
            letterSpacing: "0.24em",
            color: "var(--text-mute)",
            marginBottom: 6,
          }}
        >
          NIVXRAY · V2 · SHADOW
        </div>
        <h1 style={{ fontFamily: "Chivo, sans-serif", fontWeight: 900, letterSpacing: "-0.02em" }}>
          Case Workspace
        </h1>
        <p style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 6 }}>
          Placeholder — Phase 3 will populate this shell with 17 synchronised tabs.
        </p>
      </div>
    </div>
  );
}
