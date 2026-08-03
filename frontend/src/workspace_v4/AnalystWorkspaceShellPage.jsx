/**
 * L4 Analyst Workspace shell (PR-3).
 *
 * Blueprint §7 · §8 · §9. SHELL ONLY per ARB PR-3 scope directive:
 *   * `/investigate` and `/investigate/:caseId` routes
 *   * Mode selector (§8.2)
 *   * State pill + one Advance button (§8.1)
 *   * Empty lens tabs (§9) — placeholder panels
 *   * Workspace state persisted via PUT /workspace on lens/mode change
 *
 * Explicit NON-goals (per ARB): no graphs, no timelines, no story
 * content, no IOC cards, no detection rules, no reports.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";

import api from "./investigationApi";
import LensTabs, { LensPanel } from "./LensTabs";
import ModeSelector from "./ModeSelector";
import StatePill from "./StatePill";
import {
  TID_CASE_EMPTY,
  TID_CASE_ID_LABEL,
  TID_CASE_LOADING,
  TID_CASE_LOAD_ERROR,
  TID_CASE_RETRY_BTN,
  TID_HOME_BREADCRUMB,
  TID_INVESTIGATION_FINGERPRINT,
  TID_PERSIST_INDICATOR,
  TID_REFRESH_BTN,
  TID_SHELL_FOOTER,
  TID_SHELL_HEADER,
  TID_SHELL_MAIN,
  TID_SHELL_ROOT,
  TID_SHELL_SIDEBAR,
} from "./testIds";

export default function AnalystWorkspaceShellPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();

  const [status, setStatus]     = useState("idle"); // idle · loading · ready · error · empty
  const [bundle, setBundle]     = useState(null);
  const [workspace, setWs]      = useState(null);
  const [error, setError]       = useState("");
  const [persistState, setPersist] = useState("idle"); // idle · saving · saved · error

  const load = useCallback(async () => {
    if (!caseId) {
      setStatus("empty");
      return;
    }
    setStatus("loading");
    setError("");
    try {
      const data = await api.getWorkspaceBundle(caseId);
      setBundle(data);
      setWs(data.workspace);
      setStatus("ready");
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "load_failed");
      setStatus("error");
    }
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  const persistWorkspace = useCallback(async (patch) => {
    if (!caseId || !workspace) return;
    setPersist("saving");
    try {
      const next = await api.putWorkspaceState(caseId, patch);
      setWs(next);
      setPersist("saved");
      setTimeout(() => setPersist((s) => (s === "saved" ? "idle" : s)), 1500);
    } catch (e) {
      setPersist("error");
      toast.error(`Save failed: ${e?.response?.data?.detail || e?.message}`);
    }
  }, [caseId, workspace]);

  const advanceState = useCallback(async (target) => {
    if (!caseId) return;
    try {
      const res = await api.transitionState(caseId, target);
      setBundle((b) => (b ? { ...b, state: res.current_state } : b));
      // Refresh workspace to pick up mirrored investigation_state.
      const w = await api.getWorkspaceState(caseId);
      setWs(w);
      toast.success(`State → ${res.current_state}`);
    } catch (e) {
      toast.error(`Transition failed: ${e?.response?.data?.detail || e?.message}`);
    }
  }, [caseId]);

  const onModeChange = useCallback((mode) => {
    persistWorkspace({ mode });
  }, [persistWorkspace]);

  const onLensChange = useCallback((active_lens) => {
    persistWorkspace({ active_lens });
  }, [persistWorkspace]);

  const currentLens = workspace?.active_lens || "summary";
  const currentMode = workspace?.mode || "investigation";
  const currentState = bundle?.state || workspace?.investigation_state || "new";

  const persistLabel = useMemo(() => {
    switch (persistState) {
      case "saving": return "Saving…";
      case "saved":  return "Saved";
      case "error":  return "Save failed";
      default:       return "";
    }
  }, [persistState]);

  return (
    <div
      data-testid={TID_SHELL_ROOT}
      className="flex min-h-screen flex-col bg-slate-950 text-slate-100"
    >
      {/* Header */}
      <header
        data-testid={TID_SHELL_HEADER}
        className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 bg-slate-950/80 px-6 py-3 backdrop-blur"
      >
        <div className="flex items-center gap-4">
          <Link
            to="/"
            data-testid={TID_HOME_BREADCRUMB}
            className="text-xs uppercase tracking-widest text-slate-500 hover:text-slate-200"
          >
            NivXRay
          </Link>
          <span className="text-slate-700">/</span>
          <span className="text-sm font-medium text-slate-200">
            Analyst Workspace
          </span>
          {caseId ? (
            <>
              <span className="text-slate-700">/</span>
              <span
                data-testid={TID_CASE_ID_LABEL}
                className="rounded-md bg-slate-900 px-2 py-1 font-mono text-xs text-slate-300"
              >
                {caseId}
              </span>
            </>
          ) : null}
        </div>

        <div className="flex items-center gap-4">
          <span
            data-testid={TID_PERSIST_INDICATOR}
            aria-live="polite"
            className="min-w-[64px] text-right text-xs text-slate-400"
          >
            {persistLabel}
          </span>
          <ModeSelector
            value={currentMode}
            onChange={onModeChange}
            disabled={status !== "ready"}
          />
          <StatePill
            state={currentState}
            disabled={status !== "ready"}
            onAdvance={advanceState}
          />
          <button
            data-testid={TID_REFRESH_BTN}
            onClick={load}
            className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
          >
            Refresh
          </button>
        </div>
      </header>

      {/* Body */}
      <div className="flex flex-1 overflow-hidden">
        <aside
          data-testid={TID_SHELL_SIDEBAR}
          aria-label="Workspace navigation"
          className="hidden w-56 border-r border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-300 md:block"
        >
          <p className="text-xs uppercase tracking-widest text-slate-500">
            Case
          </p>
          <button
            onClick={() => navigate("/investigate")}
            className="mt-2 block w-full rounded-md px-2 py-1 text-left text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"
          >
            ← All cases
          </button>
          {bundle?.output?.body?.services ? (
            <div className="mt-6">
              <p className="text-xs uppercase tracking-widest text-slate-500">
                Fingerprint
              </p>
              <p
                data-testid={TID_INVESTIGATION_FINGERPRINT}
                className="mt-1 truncate font-mono text-xs text-slate-500"
                title={bundle.fingerprint}
              >
                {(bundle.fingerprint || "").slice(0, 16)}…
              </p>
            </div>
          ) : null}
        </aside>

        <main
          data-testid={TID_SHELL_MAIN}
          className="flex flex-1 flex-col overflow-y-auto"
        >
          {status === "loading" ? (
            <div
              data-testid={TID_CASE_LOADING}
              className="flex flex-1 items-center justify-center text-sm text-slate-400"
            >
              Loading investigation…
            </div>
          ) : null}

          {status === "error" ? (
            <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8">
              <p
                data-testid={TID_CASE_LOAD_ERROR}
                className="text-sm text-rose-300"
              >
                {error === "case_not_found:" + caseId
                  ? `Case '${caseId}' not found.`
                  : `Failed to load case: ${error}`}
              </p>
              <button
                data-testid={TID_CASE_RETRY_BTN}
                onClick={load}
                className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-200 hover:bg-slate-800"
              >
                Retry
              </button>
            </div>
          ) : null}

          {status === "empty" ? (
            <div
              data-testid={TID_CASE_EMPTY}
              className="flex flex-1 flex-col items-center justify-center gap-2 p-8 text-center"
            >
              <p className="text-sm text-slate-300">
                No case selected.
              </p>
              <p className="max-w-md text-xs text-slate-500">
                Open a case from the L1 API (POST <code className="rounded bg-slate-900 px-1">/api/investigation</code>)
                and navigate to <code className="rounded bg-slate-900 px-1">/investigate/&lt;case_id&gt;</code>.
                The case-list surface lands in PR-7.
              </p>
            </div>
          ) : null}

          {status === "ready" ? (
            <>
              <LensTabs activeLens={currentLens} onLensChange={onLensChange} />
              <LensPanel lens={currentLens} />
            </>
          ) : null}
        </main>
      </div>

      {/* Footer */}
      <footer
        data-testid={TID_SHELL_FOOTER}
        className="border-t border-slate-800 bg-slate-950/80 px-6 py-2 text-xs text-slate-500"
      >
        Analyst Workspace shell · PR-3 · Blueprint v1.1
      </footer>
    </div>
  );
}
