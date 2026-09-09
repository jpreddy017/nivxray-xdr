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

  // PR-4 · Case list surface (was queued for PR-7, promoted forward
  // because analysts hitting the INVESTIGATE nav tab need somewhere to
  // land other than a dead-end "no case selected" message).
  const [cases, setCases]           = useState([]);
  const [casesStatus, setCasesStat] = useState("loading"); // loading · ready · error
  const [casesError, setCasesErr]   = useState("");

  const loadCases = useCallback(async () => {
    setCasesStat("loading");
    try {
      const list = await api.listCases();
      // Newest first — sort by updated_at desc.
      list.sort((a, b) => String(b.updated_at || "").localeCompare(String(a.updated_at || "")));
      setCases(list);
      setCasesStat("ready");
    } catch (e) {
      setCasesErr(e?.response?.data?.detail || e?.message || "list_failed");
      setCasesStat("error");
    }
  }, []);

  useEffect(() => { loadCases(); }, [loadCases]);

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

  const onAnchorClick = useCallback((anchorObj) => {
    // PR-4 stub: record the last anchor selection so PR-5 Evidence lens
    // can consume it. Persist `selected_evidence_id` server-side so the
    // choice survives a page reload.
    if (!anchorObj) return;
    const id =
      anchorObj.ioc_id ||
      anchorObj.capability_id ||
      anchorObj.technique_id ||
      anchorObj.transformation ||
      anchorObj.kind ||
      "";
    if (!id) return;
    persistWorkspace({ selected_evidence_id: String(id) });
    toast.message(`Anchor · ${anchorObj.kind || "unknown"}`, {
      description: `Selected ${id}. Evidence lens lands in PR-5.`,
    });
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
          className="hidden w-64 border-r border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-300 md:block"
        >
          <div className="flex items-center justify-between">
            <p className="text-xs uppercase tracking-widest text-slate-500">
              Cases
            </p>
            <button
              onClick={loadCases}
              data-testid="workspace-cases-refresh"
              className="text-[10px] uppercase tracking-widest text-slate-500 hover:text-slate-200"
              title="Reload case list"
            >
              refresh
            </button>
          </div>

          {casesStatus === "loading" ? (
            <p className="mt-3 text-xs text-slate-500">Loading cases…</p>
          ) : null}
          {casesStatus === "error" ? (
            <p className="mt-3 text-xs text-rose-400" data-testid="workspace-cases-error">
              {casesError}
            </p>
          ) : null}
          {casesStatus === "ready" && cases.length === 0 ? (
            <p
              data-testid="workspace-cases-empty-sidebar"
              className="mt-3 text-xs text-slate-500"
            >
              No cases yet. Run a decode on the{" "}
              <Link to="/" className="text-indigo-300 hover:underline">
                Workspace
              </Link>{" "}
              to create one.
            </p>
          ) : null}
          {casesStatus === "ready" && cases.length > 0 ? (
            <ul
              data-testid="workspace-cases-list"
              className="mt-3 space-y-1"
            >
              {cases.map((c) => {
                const isActive = c.case_id === caseId;
                const family = c.sample?.family || "";
                const technique = c.sample?.technique || "";
                return (
                  <li key={c.case_id}>
                    <button
                      onClick={() => navigate(`/investigate/${c.case_id}`)}
                      data-testid={`workspace-cases-item-${c.case_id}`}
                      className={`block w-full rounded-md border px-2 py-1.5 text-left transition ${
                        isActive
                          ? "border-indigo-600 bg-indigo-950/60 text-indigo-100"
                          : "border-slate-800 bg-slate-900/40 text-slate-300 hover:border-slate-700 hover:bg-slate-800/60"
                      }`}
                    >
                      <div className="truncate font-mono text-[11px]" title={c.case_id}>
                        {c.case_id}
                      </div>
                      {(family || technique) ? (
                        <div className="mt-0.5 truncate text-[10px] text-slate-500">
                          {family || "—"} {technique ? `· ${technique}` : ""}
                        </div>
                      ) : null}
                      <div className="mt-0.5 flex items-center gap-2 text-[10px] uppercase tracking-wider text-slate-500">
                        <span>{c.state}</span>
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          ) : null}

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
              className="flex flex-1 flex-col items-center justify-center gap-4 p-8 text-center"
            >
              {casesStatus === "ready" && cases.length > 0 ? (
                <>
                  <p className="text-sm text-slate-200">
                    Select a case from the sidebar to open it.
                  </p>
                  <p className="text-xs text-slate-500">
                    {cases.length} case{cases.length === 1 ? "" : "s"} available.
                  </p>
                </>
              ) : (
                <>
                  <p className="text-base text-slate-200">
                    No investigations yet.
                  </p>
                  <p className="max-w-md text-sm text-slate-400">
                    Paste any command line on the{" "}
                    <Link to="/" className="text-indigo-300 hover:underline">
                      NivXRay Workspace
                    </Link>{" "}
                    and run Auto Investigate. When it completes, click{" "}
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs text-slate-200">
                      OPEN INVESTIGATION WORKSPACE →
                    </span>{" "}
                    to land here with a live case.
                  </p>
                  <Link
                    to="/"
                    data-testid="workspace-cases-empty-cta"
                    className="mt-2 inline-flex items-center gap-2 rounded-md border border-indigo-700 bg-indigo-950 px-4 py-2 text-sm text-indigo-100 hover:border-indigo-500 hover:bg-indigo-900"
                  >
                    ← Go to the Workspace
                  </Link>
                </>
              )}
            </div>
          ) : null}

          {status === "ready" ? (
            <>
              <LensTabs activeLens={currentLens} onLensChange={onLensChange} />
              <LensPanel
                lens={currentLens}
                caseId={caseId}
                onAnchorClick={onAnchorClick}
              />
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
