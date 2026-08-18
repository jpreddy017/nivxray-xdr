import { useEffect, useState, useRef, useMemo, useDeferredValue, startTransition } from "react";
import React from "react";
import Header from "@/components/Header";
import PageHeader from "@/components/PageHeader";
import OperationsPanel from "@/components/OperationsPanel";
import RecipePanel from "@/components/RecipePanel";
import ThreatAnalysis from "@/components/ThreatAnalysis";
import ReportMenu from "@/components/ReportMenu";
import AttackGraph from "@/components/AttackGraph";
import FinalSummary from "@/components/FinalSummary";
import ShellcodeView from "@/components/ShellcodeView";
import OutputView from "@/components/OutputView";
import WorkspaceDecodeFailureCard from "@/components/investigation/WorkspaceDecodeFailureCard";
import InputUnderstandingPanel from "@/components/investigation/InputUnderstandingPanel";
import AcquisitionPlanPanel from "@/components/investigation/AcquisitionPlanPanel";
import ExtractedArtifactsPanel from "@/components/investigation/ExtractedArtifactsPanel"; // eslint-disable-line no-unused-vars
import AcquisitionSummary from "@/components/investigation/AcquisitionSummary";
import AcquisitionEvidenceList from "@/components/investigation/AcquisitionEvidenceList";
import InvestigationSessionGateway from "@/components/investigation/InvestigationSessionGateway";
import CollapsibleSection from "@/components/investigation/CollapsibleSection";
import InlineAttackStory from "@/components/investigation/InlineAttackStory";
import TrajectoryDiagram from "@/components/investigation/TrajectoryDiagram";
import BehavioralTimeline from "@/components/investigation/BehavioralTimeline";
import ArtifactTracePanel from "@/components/investigation/ArtifactTracePanel";

// ── Local ErrorBoundary — protects the workspace from any single
// downstream projection component crashing on a malformed case.
// ═════════════════════════════════════════════════════════════════
// 2026-02-09 · Anti-Freeze / Anti-Black-Screen SLA
// ─────────────────────────────────────────────────────────────────
// HARD requirement from the product owner:
//   "No more black screens.  No more Exit/Wait dialog for any input."
//
// Defence-in-depth layers below.  If ANY of these fail, the workspace
// must still show *something* — never a blank tab.
// ═════════════════════════════════════════════════════════════════

// Global uncaught error / promise-rejection handler.  Any exception
// that bubbles out of a React render, a stream callback, or an async
// task is trapped here — the tab keeps its DOM intact instead of
// blanking out.  Chrome's "Aw, Snap" and "Page Unresponsive" pages
// are both triggered when the main thread throws or hangs; we cannot
// prevent every hang, but we CAN prevent every uncaught throw.
if (typeof window !== "undefined" && !window.__nvxAntiFreezeInstalled) {
  window.__nvxAntiFreezeInstalled = true;
  window.addEventListener("error", (ev) => {
    // Log but don't propagate — Chrome would otherwise show a fatal
    // console page for a runtime error in the main thread.
    // eslint-disable-next-line no-console
    console.warn("[nvx-anti-freeze] uncaught error:", ev?.error?.message || ev?.message);
    ev.preventDefault?.();
  });
  window.addEventListener("unhandledrejection", (ev) => {
    // eslint-disable-next-line no-console
    console.warn("[nvx-anti-freeze] unhandled promise rejection:", ev?.reason?.message || ev?.reason);
    ev.preventDefault?.();
  });
}

// Anti-Freeze / Anti-Black-Screen — workspace-wide error boundary.
// The previous boundary only wrapped the Trajectory panel; any other
// component crash could still blank the whole tab.  This one is
// mounted at the WorkspacePage root and shows a persistent recovery
// card if any child in the tree throws during render.
class WorkspaceErrorBoundary extends React.Component {
  constructor(p) { super(p); this.state = { err: null, info: null }; }
  static getDerivedStateFromError(e) { return { err: e }; }
  componentDidCatch(e, info) {
    // eslint-disable-next-line no-console
    console.error("[WorkspaceErrorBoundary]", e, info);
    this.setState({ info });
  }
  reset = () => this.setState({ err: null, info: null });
  render() {
    if (this.state.err) {
      return (
        <div data-testid="workspace-error-boundary"
             style={{ padding: 24, minHeight: "60vh",
                      background: "#0b1220", color: "#fecaca",
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: 13, lineHeight: 1.5 }}>
          <div style={{ maxWidth: 780, margin: "40px auto" }}>
            <div style={{ fontSize: 15, marginBottom: 12, color: "#fca5a5" }}>
              ⚠︎ WORKSPACE · RENDER GUARD
            </div>
            <div style={{ marginBottom: 8 }}>
              A child component threw an exception while rendering the
              workspace.  Your session is preserved — nothing has been
              lost.  Click "Reset workspace" to restore the UI.
            </div>
            <pre style={{ marginTop: 12, padding: 12,
                          background: "rgba(0,0,0,0.4)",
                          borderRadius: 6, overflow: "auto",
                          fontSize: 11 }}>
              {String(this.state.err?.message || this.state.err).slice(0, 800)}
            </pre>
            <button
              data-testid="workspace-error-reset"
              onClick={this.reset}
              style={{ marginTop: 16, padding: "8px 16px",
                       background: "#ef4444", color: "#fff",
                       border: "none", borderRadius: 6,
                       cursor: "pointer", fontWeight: 600 }}>
              Reset workspace
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// Falls back to a small in-place notice rather than a black screen.
class TrajErrorBoundary extends React.Component {
  constructor(p) { super(p); this.state = { err: null }; }
  static getDerivedStateFromError(e) { return { err: e }; }
  componentDidCatch(e, info) {
    // eslint-disable-next-line no-console
    console.error("TrajErrorBoundary caught:", e, info);
  }
  render() {
    if (this.state.err) {
      return (
        <div data-testid="traj-error-boundary"
             style={{ padding: 14, margin: "0 12px 8px",
                      border: "1px solid rgba(239,68,68,0.35)",
                      borderRadius: 8,
                      background: "rgba(15,23,42,0.85)",
                      color: "#fecaca",
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: 11 }}>
          ⚠︎ Trajectory projection failed for this case
          ({String(this.state.err && this.state.err.message || this.state.err).slice(0, 200)}).
          Rest of the workspace is unaffected.
        </div>
      );
    }
    return this.props.children;
  }
}
import AnalystNarrativePanel from "@/components/investigation/AnalystNarrativePanel";
// ▲ P0d-A (2026-02-09) — Mount the 9-card Deterministic Analyst Brief
// (Executive Summary, Analyst Summary, Observed Behaviour, Attack
// Intent, Impact, MITRE, IOC Intelligence, Recommendations, Evidence
// Confidence) directly in Prev-Mode WorkspacePage.  Previously the
// panel was only reachable via InvestigationSessionGateway, which
// gates on `acquired_document.ok`; that meant Analyst-Paste URL
// investigations never surfaced the brief even though the backend
// (P0a + P0b + P0c-A) populates `summary_narrative`.
import InvestigationSummaryPanel from "@/components/investigation/InvestigationSummaryPanel";
import CollapsibleCard from "@/components/investigation/CollapsibleCard";
// Phase 5.W permanent fix · P0.b (2026-08-11) — isolate render crashes
// to the panel that owns them so a bad shape in one panel does not
// take the whole Workspace tab down.
import PanelErrorBoundary from "@/components/PanelErrorBoundary";
import TimelinePanel from "@/components/investigation/TimelinePanel";
import QueryHuntPanel from "@/components/investigation/QueryHuntPanel";
import { InvestigationFilterProvider, InvestigationFilterBar } from "@/components/investigation/InvestigationFilter";
import { runClientRecipe } from "@/lib/clientOps";
import { magicLite } from "@/lib/magicLite";
import { detectShellcode } from "@/lib/shellcodeDetect";
import { buildFallbackGraph } from "@/lib/fallbackGraph"; // eslint-disable-line no-unused-vars
import { selectCanonicalOutput } from "@/lib/selectCanonicalOutput";
import { mergeIocs } from "@/lib/mergeIocs";
import { useIdlePersist } from "@/hooks/useIdlePersist";
import GuidanceBanner, { getGuidanceGlowStyle } from "@/components/GuidanceBanner";
import SocVerdictPanel from "@/components/SocVerdictPanel";import VerdictCard from "@/components/VerdictCard";
import SemanticIntelligencePanel from "@/components/investigation/SemanticIntelligencePanel";
import InvestigationBrainPanel from "@/components/investigation/InvestigationBrainPanel";
import OpenInvestigationButton from "@/workspace_v4/OpenInvestigationButton";
import AnalystQuickActions from "@/components/AnalystQuickActions";
import AnalystResults from "@/components/AnalystResults";
import DecodingTracePanel from "@/components/DecodingTracePanel";
import IEDDEDecisionTrace from "@/components/IEDDEDecisionTrace";
import RecoveryStatusRibbon from "@/components/RecoveryStatusRibbon";
import PEAnalysisPanel from "@/components/PEAnalysisPanel";
import ArtifactAnalysisPanel from "@/components/ArtifactAnalysisPanel";
// Phase 4 · P2.1 (2026-02-15) — Workspace-native "Find Related Cases".
import FindRelatedDrawer from "@/components/investigation/FindRelatedDrawer";
import HistoryDrawer from "@/components/HistoryDrawer";
import CasesDrawer from "@/components/CasesDrawer";
import ProcessTreeView from "@/components/ProcessTreeView";
import BoostBadge from "@/components/BoostBadge";
import ChainStageEditor from "@/components/ChainStageEditor";
import ChainReplayView from "@/components/ChainReplayView";
import CandidateExplorer from "@/components/CandidateExplorer";
import BadDecodeModal from "@/components/BadDecodeModal";
import EscalationLadder from "@/components/EscalationLadder";
import TIShieldPanel from "@/components/TIShieldPanel";
import MoEPanel from "@/components/MoEPanel";
import InvestigationTimeline from "@/components/InvestigationTimeline";
import api, { beginRestoreMode, endRestoreMode, callLlmGracefully, LLM_INPUT_BUDGET } from "@/lib/api";
import { streamAnalyze } from "@/lib/sse";
import { splitCommandLines, isMultiCommandInput } from "@/lib/commandSplitter";
import InputToolbar from "@/components/InputToolbar";
import CorrectionRefineModal from "@/components/CorrectionRefineModal";
import {
  Play, Zap, Wand2, Wrench, Share2, Download, Upload, Trash2, Copy, Sparkles, X, LayoutGrid,
} from "lucide-react";

/**
 * FU-5 · v1.4.3 · Feature-flag hide of legacy verdict surfaces
 * ---------------------------------------------------------------
 * The Investigation Brain (IU → CRE → RTE → Intent → Behavior Graph →
 * Verdict → Evidence Graph → Analyst Report) is the SOLE analyst-facing
 * verdict authority as of v1.3.0. Prior to v1.4.3, several legacy
 * verdict-producing panels still rendered on the workspace and could
 * emit conflicting verdicts (e.g. "Suspicious 45" while the Brain said
 * "Malicious 90"), destroying analyst trust.
 *
 * This flag GATES (not removes) those panels so we can toggle them back
 * if a hidden runtime dependency is discovered during the v1.4.x
 * stabilization cycle. Actual code removal is scheduled for v1.5.x
 * after one stable release with no regressions.
 *
 * Panels gated by this flag:
 *   1. SocVerdictPanel        — client-side shellcode "one-line verdict"
 *   2. AnalystQuickActions    — synthesises verdict from legacy verdictCard
 *   3. AnalystResults         — 7-panel legacy analyst view (rc2-orchestrator)
 *   4. SemanticIntelligencePanel — legacy "Behavior Storyline" verdict
 *   5. FinalSummary           — "NIVXRAY — FINAL INVESTIGATION SUMMARY" card
 *
 * NOT gated (analyst-facing, non-verdict): decoded output, IOC enrichment,
 * attack graph, kill-chain path, escalation ladder, TI shield, process tree,
 * threat analysis panel, IR handoff / refine strips.
 */
const SHOW_LEGACY_INVESTIGATION_SUMMARY = false;

// ══════════════════════════════════════════════════════════════════
// Synthesise a `preprocessor.stages` bundle from ICE behavior
// clusters so the swim-lane Trajectory view renders for URL
// investigations too.  Rule R16: this is pure projection — the
// underlying data lives in SSOT.ice; we just re-shape it into the
// stage envelope TrajectoryDiagram already understands.
// ══════════════════════════════════════════════════════════════════
const _ICE_TACTIC_LABEL = {
  initial_access:       "Initial Access",
  execution:            "Execution",
  persistence:          "Persistence",
  privilege_escalation: "Privilege Escalation",
  defense_evasion:      "Defense Evasion",
  credential_access:    "Credential Access",
  discovery:            "Discovery",
  lateral_movement:     "Lateral Movement",
  collection:           "Collection",
  command_and_control:  "Command and Control",
  exfiltration:         "Exfiltration",
  impact:               "Impact",
};

function _synthPreprocFromIce(ice) {
  const clusters = ice?.behavior_clusters || [];
  if (!clusters.length) return null;
  const stages = clusters.map((c, i) => ({
    id:              `ice-stage-${i}`,
    title:           c.label,
    tactic:          _ICE_TACTIC_LABEL[c.primary_tactic] || "Execution",
    mitre:           (c.mitre || []).map(m => m.id),
    command_family:  c.label,
    kind:            "behavior_cluster",
    confidence:      c.confidence === "high"   ? 0.95
                   : c.confidence === "medium" ? 0.7
                   :                             0.4,
  }));
  return { stages, process_edges: [] };
}


// ══════════════════════════════════════════════════════════════════
// 2026-08-11 · TrajectoryDiagram lane-assignment fix
// ──────────────────────────────────────────────────────────────────
// Owner directive: "Change lane assignment so that, where MITRE
// technique/tactic evidence exists, the node is placed according to
// the existing backend MITRE tactic mapping."  This is a display-
// only projection — it re-shapes `object.mitre[]` (which already
// carries the correct per-technique tactic assigned by the backend)
// into the `behaviors[]` shape TrajectoryDiagram's canonical 14-lane
// MITRE ATT&CK view already understands.  No new mapping algorithm,
// no new backend logic, no change to the investigation payload
// contract.  Guarded: only kicks in when the CSV/prose path leaves
// `incident.behaviors` and `ice.behavior_clusters` empty.
// ══════════════════════════════════════════════════════════════════
// ▲ UX-FIX (2026-02-09) · LolbasTab crash guard — the sidebar
// LolbasTab does `l.purposes.map(...)` and `l.mitre.map(...)` with
// no guard.  SSOT lolbas entries use {binary, legit, abuse, mitre,
// detection} shape while the sidebar expects {binary, purposes,
// mitre, description, snippet, url}.  Normalize once at the lift
// boundary so every consumer sees the same defensive shape.
function _normalizeLolbas(list) {
  if (!Array.isArray(list)) return [];
  return list.map((raw) => {
    const l = (raw && typeof raw === "object") ? raw : {};
    const purposes = Array.isArray(l.purposes) ? l.purposes
                    : (l.abuse ? [l.abuse] : (l.legit ? [l.legit] : []));
    return {
      binary:      l.binary || "",
      purposes:    purposes,
      mitre:       Array.isArray(l.mitre) ? l.mitre : [],
      description: l.description || l.legit || l.abuse || "",
      snippet:     l.snippet || "",
      url:         l.url || "",
      custom:      !!l.custom,
      model_id:    l.model_id || null,
      model_name:  l.model_name || null,
      // Preserve original SSOT fields so downstream projections still
      // have access if they need them.
      legit:       l.legit || "",
      abuse:       l.abuse || "",
      detection:   Array.isArray(l.detection) ? l.detection : [],
    };
  });
}



function _synthBehaviorsFromMitre(mitreList) {
  if (!Array.isArray(mitreList) || !mitreList.length) return [];
  // ▲ UX-FIX (2026-02-09) — Trajectory-diagram main-thread freeze on
  // XDR/vendor-report pastes (Chrome "Page Unresponsive · Wait/Exit"
  // dialog).  When yesterday's projection enrichment populates
  // `obj.mitre` with 60-100+ techniques for a single vendor report,
  // `TrajectoryDiagram`'s SVG layout algorithm (O(N²) edge routing +
  // per-node reflow) blocks the JS thread for 15+ seconds.
  //
  // Fix: cap at TRAJECTORY_MAX (60 = 12 ATT&CK tactics × 5 techniques
  // per lane average — well above any real single-incident chain,
  // well below the render-storm threshold).  Deterministic sort:
  // preserve the extractor's original emission order so the first-N
  // are the earliest-observed techniques.  Truncated list is still
  // fully deterministic and reproducible.
  const TRAJECTORY_MAX = 60;
  const source = mitreList.length > TRAJECTORY_MAX
    ? mitreList.slice(0, TRAJECTORY_MAX)
    : mitreList;
  const behaviors = [];
  source.forEach((t, i) => {
    if (!t || typeof t !== "object") return;
    const tid   = t.id;
    const name  = t.name || "";
    const tactic = t.tactic || (Array.isArray(t.tactics) && t.tactics[0]) || null;
    if (!tid || !tactic) return;
    // Title-case the tactic so the canonical MITRE_LANES switch in
    // TrajectoryDiagram matches without further remapping.
    const label = String(tactic)
      .replace(/[_-]+/g, " ")
      .replace(/\b\w/g, ch => ch.toUpperCase());
    behaviors.push({
      id:              `mitre-behavior-${tid}-${i}`,
      title:           `${tid}${name ? " · " + name : ""}`,
      mitre_tactics:   [label],
      mitre:           [{ id: tid, tactic: label }],
      primary_tactic:  label,
      confidence:      "medium",
      order:           i,
      kind:            "mitre_technique_projection",
    });
  });
  return behaviors;
}


// Inner render — heavy tree, wrapped by WorkspacePage in the error boundary.
function WorkspacePageInner() {
  // ▲ 2026-02-28 · P0 Persistence — restore the last completed
  // Workspace session (input, output, and all generated panels) so
  // that navigating away and coming back does NOT lose the analyst's
  // work.  Cleared only when the CLEAR button is pressed.
  //
  // ▲ 2026-08-07 · User Request — a browser REFRESH (F5 / Cmd+R /
  // Cmd+Shift+R) must behave EXACTLY like clicking CLEAR: wipe the
  // input, output, and every generated panel.  This gives analysts a
  // guaranteed clean slate on refresh without touching cross-tab
  // navigation.  Detection uses the Navigation Timing API — the
  // ``type`` field is "reload" on every browser refresh regardless
  // of soft (F5) vs hard (Cmd+Shift+R), while remaining "navigate"
  // for URL entry, link click, and back/forward-restore.
  const _pageWasReloaded = (() => {
    try {
      const nav = (window.performance || {}).getEntriesByType
        ? window.performance.getEntriesByType("navigation")
        : [];
      if (nav && nav.length && nav[0].type === "reload") return true;
      // Fallback for older browsers that still expose PerformanceNavigation
      const legacy = (window.performance || {}).navigation;
      // 1 === TYPE_RELOAD in the deprecated PerformanceNavigation API.
      if (legacy && legacy.type === 1) return true;
    } catch { /* ignore — treat as fresh navigation */ }
    return false;
  })();

  const _persisted = (() => {
    if (_pageWasReloaded) {
      // Reload → THIS tab starts empty.  We deliberately do NOT delete
      // any localStorage keys here — localStorage is shared across every
      // tab of the same origin, and wiping it on reload would clear
      // OTHER open Workspace tabs whose state is untouched.  Skipping
      // the restore is enough to give this tab a clean slate; other
      // tabs keep their data, and if the user navigates away from this
      // tab and back (or opens another new tab), the shared persist
      // will still be there.
      return {};
    }
    try {
      const raw = localStorage.getItem("nvx.workspace.persist");
      if (!raw) return {};
      // 2026-02-15 · Anti-hang fix — cap the mount-time JSON.parse.
      // Real-world sessions with a large decoded output + AI narrative
      // + investigation object can push this blob past 1 MB.  Parsing
      // >500 KB synchronously on first paint delays the workspace by
      // multiple seconds.  Drop the persisted state above the cap;
      // the user can re-run the last investigation in one click.
      if (raw.length > 500_000) {
        try { localStorage.removeItem("nvx.workspace.persist"); } catch {}
        return {};
      }
      const p = JSON.parse(raw);
      return (p && typeof p === "object") ? p : {};
    } catch { return {}; }
  })();

  const [ops, setOps] = useState([]);
  const [examples, setExamples] = useState([]);
  const [input, setInput] = useState(() => {
    if (_pageWasReloaded) return "";
    // Restore last input if a session expired mid-decode (see api.js 401 interceptor)
    try {
      const saved = localStorage.getItem("nvx_last_input");
      if (saved) {
        localStorage.removeItem("nvx_last_input");
        return saved;
      }
    } catch (_) {}
    // Fall back to the persisted Workspace session.
    return _persisted.input || "";
  });
  // Deferred copy of `input` (2026-08-11) — Timeline / Query panels
  // consume this instead of the raw state so a large-paste doesn't
  // cascade into synchronous re-fetches while the browser is still
  // committing the textarea update.  React yields between the
  // urgent (textarea) and non-urgent (panel) work.
  const deferredInput = useDeferredValue(input);
  const [output, setOutput] = useState(() => _pageWasReloaded ? "" : (_persisted.output || ""));
  const [steps, setSteps] = useState([]);
  const [detected, setDetected] = useState(null);
  const [chain, setChain] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [status, setStatus] = useState("READY");
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [shareUrl, setShareUrl] = useState("");
  const [tacticFilter, setTacticFilter] = useState(null); // P3: click-to-filter
  const [graphView, setGraphView] = useState("path"); // eslint-disable-line no-unused-vars
  const [personas, setPersonas] = useState([]);
  const [providers, setProviders] = useState([]);
  const [personaId, setPersonaId] = useState("");
  const [providerId, setProviderId] = useState("");
  const [magicResults, setMagicResults] = useState(null);
  const [showMagic, setShowMagic] = useState(false);
  const [shellcodeFlag, setShellcodeFlag] = useState(false);
  // Winner metadata from AI Decode / Auto Investigate — feeds the SOC Verdict panel
  const [decodeConfidence, setDecodeConfidence] = useState(null);
  const [decodeWinnerEngine, setDecodeWinnerEngine] = useState(null);
  // ▲ SOC Verdict Card — evidence-driven, backend-computed (Feb-2026)
  const [verdictCard, setVerdictCard] = useState(null);
  // Corrupted-container signal — big-red panel when the decoder refuses to
  // brute-force inside a corrupt GZIP / ZLIB / LZMA / BZIP2 archive.
  const [corruptedContainer, setCorruptedContainer] = useState(null);
  // Decoding Trace panel — per-layer intermediate outputs from the deterministic decoder
  const [decodeTrace, setDecodeTrace] = useState([]);
  // R28.C · Artifact Trace projection surfaced on SSOT restore
  // (Artifact → Recognizer → Capability → Evidence → Child).
  const [artifactTrace, setArtifactTrace] = useState([]);
  const [reachedShellcode, setReachedShellcode] = useState(false);
  // Client-side auto-detect on paste — 14 decoders raced instantly to surface a suggestion
  const [pasteHint, setPasteHint] = useState(null);
  // Feb-2026: Server-side Smart Input Advisor (planner) hint — real-time layer detection
  const [plannerHint, setPlannerHint] = useState(null);
  // History drawer
  const [historyOpen, setHistoryOpen] = useState(false);
  const [casesOpen, setCasesOpen] = useState(false);
  // Feb-2026: Candidate Explorer toggle — shows the ranked encoding candidates
  // + structured why-not breakdown from /api/decode/candidates.
  const [showCandidateExplorer, setShowCandidateExplorer] = useState(false);
  // Feb-2026 P2: Mixture-of-Experts (MoE) Analyst Panel toggle
  const [showMoePanel, setShowMoePanel] = useState(false);
  // Predicted process tree (fed to both ProcessTreeView + SocVerdictPanel mini)
  const [predictedTree, setPredictedTree] = useState(null);
  // Phase 9.4 · Semantic Intelligence — mirrors Auto-Investigate contract so
  // the Workspace surfaces the SAME recursive deobfuscation +
  // Behavior Storyline + Semantic panels as /auto-investigate.
  const [semantic, setSemantic] = useState(null);
  // Phase 4 · Unified Investigation Brain payload (IU → CRE → RTE → Intent)
  const [investigation, setInvestigation] = useState(null);
  // Learning Feedback Loop
  const [boost, setBoost] = useState(null);
  const [boostHit, setBoostHit] = useState(false);
  // ▲ IEDDE SSOT (Priority 1/2/3 · 2026-02) — decision trace + canonical
  // recovery signals surfaced from /api/decode/smart and /api/analyze/async.
  const [iedde, setIedde] = useState(null);  const [iddeTerminalState, setIeddeTerminalState] = useState(null);
  const [canonicalConfidence, setCanonicalConfidence] = useState(null);
  const [canonicalConfidenceReason, setCanonicalConfidenceReason] = useState(null);
  const [ieddeDiagnostics, setIeddeDiagnostics] = useState([]);
  // ONE-BUTTON UX — collapse Smart/AI/Auto Investigate/Troubleshoot into ADVANCED
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [chainOpen, setChainOpen] = useState(false);
  // Chain replay — read-only viewer for a rehydrated multi-stage history record
  const [chainReplay, setChainReplay] = useState(null); // full history record with kind === "chain"
  // Pending stage seed for ChainStageEditor after user chooses to restore a saved chain
  const [pendingChainStages, setPendingChainStages] = useState(null);
  // Feb-2026 fix: parent-supplied chain result forwarded to ChainStageEditor
  // so RE-RUN buttons and break-ribbons render immediately after
  // auto-investigate (fixes iteration-11 gating issue).
  const [pendingChainResult, setPendingChainResult] = useState(null);
  const [chainEditorKey, setChainEditorKey] = useState(0); // force remount when initialStages change
  // Feb-2026 Enhancements: input lock (edit toggle) + multi-command auto-route toast
  const [inputLocked, setInputLocked] = useState(false);
  // ▲ 2026-02-28 · P0 · Input Understanding Engine (IUE).  Populated on
  // every analyze() so the analyst sees WHAT the paste is and WHY we
  // are running each engine, before results land.
  const [understanding, setUnderstanding] = useState(() => _persisted.understanding || null);
  const [understandingLoading, setUnderstandingLoading] = useState(false);
  const [understandingError, setUnderstandingError] = useState(null);
  // R28.10 · Graceful "skipped" state — the LLM Input-Understanding
  // call is OPTIONAL; when it is skipped (large input) or fails (timeout,
  // budget) we surface a friendly muted panel instead of the red
  // "REQUEST FAILED" banner and let the deterministic path run to
  // completion regardless.
  const [understandingSkipReason, setUnderstandingSkipReason] = useState("");
  // Inline Attack Story feed — preprocessor stages come back inside
  // the DIE analyze envelope when the input is mixed / prose / chain.
  const [inlineStoryPreproc, setInlineStoryPreproc] = useState(() => _persisted.inlineStoryPreproc || null);
  // Deterministic Analyst Narrative — Executive Summary, Sigma / YARA
  // ideas, Analyst Summary, Threat Actor Context and Recommended
  // Actions.  Zero LLM, template-driven from preprocessor stages.
  const [analystNarrative, setAnalystNarrative] = useState(() => _persisted.analystNarrative || null);
  // ── IUE v2.0 · Investigation Results (2026-03-01) ─────────────
  // When the IUE decides no decoding is required, the OUTPUT pane
  // (renamed "INVESTIGATION RESULTS") is populated with the
  // deterministic investigation-results text from
  // /api/die/investigation-results.  The pane never echoes the
  // input; it always presents structured findings.  See
  // /app/memory/IUE_ARCHITECTURE_V2.md for the frozen contract.
  const [investigationMode, setInvestigationMode] = useState(() => !!_persisted.investigationMode);
  const [investigationObject, setInvestigationObject] = useState(() => _persisted.investigationObject || null);
  // ▲ P0d-A (2026-02-09) — Session snapshot for the Deterministic
  // Analyst Brief.  Populated by /api/session/from-investigation
  // whenever `investigationObject` acquires meaningful evidence
  // (IOCs, commands, artifacts, or an acquired document).  Feeds
  // `summary_narrative` directly to InvestigationSummaryPanel so
  // Prev-Mode paste surfaces the 9-card brief without requiring
  // navigation to /workspace/session/:id.
  const [sessionSnapshot, setSessionSnapshot] = useState(null);
  // ▲ P0.15C · VEEE Acquisition Summary + Jump-to-Source (2026-02-09)
  //   Both fields are attached by the backend on GET /cases/{id} as an
  //   ADDITIVE read-only projection.  Live investigation flows leave
  //   them null → the panels render nothing (byte-identical to legacy).
  const [acquisitionSummary,     setAcquisitionSummary]     = useState(null);
  const [acquisitionOcrRecords,  setAcquisitionOcrRecords]  = useState([]);
  const [multiChainNotice, setMultiChainNotice] = useState(null);   // { stages, verdict, family }
  // Feb-2026 · once a case has been named+saved, subsequent SAVE clicks
  // silently upsert under the same name (no prompt). Reset when the input
  // is materially cleared (user starts a new investigation).
  const [savedCaseName, setSavedCaseName] = useState(null);
  // ▲ Phase 4 · P2.1 (2026-02-15) — Workspace-native "Find Related Cases".
  //   currentCaseId is set on restore-from-history and after a successful
  //   /cases/save (via input_hash lookup). The drawer stays disabled with
  //   a helpful tooltip until an ID is available so the correlation flow
  //   can only run against a persisted case.
  const [currentCaseId, setCurrentCaseId] = useState(null);
  const [findRelatedOpen, setFindRelatedOpen] = useState(false);
  // Feb-2026: analyst-corrections launcher state.
  const [refineOpen, setRefineOpen] = useState(false);
  const [refineCtx, setRefineCtx] = useState(null); // { surface, wrong_finding }
  const openRefine = (surface, wrongFinding) => {
    setRefineCtx({ surface, wrong_finding: wrongFinding });
    setRefineOpen(true);
  };

  // RC3.1 · IR Handoff Export — download the analyst brief in the
  // requested format. Re-runs the deterministic orchestrator so the
  // downloaded artefact always matches what the analyst sees on screen.
  const downloadHandoff = async (fmt) => {
    try {
      const axios = (await import("axios")).default;
      const src = (input || "").trim();
      if (!src) {
        alert("Nothing to export — decode an input first.");
        return;
      }
      const token = localStorage.getItem("nvx_token");
      const r = await axios.post(
        `${process.env.REACT_APP_BACKEND_URL}/api/v2/analyze/report?fmt=${encodeURIComponent(fmt)}`,
        { input: src },
        {
          responseType: "blob",
          timeout: 45_000,
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        },
      );
      const ext = fmt === "md" ? "md"
        : fmt === "pdf" ? "pdf"
        : fmt === "json" ? "json"
        : fmt === "stix" ? "stix.json"
        : "txt";
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const blob = new Blob([r.data], {
        type: r.headers?.["content-type"] || "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `nivxray-analyst-report-${stamp}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Handoff export failed: ${err?.response?.status || err?.message || err}`);
    }
  };
  const [nivxrayTrace, setNivxrayTrace] = useState([]);
  // v1.4.2 · Report Bad Decode + Enrich IOCs
  const [badDecodeOpen, setBadDecodeOpen] = useState(false);
  const [iocEnrichment, setIocEnrichment] = useState(null);
  const [enrichingIocs, setEnrichingIocs] = useState(false);
  const enrichIocs = async () => {
    if (!analysis?.iocs) return;
    const values = [];
    Object.values(analysis.iocs).forEach((v) => {
      if (Array.isArray(v)) v.forEach((x) => { if (typeof x === "string") values.push(x); });
    });
    if (values.length === 0) return;
    setEnrichingIocs(true);
    try {
      const axios = (await import("axios")).default;
      const API = process.env.REACT_APP_BACKEND_URL + "/api";
      const token = localStorage.getItem("nvx_token");
      const r = await axios.post(
        `${API}/threat-intel/enrich-batch`,
        { values: values.slice(0, 25) },
        { headers: token ? { Authorization: `Bearer ${token}` } : {} },
      );
      // Reshape to the pill format (v1.5.3 · full osint.enrich_iocs)
      const out = (r.data?.results || []).map((row) => ({
        value:            row.value || row.ioc || "",
        kind:             row.kind || "",
        malicious_score:  row.malicious_score || 0,
        abuse_confidence: row.abuse_confidence || 0,
        otx_pulses:       row.otx_pulses || 0,
        providers:        row.providers || {},
      }));
      setIocEnrichment(out);
    } catch (e) {
      setIocEnrichment([{ value: "enrichment failed: " + (e?.message || "unknown") }]);
    } finally {
      setEnrichingIocs(false);
    }
  };
  // Track whether the analyst has unsaved work in the current workspace so
  // rehydrating from history can prompt before overwriting.
  const hasUnsavedWork = () => !!(
    (input && input.trim()) ||
    (output && output.trim()) ||
    (steps && steps.length > 0)
  );
  const rehydrateFromHistory = async (rec) => {
    if (!rec) return;
    // Chain records — default UX is read-only viewer, RESTORE button transitions
    // into editing after unsaved-changes confirmation.
    if (rec.kind === "chain") {
      setChainReplay(rec);
      setHistoryOpen(false);
      setStatus(`▸ CHAIN REPLAY (${rec.stage_count || (rec.stages || []).length} stages · read-only)`);
      // Scroll the replay into view after render, offset for the sticky header
      setTimeout(() => {
        try {
          const el = document.querySelector('[data-testid="chain-replay-view"]');
          if (el) {
            const rect = el.getBoundingClientRect();
            const HEADER = 90; // brut-border top header + toolbar strip
            window.scrollTo({ top: rect.top + window.scrollY - HEADER, behavior: "smooth" });
          }
        } catch {}
      }, 60);
      return;
    }
    if (hasUnsavedWork() &&
        !window.confirm("You have unsaved work in the current workspace. Restore this investigation and overwrite it?")) {
      setHistoryOpen(false);
      return;
    }
    // ▲ SOC Verdict Card (Feb-2026) — fetch the full history doc so we get
    // the freshly-computed verdict_card + per-layer evidence on rehydrate.
    // The list endpoint only carries lightweight preview fields.
    let full = rec;
    if (rec.id && !rec.verdict_card) {
      try {
        const r = await api.get(`/history/${rec.id}`);
        full = { ...rec, ...r.data };
      } catch (_) {
        // fall back to the list record — restore still works, verdict just
        // won't render for this rehydrate.
      }
    }
    // ▲ Skip the client-side live-preview one shot so it doesn't
    // overwrite the properly-decoded output we just restored from
    // history (matters when the payload is a PE binary or the client
    // recipe would silently mangle non-ASCII bytes).
    skipLivePreviewRef.current = true;
    const _inp = full.input || full.input_preview || "";
    const _out = full.output || full.output_preview || "";
    // Feb 2026 — detect "OUTPUT == INPUT" (case saved before AUTO-INVESTIGATE
    // ran) and auto-fire a re-investigate so the analyst never sees a
    // silent echo. Uses the permissive comparator that ignores the
    // DECODED-OUTPUT header the backend prepends.
    const cleanedOut = _out.replace(/^━+\s*▼ DECODED OUTPUT\s*━+\s*/i, "").trim();
    const isEcho = _inp && cleanedOut && cleanedOut === _inp.trim();
    setInput(_inp);
    setOutput(_out);
    setDecodeTrace(full.trace || []);
    setDecodeWinnerEngine(full.engine || null);
    setDecodeConfidence(full.confidence ?? null);
    setVerdictCard(full.verdict_card || null);
    setCorruptedContainer(full.corrupted_container || null);
    setReachedShellcode(!!full.reached_shellcode);
    // ▲ IEDDE SSOT rehydrate (2026-02 · Priority 1/2/3) — restores the
    // Recovery Status ribbon + IEDDE Decision Trace panel so the analyst
    // lands on exactly the state the previous investigation ended in.
    setIedde(full.iedde || null);
    setIeddeTerminalState(full.iedde_terminal_state || null);
    setCanonicalConfidence(
      typeof full.canonical_confidence === "number" ? full.canonical_confidence : null,
    );
    setCanonicalConfidenceReason(full.canonical_confidence_reason || null);
    setSteps((full.chain || []).map((op) => ({ op: (typeof op === "string" ? op : op.op), args: {} })));
    setChain((full.chain || []).map((op, i) => ({
      op: (typeof op === "string" ? op : op.op),
      reason: full.trace?.[i]?.reason || "",
      output_preview: full.trace?.[i]?.output_preview || "",
    })));
    setAnalysis({ iocs: rec.iocs || {}, mitre: rec.mitre || [], ai_verdict: rec.verdict });
    // Feb 2026 — restore the friendly case name so the workspace pill
    // (💾 CASE · <name>) reappears and subsequent SAVE upserts the same case.
    if (full.case_name) setSavedCaseName(full.case_name);
    else setSavedCaseName(null);
    // ▲ Phase 4 · P2.1 (2026-02-15) — track the current case id so the
    // Workspace "Find Related Cases" button can seed the correlation
    // drawer without a redirect through HistoryPage.
    if (full.id || rec.id) setCurrentCaseId(String(full.id || rec.id));
    setStatus(
      isEcho
        ? `▲ OUTPUT=INPUT · "${full.case_name || "case"}" was saved before decode — click AUTO INVESTIGATE to peel it`
        : (full.case_name
            ? `▸ RESTORED "${full.case_name}" (${rec.engine} · ${rec.confidence}%)`
            : `▸ RESTORED FROM HISTORY (${rec.engine} · ${rec.confidence}%)`)
    );
    setHistoryOpen(false);
    // ▲ IUE v2.0 · Rehydrate the IUE + Attack Story + Trajectory +
    // Analyst Narrative for restored history records so Prev Mode is
    // indistinguishable from a fresh AUTO INVESTIGATE.  Also flip the
    // OUTPUT pane into INVESTIGATION RESULTS mode whenever the IUE
    // says no decoding was required.
    //
    // ── Feb 2026 P0 · Full SSOT rehydration (no recomputation) ──
    // When the history record carries a full SSOT bundle (either from a
    // linked workspace_case, or because the future /history endpoint
    // shipped one), we rehydrate every workspace panel deterministically
    // and skip the three /die/* re-fires below.
    const _ssot = full.ssot;
    if (_inp.trim() && _ssot && typeof _ssot === "object") {
      // R28 · Restore is Rendering — gate the /die/* firewall.
      beginRestoreMode(`history:${full.case_name || full.id}`);
      try {
        setUnderstanding(_ssot.understanding || null);
        setUnderstandingLoading(false);
        setUnderstandingError(null);
        setInlineStoryPreproc(_ssot.inline_story_preproc || null);
        setAnalystNarrative(_ssot.analyst_narrative || null);
        setInvestigationObject(_ssot.investigation_object || null);
        setInvestigationMode(!!_ssot.investigation_mode);
        setArtifactTrace(full.artifact_trace || []);
        if (_ssot.semantic !== undefined) setSemantic(_ssot.semantic);
        if (_ssot.predicted_tree !== undefined) setPredictedTree(_ssot.predicted_tree);
      } finally {
        setTimeout(() => endRestoreMode(), 0);
      }
    } else if (_inp.trim()) {
      setUnderstanding(null);
      setUnderstandingError(null);
      setUnderstandingSkipReason("");
      setUnderstandingLoading(true);
      setInlineStoryPreproc(null);
      setAnalystNarrative(null);
      setInvestigationMode(false);
      setInvestigationObject(null);
      // ── R28.10 · ARCHITECTURAL SEPARATION ────────────────────
      // The deterministic Investigation Results MUST run to completion
      // regardless of whether the LLM-backed /die/understand succeeds,
      // times out, or is skipped for size.  Fire it in parallel — never
      // gate it on the AI narration.
      runInvestigationResults(_inp);
      callLlmGracefully("/die/understand", { input: _inp, execute: true }, {
        budgetBytes: LLM_INPUT_BUDGET.understand,
      }).then((res) => {
        if (res.ok) {
          setUnderstanding(res.data?.understanding || null);
        } else {
          setUnderstandingSkipReason(res.reason || "");
        }
        setUnderstandingLoading(false);
      });
      callLlmGracefully("/die/analyze", { input: _inp }, {
        budgetBytes: LLM_INPUT_BUDGET.analyze,
      }).then((res) => {
        if (!res.ok) return;
        const pre = res.data?.result?.preprocessor
                 || res.data?.result?.chain?.preprocessor
                 || null;
        if (pre) setInlineStoryPreproc(pre);
      });
      callLlmGracefully("/die/narrate", { input: _inp }, {
        budgetBytes: LLM_INPUT_BUDGET.narrate,
      }).then((res) => {
        if (res.ok) setAnalystNarrative(res.data?.narrative || null);
      });
    }
    // Auto-fire re-investigate for echo cases so the analyst never
    // stares at a raw base64 blob wondering what to do.
    if (isEcho) {
      setTimeout(() => autoInvestigate(), 400);
    }
  };

  // Move a saved chain from the read-only replay viewer into the editable
  // ChainStageEditor. Prompts to confirm if there's unsaved single-stage work.
  const restoreChainToWorkspace = () => {
    if (!chainReplay) return;
    if (hasUnsavedWork() &&
        !window.confirm("You have unsaved work in the current workspace. Restore this chain and overwrite it?")) {
      return;
    }
    const stages = (chainReplay.stages || []).map((s) => ({
      input: s.input_preview || s.input || "",
    }));
    // Reset single-stage state (chain will own the workspace now)
    setInput("");
    setOutput("");
    setSteps([]);
    setChain([]);
    setAnalysis(null);
    setDecodeTrace([]);
    setDecodeWinnerEngine(null);
    setDecodeConfidence(null);
    setVerdictCard(null);
    setCorruptedContainer(null);
    setReachedShellcode(false);
    setPendingChainStages(stages);
    setChainEditorKey((k) => k + 1);
    setChainOpen(true);
    setChainReplay(null);
    setStatus(`▸ CHAIN RESTORED TO WORKSPACE · ${stages.length} stages ready to re-run`);
  };
  const isShellcodeClient = useMemo(() => !!detectShellcode(output || ""), [output]);
  const streamStopRef = useRef(null);
  const fileRef = useRef(null);
  // Phase 5.W.2 — Shared AbortController for the current workspace API
  // request (upload, investigate, decode, etc.).  CLEAR aborts it to
  // prevent stale responses from repopulating the workspace after wipe.
  const workspaceAbortRef = useRef(null);

  // ▲ Global HISTORY restore hook (2026-02 · Nav Consolidation).
  //   • Listens for `nvx:open-history` events (legacy in-page HISTORY btn).
  //   • On mount, checks `nvx_restore_history_id` — set by HistoryPage
  //     when the user clicks RESTORE — and rehydrates that case so the
  //     analyst lands on the full previous investigation.
  useEffect(() => {
    const onOpen = () => setHistoryOpen(true);
    window.addEventListener("nvx:open-history", onOpen);
    try {
      if (window.sessionStorage.getItem("nvx_open_history") === "1") {
        window.sessionStorage.removeItem("nvx_open_history");
        setHistoryOpen(true);
      }
      const restoreId = window.sessionStorage.getItem("nvx_restore_history_id");
      if (restoreId) {
        window.sessionStorage.removeItem("nvx_restore_history_id");
        (async () => {
          try {
            const r = await api.get(`/history/${restoreId}`);
            if (r.data && r.data.id) rehydrateFromHistory(r.data);
          } catch (_e) { /* noop — record may have TTL-expired */ }
        })();
      }
    } catch { /* noop */ }
    return () => window.removeEventListener("nvx:open-history", onOpen);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ▲ P0d-A (2026-02-09) — Auto-mint the Investigation Session
  // whenever `investigationObject` acquires meaningful evidence.
  // The response carries `summary_narrative` (backend, deterministic,
  // zero LLM) which drives the 9-card InvestigationSummaryPanel
  // (Executive Summary, IOC Intelligence, Evidence Confidence, …).
  //
  // Scope: additive, Prev-Mode surface only.  When Analyst-Paste has
  // no evidence at all we intentionally skip the call so the panel
  // simply doesn't render (identical to legacy behaviour).  This
  // does NOT change InvestigationSessionGateway's own mint logic —
  // gateway keeps rendering as-is when `acquired_document.ok`.
  useEffect(() => {
    const inv = investigationObject;
    if (!inv) {
      setSessionSnapshot(null);
      return;
    }
    const hasEvidence =
         !!inv?.acquired_document?.ok
      || (Array.isArray(inv?.commands) && inv.commands.length > 0)
      || (Array.isArray(inv?.artifacts) && inv.artifacts.length > 0)
      || (inv?.incident?.iocs && Array.isArray(inv.incident.iocs) && inv.incident.iocs.length > 0)
      || (inv?.report_extraction?.body_artifacts
          && Array.isArray(inv.report_extraction.body_artifacts)
          && inv.report_extraction.body_artifacts.length > 0)
      // Atomic-IOC / prose paths (e.g. Analyst-Paste URL routed to IOC lane)
      // land the extracted IOCs at the TOP level of the canonical object.
      // Any populated bucket (url / domain / ip / hash / …) counts as evidence.
      || (inv?.iocs && typeof inv.iocs === "object"
          && Object.values(inv.iocs).some(v => Array.isArray(v) && v.length > 0));
    if (!hasEvidence) {
      setSessionSnapshot(null);
      return;
    }
    let alive = true;
    (async () => {
      try {
        const { data } = await api.post("/session/from-investigation", {
          input, investigation: inv,
        });
        if (alive) setSessionSnapshot(data?.session || null);
      } catch {
        if (alive) setSessionSnapshot(null);
      }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigationObject]);

  useEffect(() => {
    api.get("/operations").then((r) => setOps(r.data)).catch(() => {});
    api.get("/examples").then((r) => setExamples(r.data)).catch(() => {});
    // Model Studio — load enabled personas + providers if the user is admin;
    // non-admin users get an empty list (the AI call falls back to defaults).
    api.get("/admin/models?kind=ai_persona")
      .then((r) => {
        const enabled = (r.data || []).filter((m) => m.enabled);
        setPersonas(enabled);
        // RC3.0 (Feb-2026): DO NOT auto-select an AI persona. Deterministic-
        // only is the product default — analysts opt IN to AI narrative by
        // picking a persona explicitly. Every technical panel (Verdict,
        // MITRE, IOCs, LOLBAS, Recovered Payload) populates identically
        // whether an AI persona is active or not.
      })
      .catch(() => setPersonas([]));
    api.get("/admin/models?kind=ai_provider")
      .then((r) => setProviders((r.data || []).filter((m) => m.enabled)))
      .catch(() => setProviders([]));
    // Recipe URL sharing — if the page loads with #recipe=<base64>, restore input+steps
    if (window.location.hash.startsWith("#recipe=")) {
      try {
        const b64 = window.location.hash.slice("#recipe=".length);
        const decoded = JSON.parse(decodeURIComponent(escape(atob(b64))));
        if (decoded?.i) setInput(decoded.i);
        if (Array.isArray(decoded?.s)) {
          setSteps(decoded.s.map((s) => ({ op: s.op, args: s.a || {} })));
        }
        setStatus("RECIPE LOADED FROM URL");
      } catch (e) {
        setStatus("Invalid recipe URL");
      }
    }
  }, []);

  const addOp = (op) => {
    const args = {};
    (op.args || []).forEach((a) => { if (a.default !== undefined) args[a.name] = a.default; });
    setSteps([...steps, { op: op.id, args }]);
  };

  const runRecipe = async () => {
    setLoading(true);
    setStatus("RUNNING RECIPE...");
    try {
      const r = await api.post("/recipe/run", { input, steps });
      setOutput(r.data.output);
      setDetected(r.data.detected_type);
      setChain(r.data.steps_output || []);
      setStatus(r.data.errors?.length ? "COMPLETED WITH ERRORS" : "OK");
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };

  // ---------- P1.a — Real-time client-side recipe preview ----------
  // Runs the recipe in-browser as the analyst types / edits steps. Falls back
  // to the backend for ops not ported to JS (kept out of the debounce loop).
  // ~30ms debounce keeps the workspace fluid even on large paste.
  const [livePreview, setLivePreview] = useState(null);

  // Feb-2026: Debounced Smart Input Advisor — hits /api/planner/advise 400ms
  // after last keystroke. Zero cost when input < 20 chars.
  // 2026-02-09 · Also skip for oversized inputs — the planner sends
  // the entire input to the backend on every debounce tick, so a
  // 7 KB base64 blob triggers 7 KB uploads while the user is still
  // adding characters.  Backend takes >2 s on huge inputs and the
  // response can be equally large — free unresponsiveness.
  useEffect(() => {
    if (!input || input.length < 20 || input.length > 4096) {
      setPlannerHint(null);
      return;
    }
    const t = setTimeout(async () => {
      try {
        const r = await api.post("/planner/advise", { input });
        const hints = r.data?.hints || [];
        setPlannerHint(hints[0] || null);
      } catch (_) {
        setPlannerHint(null);
      }
    }, 400);
    return () => clearTimeout(t);
  }, [input]);

  // Feb 2026 — Ref to skip the client-side live-preview overwrite when we
  // just restored a case from History. Live-preview naively runs the recipe
  // in JS which overwrites the properly-decoded output stored in the case
  // (especially destructive for binary PE payloads that JS can't render).
  const skipLivePreviewRef = useRef(false);


  // ▲ 2026-02-28 · P0 Persistence — persist input, output, IUE bundle,
  // preprocessor bundle and analyst-narrative bundle to localStorage
  // so navigating away and back to the Workspace preserves the work.
  // Only CLEAR wipes the key (see clearAll above).
  //
  // 2026-02-15 · Systemic anti-hang refactor
  // ──────────────────────────────────────────────
  // Persistence now runs via `useIdlePersist`:
  //   · debounced 800 ms after the last state change
  //   · scheduled through `requestIdleCallback` so `JSON.stringify`
  //     NEVER runs on the critical render path
  //   · skipped entirely when the tab is hidden
  //   · bulk fields (analyst narrative, understanding, investigation
  //     object) auto-drop when the raw payload exceeds 200 KB
  //   · hard-caps at 900 KB (aborts write, never blocks the tab)
  //
  // Result: pasting a huge input, tab-switching mid-analysis, or
  // backgrounding the browser can no longer starve the main thread.
  useIdlePersist("nvx.workspace.persist", {
    input,
    output,
    investigationMode,
    // ── Phase 5.W permanent fix P0.c (2026-08-11) ─────────────────
    // `understanding`, `inlineStoryPreproc`, `analystNarrative` and
    // `investigationObject` were removed from the idle-persist
    // snapshot: they can be arbitrarily large (100 KB – multiple MB
    // once VEEE / attack_progression / behaviour clusters are
    // hydrated), and stringifying them on every state change was
    // the root cause of the "Page Unresponsive" freeze on any
    // non-trivial upload / paste. If the user needs the previous
    // investigation on reload, they re-open the saved case from
    // `/api/cases/{id}` (fast, authoritative, versioned) — which is
    // the same path the Case Library restore button already uses.
  }, { bulkFields: [] });


  useEffect(() => {
    if (!input && !steps.length) {
      setLivePreview(null);
      return;
    }
    if (skipLivePreviewRef.current) {
      // Consume the one-shot skip flag — next input/steps edit re-enables preview.
      skipLivePreviewRef.current = false;
      return;
    }
    // IUE v2.0 · When the pane is in "INVESTIGATION RESULTS" mode
    // (no decoding required), NEVER let the client-side recipe
    // preview stomp the deterministic investigation text.  The pane
    // must never echo the input.
    if (investigationMode) {
      setLivePreview(null);
      return;
    }
    // 2026-02-15 · Anti-hang guard
    // The client-side recipe preview runs base64/gzip/utf-16 decoders
    // in JS on the main thread.  For big real-world payloads
    // (> 4 KB, e.g. a full Sophos PowerShell -encodedcommand blob)
    // this can starve the tab.  The backend investigation is
    // deterministic and completes in <2s for the same input, so we
    // simply skip the JS preview above the guard — Output still
    // populates from the backend response.
    if ((input?.length || 0) > 4096) {
      setLivePreview({ output: "", ranSteps: [], unsupported: [],
                          skipped_reason: "input_too_large_for_client_preview",
                          latencyMs: 0 });
      return;
    }
    const t = setTimeout(() => {
      const t0 = performance.now();
      try {
        const r = runClientRecipe(input, steps);
        const latencyMs = Math.round(performance.now() - t0);
        setLivePreview({ ...r, latencyMs });
        // Preview only auto-populates Output if:
        //   1. All steps ran in JS (no backend fallback needed), AND
        //   2. The user hasn't manually triggered a run yet (output empty)
        //      OR the previously-set output came from an earlier client preview.
        if (!r.needsBackend && !r.error && r.output != null) {
          setOutput(r.output);
        }
      } catch (e) {
        setLivePreview({ output: "", ranSteps: [], unsupported: [], error: e.message, latencyMs: 0 });
      }
    }, 30);
    return () => clearTimeout(t);
  }, [input, steps, investigationMode]);

  // ─── Universal CLEAR — wipe input + output + recipe + all analysis state ──
  // (Previously "Clear" only touched input; now it resets every panel.)
  //
  // Phase 5.W.2 (2026-08-10) · owner request: "when we click on CLEAR,
  // all accumulated memory in frontend and backend should get clear
  // to save the workspace". CLEAR now performs a FULL wipe:
  //   (a) All React state fields the workspace uses (below).
  //   (b) Every workspace-scoped localStorage key (auth tokens preserved).
  //   (c) sessionStorage.
  //   (d) Any in-flight API request via the shared AbortController.
  //   (e) status = "WORKSPACE CLEARED".
  const clearAll = () => {
    setInput("");
    setOutput("");
    setSteps([]);
    setDetected(null);
    setChain([]);
    setAnalysis(null);
    setMagicResults(null);
    setShowMagic(false);
    setShellcodeFlag(false);
    setDecodeConfidence(null);
    setDecodeWinnerEngine(null);
    setDecodeTrace([]);
    setArtifactTrace([]);
    setReachedShellcode(false);
    setPasteHint(null);
    setPredictedTree(null);
    setBoost(null);
    setBoostHit(false);
    setNivxrayTrace([]);
    setLivePreview(null);
    setShareUrl("");
    setTacticFilter(null);
    setChainOpen(false);
    setChainReplay(null);
    setPendingChainStages(null);
    setPendingChainResult(null);
    setMultiChainNotice(null);
    setSavedCaseName(null);
    setInputLocked(false);
    setVerdictCard(null);
    setSemantic(null);
    setInvestigation(null);
    setIedde(null);
    setIeddeTerminalState(null);
    setCanonicalConfidence(null);
    setCanonicalConfidenceReason(null);
    setIeddeDiagnostics([]);
    setUnderstanding(null);
    setUnderstandingLoading(false);
    setUnderstandingError(null);
    setInlineStoryPreproc(null);
    setAnalystNarrative(null);
    setInvestigationMode(false);
    setInvestigationObject(null);
    // (b) All workspace-scoped localStorage keys — auth tokens preserved.
    const _PRESERVE = new Set([
      "nvx_token", "token", "nvx_email", "nvx_dev_mode",
      "nvx_recovery_mode", "nvx-v2-flags",
    ]);
    try {
      const doomed = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (!k) continue;
        if (_PRESERVE.has(k)) continue;
        // Wipe any workspace / investigation / xlab / nvx.* key.
        if (k.startsWith("nvx.") || k.startsWith("nivx.")
            || k.startsWith("xlab.") || k.startsWith("nvx_last")
            || k.startsWith("nvx_pending")) {
          doomed.push(k);
        }
      }
      for (const k of doomed) localStorage.removeItem(k);
    } catch { /* localStorage unavailable → ignore */ }
    // (c) sessionStorage — Workspace uses none currently but wipe defensively.
    try {
      const doomed = [];
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        if (k && (k.startsWith("nvx.") || k.startsWith("nivx.") || k.startsWith("xlab."))) doomed.push(k);
      }
      for (const k of doomed) sessionStorage.removeItem(k);
    } catch { /* ignore */ }
    // (d) Abort any in-flight workspace HTTP request.
    try {
      if (workspaceAbortRef.current) {
        workspaceAbortRef.current.abort(new Error("workspace-cleared"));
        workspaceAbortRef.current = null;
      }
    } catch { /* ignore */ }
    // (e) Final status.
    setStatus("WORKSPACE CLEARED — memory + persisted state wiped");
  };


  // ─── Multi-command chain routing ─────────────────────────────────────
  // When the analyst pastes multiple plain-text command lines (e.g. a Lumma
  // ClickFix sequence, an EDR-bypass chain, a Meterpreter runner), the
  // top-level AUTO INVESTIGATE / DECODE buttons must NOT flat-decode the
  // whole blob (that would only pick up line 1). Instead we split into
  // stages, run /api/decode/chain deterministically per stage, and expose
  // the AGGREGATE as the top-level Output / Recipe / Attack Graph / KILL
  // CHAIN so nothing is truncated. The full per-stage drill-down is
  // rendered by ChainStageEditor which we auto-open below.
  // ▲ IEDDE SSOT helper — apply IEDDE decision trace + canonical
  // confidence pulled from any /api/decode/smart or /api/analyze/async
  // response envelope. Backend guarantees these fields are populated
  // for every decode entry point (Priority 1 · 2026-02).
  const applyIeddeFromResponse = (data) => {
    if (!data || typeof data !== "object") return;
    if (data.iedde !== undefined) setIedde(data.iedde || null);
    if (data.iedde_terminal_state !== undefined)
      setIeddeTerminalState(data.iedde_terminal_state || null);
    if (data.canonical_confidence !== undefined)
      setCanonicalConfidence(
        typeof data.canonical_confidence === "number"
          ? data.canonical_confidence
          : null,
      );
    if (data.canonical_confidence_reason !== undefined)
      setCanonicalConfidenceReason(data.canonical_confidence_reason || null);
    // ▲ Phase 2 · Broken Payload Diagnostics
    if (data.iedde_diagnostics !== undefined)
      setIeddeDiagnostics(Array.isArray(data.iedde_diagnostics) ? data.iedde_diagnostics : []);
  };

  const runChainAnalysis = async (parts, opts = {}) => {
    // 2026-02-09 · Anti-Freeze SLA.
    // opts.autoInvoked=true means AUTO INVESTIGATE routed here
    // automatically for a multi-layer single command.  In that case
    // we DON'T open the Chain Editor modal — the modal mounts a
    // per-stage syntax-highlighted editor for a 2KB+ stage input
    // which blew past Chrome's 15s Page-Unresponsive threshold.
    // Results still populate the sidebar (MITRE/IOCs/GRAPH via
    // `analysis`) and the OUTPUT panel; users can open CHAIN MODE
    // manually if they want the per-stage editor view.
    const _autoInvoked = !!opts.autoInvoked;
    setLoading(true);
    setStatus(`MULTI-COMMAND CHAIN DETECTED · analysing ${parts.length} stages…`);
    try {
      const r = await api.post("/decode/chain", {
        stages: parts.map((p) => ({ input: p })),
      });
      const d = r.data || {};
      const stages = d.stages || [];
      const agg = d.aggregate || {};

      // Aggregate confidence: floor of mean per-stage confidence, capped 0–100.
      const confs = stages.map((s) => s.confidence).filter((c) => Number.isFinite(c));
      const meanConf = confs.length
        ? Math.min(100, Math.max(0, Math.round(confs.reduce((a, b) => a + b, 0) / confs.length)))
        : null;
      const family = agg.family?.family;
      const verdict = agg.risk?.verdict;

      // Compose a unified OUTPUT preview — prefer the server-synthesized
      // SOC report when present (Feb-2026 UX fix so the OUTPUT panel does
      // NOT echo the analyst's raw multi-line paste), fall back to
      // per-stage headers + decoded blobs when the report is absent.
      const aggregatedOutput = (
        d.report_text
        || stages.map((s, i) => {
             // RC2.4 — Don't render a misleading "conf 0/100" header when the
             // stage decoded successfully but the backend didn't attach a
             // per-stage confidence value. Show a decode status instead.
             const hasConf = Number.isFinite(s.confidence) && s.confidence > 0;
             const decodedOk = (s.output || "").trim().length > 0;
             const confBadge = hasConf
               ? `conf=${s.confidence}/100`
               : (decodedOk ? "conf=n/a · decoded" : "conf=n/a");
             const head = `─── STAGE ${i + 1} · engine=${s.engine || "?"} · ${confBadge} ───`;
             return `${head}\n${(s.output || "").trim() || "(no additional decode — plain-text command)"}`;
           }).join("\n\n")
      );

      // 2026-02-09 · Anti-Freeze SLA · Yielded state application.
      // Split the ~17 setState calls that follow into 3 batches
      // separated by animation frames.  This prevents a single
      // ~200 ms reconciliation from stacking on top of another
      // (chain-mode editor mount, TrajectoryDiagram rebuild,
      // sidebar tabs re-render) and blowing past Chrome's 15s
      // unresponsive threshold on real user machines.
      //
      // Each batch is wrapped in `startTransition` so React can
      // interrupt the render if the user clicks anything.
      //
      // ── Batch 1: status + verdict + OUTPUT (fast, small state) ──
      startTransition(() => {
        setOutput(aggregatedOutput);
        setDecodeWinnerEngine(`chain (${stages.length} stages)`);
        setDecodeConfidence(meanConf);
        setReachedShellcode(stages.some((s) => s.reached_shellcode));
        setVerdictCard(null);
        setCorruptedContainer(null);
        setStatus(
          `CHAIN COMPLETE · ${stages.length} stages · ${verdict || "unknown"}` +
          (family ? ` · ${family}` : "") +
          (meanConf != null ? ` · avg ${meanConf}%` : "")
        );
      });

      // Yield to the browser so it can paint the status update.
      await new Promise((r) => requestAnimationFrame(() => r()));

      // ── Batch 2: recipe + chain + trace (medium state) ──
      // Recipe: show a synthetic "chain" step-summary so the RECIPE panel
      // is not empty. Each stage becomes one recipe row.
      const recipeSteps = stages.map((s) => ({
        op: `stage-${s.stage_index + 1}`,
        args: {},
      }));
      startTransition(() => {
        setSteps(recipeSteps);
        setChain(stages.map((s) => ({
          op: `stage-${s.stage_index + 1}`,
          reason: `${s.engine || "?"} · conf=${s.confidence ?? "?"}/100 · ${(s.input_preview || "").slice(0, 80)}`,
          output_preview: (s.output || "").slice(0, 200),
        })));
        setDecodeTrace(stages.map((s) => ({
          op: `stage-${s.stage_index + 1}`,
          args: {},
          reason: `Stage ${s.stage_index + 1} · engine=${s.engine} · conf=${s.confidence}/100`,
          output_preview: (s.output || "").slice(0, 400),
          output_length: s.output_length,
        })));
      });

      // Yield again before the biggest reconciliation.
      await new Promise((r) => requestAnimationFrame(() => r()));

      // ── Batch 3: the heavy `analysis` object (feeds MITRE / IOC / GRAPH sidebars) ──
      // Slim `chain_result` — the full 30KB response was being held
      // in TWO state slots (analysis.chain_result AND
      // pendingChainResult); that doubles GC pressure and DOM diff
      // work on any downstream re-render.  Store only the small
      // aggregate + stage summaries — the full response stays in
      // `pendingChainResult` when the user opens Chain Editor.
      const _slimChainResult = {
        stage_count: d.stage_count,
        aggregate:   d.aggregate,
        labels:      d.labels,
        timestamp:   d.timestamp,
        history_id:  d.history_id,
      };
      startTransition(() => {
        setAnalysis({
          iocs: agg.iocs || {},
          mitre: agg.mitre || [],
          lolbins: agg.lolbas || [],   // fallbackGraph reads `lolbins`
          lolbas: agg.lolbas || [],
          yara: agg.yara || [],
          risk: agg.risk || {},
          family: agg.family || null,
          ai_verdict: verdict ? {
            verdict,
            confidence: agg.risk?.score,
            summary: `${family ? family + " · " : ""}${stages.length} stages · chain-amplified`,
          } : null,
          chain_result: _slimChainResult,  // slim summary only
          streaming: false,
        });
      });

      // Auto-open Chain Mode so the per-stage drill-down UI is visible —
      // BUT ONLY when the user manually invoked chain analysis.  If we
      // routed here from AUTO INVESTIGATE the modal mount would trigger
      // a heavy per-stage editor render that hits the freeze threshold.
      const stageSeeds = stages.map((s) => ({
        input: s.input_preview && !s.input_preview.endsWith("…")
          ? s.input_preview : (parts[s.stage_index] || ""),
      }));
      if (!_autoInvoked) {
        setPendingChainStages(stageSeeds);
        setPendingChainResult(d);        // full response only for editor
        setChainEditorKey((k) => k + 1);
        setChainOpen(true);
      } else {
        // For auto-invoked chains, seed the editor state so if the
        // user opens CHAIN MODE manually later it's pre-populated —
        // but keep the modal closed.
        setPendingChainStages(stageSeeds);
        setPendingChainResult(d);
        setChainEditorKey((k) => k + 1);
      }
      setMultiChainNotice({
        stages: stages.length,
        verdict: verdict || "unknown",
        family: family || null,
      });
      setPasteHint(null);
      // ▲ IUE v2.0 · Auto-enrich (P0 · 2026-03-01) — after chain
      // decode + analyze completes, transition the pane to structured
      // Investigation Results.  Same principle as the smart-decode
      // path: the pane never ends on raw decoded bytes.
      if (input && input.trim()) runInvestigationResults(input);
      return d;
    } catch (e) {
      // Robust stringify — the `/decode/chain` endpoint can return a
      // structured pydantic error (list of dicts) that renders as
      // "[object Object]" if concatenated with `+`.  Normalise to a
      // readable string so the analyst sees the actual cause.
      const rawDetail = e?.response?.data?.detail;
      const detailStr = Array.isArray(rawDetail)
        ? rawDetail.map((d) => d?.msg || d?.detail || JSON.stringify(d)).join(" · ")
        : (typeof rawDetail === "object" && rawDetail !== null
            ? JSON.stringify(rawDetail)
            : (rawDetail || e?.message || String(e)));
      setStatus("CHAIN ERROR: " + detailStr);
      return null;
    } finally {
      setLoading(false);
    }
  };

  // Opt-out escape hatch — analyst wants the whole blob decoded flat
  // (e.g. for a payload that *looks* multi-command but is actually a
  // single obfuscation with newlines as delimiters). Bypasses the
  // splitter and runs /api/decode/smart on the raw text.
  const revertToFlatDecode = async () => {
    setMultiChainNotice(null);
    setChainOpen(false);
    setPendingChainResult(null);
    setPendingChainStages(null);
    setLoading(true);
    setStatus("REVERTED · analysing as flat blob…");
    try {
      const r = await api.post("/decode/smart", { input });
      applyIeddeFromResponse(r.data);
      const d = r.data || {};
      // Feb 2026 · v1.5.3 · OUTPUT panel authority.
      // The v1.5.1 backend hotfix promotes the RTE decoder trace and the
      // deepest recovered artefact (L2 for the reflective-loader class)
      // into ``d.output`` with a header line beginning
      // ``═══ INVESTIGATION BRAIN · RTE DECODER TRACE``.
      //
      // When that header is present, ``d.output`` is the AUTHORITATIVE
      // analyst-facing output: it already contains the deepest layer,
      // the per-stage confidence table, and the DX diagnostics chain.
      // The frontend must NOT downgrade it to a shorter ``semantic
      // deobfuscation.final`` (which only carries L1). Previously the
      // preference logic below unconditionally chose the shorter
      // "semantic final" when it existed, causing the OUTPUT panel to
      // display L1 (`$s = New-Object IO.MemoryStream(...)`) instead of
      // L2 (`Set-StrictMode … func_get_proc_address …`) even though
      // the RTE, Semantic Intent, and Verdict panels correctly showed
      // the L2 reflective-loader plaintext. Reported by SME 2026-02-XX.
      const _fSemFinal =
        d?.semantic?.deobfuscation?.final ||
        d?.semantic?.recovered_script || "";
      const _fRawOut = d.output || "";
      const _rteBrainAuthority =
        _fRawOut.includes("INVESTIGATION BRAIN · RTE DECODER TRACE");
      const _fPreferSem =
        !_rteBrainAuthority &&
        !!_fSemFinal &&
        _fSemFinal !== _fRawOut &&
        _fSemFinal.length < String(input).length;
      setOutput(_fPreferSem ? _fSemFinal : _fRawOut);
      setSteps((d.recipe || []).map((s) => ({ op: s.op, args: s.args || {} })));
      setChain(d.chain || []);
      setDecodeTrace(d.chain || []);
      setDecodeWinnerEngine(d.engine || null);
      setDecodeConfidence(d.confidence ?? null);
      setReachedShellcode(!!d.reached_shellcode);
      setSemantic(d.semantic || null);
      setInvestigation(d.investigation || null);
      // Wipe stale chain-aggregated analysis so ATT&CK / IOC panels re-derive from single blob.
      setAnalysis((a) => ({
        // v1.5.8 · merge preserves iocs already extracted upstream
        // (e.g. by /decode/smart before AUTO INVESTIGATE polls).
        iocs: mergeIocs(a?.iocs, d.iocs),
        mitre: d.mitre || [],
        lolbins: d.lolbas || [],
        lolbas: d.lolbas || [],
        yara: d.yara || [],
        risk: d.risk || {},
        family: d.family || null,
        // v1.5.1 — Zero-Miss escalation trace
        layer_trace: d.layer_trace || [],
        engine: d.engine || null,
        confidence: (d.confidence ?? d.score ?? null),
        // v1.5.5 — TI Shield · 360° per-layer intelligence
        ti_shield: d.ti_shield || [],
      }));
      // RC2.4 — Same treatment for flat decode: don't show "0/100" when the
      // decoder actually returned content.
      const flatHasConf = Number.isFinite(d.confidence) && d.confidence > 0;
      const flatDecodedOk = (d.output || "").trim().length > 0;
      const flatConfBadge = flatHasConf
        ? `conf=${d.confidence}/100`
        : (flatDecodedOk ? "conf=n/a · decoded" : "conf=n/a");
      setStatus(`FLAT DECODE · engine=${d.engine || "?"} · ${flatConfBadge}`);
      // ▲ IUE v2.0 · Auto-enrich (P0 · 2026-03-01) — after any flat
      // decode, transition the pane to structured Investigation
      // Results.  The pane must never end on raw decoded bytes.
      if (input && input.trim()) runInvestigationResults(input);
    } catch (e) {
      setStatus("FLAT DECODE ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };


  // ─── ONE-BUTTON orchestrator ─────────────────────────────────────────
  // Auto-runs: (1) archetype/boost/deterministic via Smart Decode, then
  //           (2) AI fallback (Auto Investigate) if confidence < 40.
  // Fires a live trace so the analyst sees exactly what happened.
  const nivxrayDecode = async () => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    // ── IUE v2.0 · Investigation-first (2026-03-01) ─────────────
    // DECODE is a capability, not a driver.  Ask the IUE whether
    // decoding is required before touching the decoder pipeline.
    // For plain PowerShell / CMD / Bash / vendor report / IOC
    // list, we skip the decoder entirely and render deterministic
    // Investigation Results instead of echoing the input.
    // ── Phase A · state-machine sync (2026-02-13) ────────────────
    // Idempotently clear any stale AUTO-INVESTIGATE / prior-run
    // flags at entry so the fast-path never inherits them.
    setAnalyzing(false);
    setLoading(false);
    setInvestigationMode(false);
    setInvestigationObject(null);
    try {
      const und = await api.post("/die/understand", { input, execute: false });
      const u = und?.data?.understanding;
      if (u) setUnderstanding(u);
      if (u && u.decode_required === false) {
        setStatus("INVESTIGATION READY · NO DECODE REQUIRED · RENDERING FINDINGS…");
        // ── Phase A · guarantee chips clear on the fast-path ─────
        // Raise `analyzing` while the SSOT is being fetched, then
        // clear it in a try/finally so success AND error both
        // return the UI to a consistent state.
        setAnalyzing(true);
        try {
          // Populate Inline Story + Narrative in parallel so the
          // Trajectory + Attack Story panels remain in sync with the
          // Investigation Results text.
          api.post("/die/analyze", { input })
            .then((r) => {
              const pre = r?.data?.result?.preprocessor
                       || r?.data?.result?.chain?.preprocessor
                       || null;
              if (pre) setInlineStoryPreproc(pre);
            })
            .catch(() => { /* silently absent */ });
          api.post("/die/narrate", { input })
            .then((r) => setAnalystNarrative(r?.data?.narrative || null))
            .catch(() => { /* silently absent */ });
          const ok = await runInvestigationResults(input);
          setStatus(ok
            ? "INVESTIGATION READY · DETERMINISTIC RESULTS RENDERED"
            : "INVESTIGATION READY · (fallback view)");
        } finally {
          setAnalyzing(false);
          setLoading(false);
        }
        return;
      }
    } catch { /* fall through — classic decode path handles errors */ }

    // Multi-command chain? Route to /decode/chain so all stages are analysed.
    // BUT — the chain endpoint caps at 20 parts and does not handle
    // vendor-report prose.  Skip the chain path for those.
    const parts = splitCommandLines(input);
    const looksLikeProse =
      (input || "").length > 400 &&
      /(?:^|\n)(?:the\s|talos\s|initial access|discovery|lateral movement|executive summary|engagement\s\d|mandiant|crowdstrike|microsoft defender|securex|falcon overwatch|customer\s|outcome|main research question|defensive)/i
        .test(input || "");
    if (parts && parts.length > 1 && parts.length <= 20 && !looksLikeProse) {
      await runChainAnalysis(parts);
      return;
    }
    const trace = [];
    setNivxrayTrace(trace);
    setStatus("NIVXRAY DECODE — DETERMINISTIC + BOOST…");
    setLoading(true);
    try {
      // Step 1 · deterministic (archetype + smart/magic race + boost)
      const r = await api.post("/decode/smart", { input });
      applyIeddeFromResponse(r.data);
      const conf = r.data.confidence ?? 0;
      const eng = r.data.engine || "?";
      const outLen = (r.data.output || "").length;
      trace.push({
        step: "deterministic",
        engine: eng,
        confidence: conf,
        output_len: outLen,
        note: eng.startsWith("archetype:")
          ? `Matched wrapper archetype — ${eng.replace("archetype:", "")}`
          : `Smart/magic race — ${eng}`,
      });
      setSteps((r.data.recipe || []).map((s) => ({ op: s.op, args: s.args || {} })));
      // Feb 2026 · v1.5.5 · Shared canonical output selector — see
      // /app/frontend/src/lib/selectCanonicalOutput.js for the priority
      // ladder. Guarantees DECODE and AUTO INVESTIGATE both surface
      // the same terminal artifact (SME parity directive).
      const _sel = await selectCanonicalOutput({ api, input, smartResp: r.data });
      setOutput(_sel.text);
      if (r.data.trace) setDecodeTrace(r.data.trace);
      setReachedShellcode(!!r.data.reached_shellcode);
      setDecodeConfidence(conf);
      setDecodeWinnerEngine(eng);
      setBoost(r.data.boost || null);
      setBoostHit(!!r.data.boost_hit);
      setSemantic(r.data.semantic || null);
      setInvestigation(r.data.investigation || null);
      setNivxrayTrace([...trace]);
      // v1.5.1 — populate analysis with Zero-Miss escalation ladder so the
      // EscalationLadder component renders immediately on primary decode
      // (without waiting for the analyst to click ANALYZE + OSINT).
      setAnalysis((a) => ({
        ...(a || {}),
        // v1.5.8 · merge preserves iocs the deterministic pipeline already
        // extracted (never clobber with an empty AI-job shell).
        iocs:        mergeIocs(a?.iocs, r.data.iocs),
        mitre:       r.data.mitre || (a?.mitre) || [],
        lolbas:      r.data.lolbas || (a?.lolbas) || [],
        // v1.5.8 · Deterministic FLOW baseline (SME Rule 5: deterministic
        // first). Every decoder recipe step becomes a stage in the
        // attack chain so the FLOW panel populates on DECODE-only mode
        // (no AI required). AI describe layers on top when present.
        chain: (r.data.recipe || []).map((s, i) => ({
          op: s.op,
          reason: s.reason || "",
          output_preview: (r.data.trace?.[i]?.output_preview) || "",
        })) || (a?.chain) || [],
        engine:      eng,
        confidence:  conf / 100,
        layer_trace: r.data.layer_trace || [],
        l3_metadata: r.data.l3_metadata || null,
        // v1.5.5 — TI Shield renders immediately on primary decode
        ti_shield:   r.data.ti_shield || (a?.ti_shield) || [],
        // Jul-2026 — PowerShell EncodedCommand deterministic decode-error card
        terminal:    r.data.terminal || null,
        decode_error: r.data.decode_error || null,
      }));

      // Step 2 · AI fallback if confidence low OR archetype didn't match AND output is trivial
      // Feb 2026 · v1.5.4 · skip fallback when the primary decode already
      // ran a complete linear recipe (≥ 4 steps means we peeled at least
      // one non-trivial obfuscation chain). Prevents the double-decode
      // that pinned the browser tab at ~2 minutes and produced the
      // "Page Unresponsive" dialog reported by SME 2026-02-XX.
      const _recipeCompleted = Array.isArray(r.data?.recipe) && r.data.recipe.length >= 4;
      const shouldFallback = conf < 40 && !eng.startsWith("archetype:") && !_recipeCompleted;
      if (shouldFallback) {
        trace.push({
          step: "ai-fallback",
          note: `Confidence ${conf}% below threshold — escalating to Auto Investigate`,
        });
        setNivxrayTrace([...trace]);
        setStatus("NIVXRAY DECODE — AI FALLBACK…");
        await autoInvestigate();   // reuses existing SSE stream
        trace.push({ step: "ai-done", note: "AI investigation complete — see verdict panel" });
      } else {
        trace.push({
          step: "done",
          note: conf >= 40
            ? `Deterministic decode succeeded at ${conf}% — AI fallback not needed`
            : `Archetype match at 100% — AI fallback not needed`,
        });
      }
      setNivxrayTrace([...trace]);
      setStatus(`NIVXRAY DECODE COMPLETE · ${eng} · ${conf}%`);
    } catch (e) {
      trace.push({ step: "error", note: e?.response?.data?.detail || e.message });
      setNivxrayTrace([...trace]);
      setStatus("NIVXRAY DECODE FAILED — see trace");
    } finally {
      setLoading(false);
    }
  };

  // Feb-2026 · Strict vs Best-Effort container-recovery mode. Persisted per
  // user so the choice sticks across sessions.
  const [recoveryMode, setRecoveryMode] = useState(
    () => localStorage.getItem("nvx_recovery_mode") || "strict",
  );
  const setRecoveryModePersisted = (m) => {
    setRecoveryMode(m);
    try { localStorage.setItem("nvx_recovery_mode", m); } catch {}
  };

  const autoDecode = async ({ smart = false, disable_boost = false } = {}) => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    // Multi-command chain? Route to /decode/chain (both smart and AI paths).
    // BUT — the chain endpoint caps at 20 parts and does not handle
    // vendor-report prose.  Skip the chain path for those.
    const parts = splitCommandLines(input);
    const looksLikeProse =
      (input || "").length > 400 &&
      /(?:^|\n)(?:the\s|talos\s|initial access|discovery|lateral movement|executive summary|engagement\s\d|mandiant|crowdstrike|microsoft defender|securex|falcon overwatch|customer\s|outcome|main research question|defensive)/i
        .test(input || "");
    if (parts && parts.length > 1 && parts.length <= 20 && !looksLikeProse) {
      await runChainAnalysis(parts);
      return;
    }
    setLoading(true);
    setStatus(smart ? "SMART-DECODING (DETERMINISTIC)..." : "AI AUTO-DECODING...");
    try {
      const url = smart ? "/decode/smart" : "/ai/auto-decode";
      const payload = smart ? { input, disable_boost, mode: recoveryMode } : { input };
      const r = await api.post(url, payload);
      if (smart) applyIeddeFromResponse(r.data);
      setSteps((r.data.recipe || []).map((s) => ({ op: s.op, args: s.args || {} })));

      // Anti-hallucination guard — if backend refused to emit a decode (SOC-mode
      // graceful stop), keep the input unchanged and surface the explanation
      // instead of dumping garbage into the Output pane.
      if (r.data.stopped_gracefully) {
        setOutput("");
        setStatus(`⚠ ${r.data.graceful_message || "No further deterministic decoding possible"}`);
      } else {
        setOutput(r.data.output || "");
        const conf = r.data.confidence;
        const eng  = r.data.winner_engine;
        setDecodeConfidence(conf ?? null);
        setDecodeWinnerEngine(eng || null);
        const confPrefix = (conf != null && eng) ? `[${eng.toUpperCase()} · ${conf}%] ` : "";
        // v1.5.8 · reasoning can arrive as string OR object (LLM path variants).
        // Guard against `.slice is not a function` when it's an object.
        const _raw = r.data.reasoning;
        const _reasonStr = typeof _raw === "string"
          ? _raw
          : (_raw && typeof _raw === "object"
              ? (_raw.explanation || _raw.summary || _raw.text || JSON.stringify(_raw))
              : "");
        const detail = _reasonStr ? `AI: ${_reasonStr.slice(0, 120)}` : "SMART DECODE COMPLETE";
        setStatus(confPrefix + detail);
      }

      setDetected(r.data.detected_type || null);
      // Jul-2026 — PowerShell EncodedCommand decode-error state.
      // Keep analysis populated so <WorkspaceDecodeFailureCard/> renders
      // when the deterministic recovery chain fails on a corrupt blob.
      setAnalysis((a) => ({
        ...(a || {}),
        engine:        r.data.engine || (a?.engine) || null,
        terminal:      r.data.terminal || null,
        decode_error:  r.data.decode_error || null,
        verdict_card:  r.data.verdict_card || (a?.verdict_card) || null,
      }));
      setChain((r.data.recipe || []).map((s, i) => ({
        op: s.op, reason: s.reason || "",
        output_preview: r.data.trace?.[i]?.output_preview || r.data.steps_output?.[i]?.output_preview || "",
        custom: !!s.custom, model_id: s.model_id, model_name: s.model_name,
      })));
      // Decoding Trace panel data (smart-decode returns full trace; ai-decode does not)
      if (smart && r.data.trace) {
        setDecodeTrace(r.data.trace);
        setReachedShellcode(!!r.data.reached_shellcode);
        setDecodeConfidence(r.data.confidence ?? null);
        setDecodeWinnerEngine(r.data.engine || null);
        // Learning Feedback Loop — boost metadata
        setBoost(r.data.boost || null);
        setBoostHit(!!r.data.boost_hit);
      }
      // ▲ SOC evidence-driven analyst brief (Feb-2026)
      setVerdictCard(r.data.verdict_card || null);
      setCorruptedContainer(r.data.corrupted_container || null);
      setPasteHint(null);
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };

  const magicDecode = async () => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    setLoading(true);
    setStatus("MAGIC ▸ recursive multi-branch search…");
    try {
      const r = await api.post("/decode/magic", { input, max_depth: 4, max_branches: 4, top_n: 5 });
      setMagicResults(r.data);
      setShowMagic(true);
      setStatus(`MAGIC ▸ ${r.data.top_results?.length || 0} candidate chains · explored ${r.data.candidates_explored} paths`);
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };

  const applyMagicResult = (r) => {
    setSteps((r.chain || []).map((s) => ({ op: s.op, args: s.args || {} })));
    setOutput(r.output || "");
    setChain((r.chain || []).map((s, i) => ({
      op: s.op, reason: `magic auto-decoder (score ${r.score_breakdown?.score ?? "?"})`,
      output_preview: (r.output || "").slice(0, 400),
    })));
    // Propagate the shellcode stop-condition flag so the ShellcodeView can
    // auto-render when a magic chain terminates on binary output.
    setShellcodeFlag(!!r.is_shellcode);
    setShowMagic(false);
    setStatus(`APPLIED MAGIC CHAIN · score ${r.score_breakdown?.score}`);
  };

  const shareRecipe = () => {
    const payload = {
      i: input.slice(0, 40000),
      s: steps.map((s) => ({ op: s.op, a: s.args && Object.keys(s.args).length ? s.args : undefined })),
    };
    const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
    const url = `${window.location.origin}${window.location.pathname}#recipe=${encoded}`;
    setShareUrl(url);
    // Best-effort clipboard write; the toast shows the URL either way
    try {
      if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(url).then(
          () => setStatus("SHARE URL COPIED TO CLIPBOARD"),
          () => setStatus("SHARE URL READY — copy from the toast"),
        );
      } else {
        setStatus("SHARE URL READY — copy from the toast");
      }
    } catch {
      setStatus("SHARE URL READY — copy from the toast");
    }
  };

  const analyze = ({ describe = false, aiVerdict = false } = {}) => {
    if (!input.trim() && !output.trim()) { setStatus("PROVIDE INPUT OR OUTPUT FIRST"); return; }
    streamStopRef.current?.();
    setAnalyzing(true);
    // ── P0 · Input Understanding Engine (2026-02-28) ────────────
    // Runs in parallel with the SSE/job pipeline so the analyst sees
    // WHAT they pasted and WHY each engine is running BEFORE results
    // land.  Deterministic — same paste always yields the same trace.
    if (input && input.trim()) {
      setUnderstanding(null);
      setUnderstandingError(null);
      setUnderstandingSkipReason("");
      setUnderstandingLoading(true);
      setInlineStoryPreproc(null);
      callLlmGracefully("/die/understand", { input, execute: true }, {
        budgetBytes: LLM_INPUT_BUDGET.understand,
      }).then((res) => {
        if (res.ok) setUnderstanding(res.data?.understanding || null);
        else setUnderstandingSkipReason(res.reason || "");
        setUnderstandingLoading(false);
      });
      callLlmGracefully("/die/analyze", { input }, {
        budgetBytes: LLM_INPUT_BUDGET.analyze,
      }).then((res) => {
        if (!res.ok) return;
        const pre = res.data?.result?.preprocessor
                 || res.data?.result?.chain?.preprocessor
                 || null;
        if (pre) setInlineStoryPreproc(pre);
      });
      callLlmGracefully("/die/narrate", { input }, {
        budgetBytes: LLM_INPUT_BUDGET.narrate,
      }).then((res) => {
        if (res.ok) setAnalystNarrative(res.data?.narrative || null);
      });
    }
    if (describe || aiVerdict) {
      // AI-heavy path — use job polling to bypass reverse-proxy timeouts
      pollAnalyzeJob({ input, output, enrich_osint: true, describe, use_ai_verdict: aiVerdict,
                       persona_id: personaId || undefined, provider_id: providerId || undefined }, chain);
    } else {
      // Fast path — SSE streaming
      setStatus("ANALYZING…");
      setAnalysis((prev) => ({ ...(prev || {}), chain, streaming: true }));

      // 2026-02-09 · Page-Unresponsive fix
      // ──────────────────────────────────────────────
      // SSE streams can fire 10-20 partial events during a single
      // AUTO INVESTIGATE. Each `setAnalysis` synchronously re-renders
      // the full 3.7k-line WorkspacePage tree (Trajectory · Semantic
      // Panel · Extracted Artifacts · TI-Hits · OSINT · IOC lists).
      // On a 7 KB input this compound render blows past Chrome's
      // 15-second unresponsive threshold.
      //
      // Two safety nets:
      //   1. `startTransition` — marks stream updates as non-urgent,
      //      so React interrupts a slow render when the next partial
      //      arrives instead of finishing it, blocking, then rendering
      //      the next one.
      //   2. Throttle-coalesce — buffers partial events and flushes
      //      at most once per 200 ms via requestAnimationFrame, so
      //      even a fast stream can't overwhelm the reconciler.
      const _pendingRef = { partial: null, ti: null, osint: null,
                             timer: 0, lastFlush: 0 };
      const _flushBuffered = () => {
        _pendingRef.timer = 0;
        _pendingRef.lastFlush = performance.now();
        const { partial, ti, osint } = _pendingRef;
        _pendingRef.partial = _pendingRef.ti = _pendingRef.osint = null;
        startTransition(() => {
          if (partial) {
            setAnalysis((a) => ({
              ...(a || {}), ...partial,
              iocs: mergeIocs(a?.iocs, partial?.iocs),
              chain, streaming: true,
            }));
          }
          if (ti !== null)    setAnalysis((a) => ({ ...(a || {}), ti_hits: ti, streaming: true }));
          if (osint !== null) setAnalysis((a) => ({ ...(a || {}), osint,    streaming: true }));
        });
      };
      const _schedule = () => {
        if (_pendingRef.timer) return;
        // Coalesce updates into ~200 ms windows (5 renders/sec ceiling).
        const elapsed = performance.now() - _pendingRef.lastFlush;
        const delay = Math.max(0, 200 - elapsed);
        _pendingRef.timer = setTimeout(_flushBuffered, delay);
      };

      const stop = streamAnalyze(
        // v1.5.8 · describe:true — AUTO INVESTIGATE must generate the
        // attack-chain description so FLOW / TI-HITS / summary panels
        // populate. Deterministic-first: if AI is unavailable the FLOW
        // panel falls back to the linear recipe chain (see FlowTab
        // deterministicChain prop).
        { input, output, enrich_osint: true, describe: true, use_ai_verdict: false },
        {
          onStatus:      (s) => setStatus(`▸ ${s.phase.toUpperCase()}: ${s.message}`),
          // v1.5.8 · AUTO INVESTIGATE = deterministic pipeline PLUS AI enrichment.
          // The AI stream must ADD to what the deterministic decoder produced —
          // never replace. Any incoming iocs are MERGED (union of prior + new)
          // so the C2 IP / URL / API imports already extracted by the RC2
          // pipeline don't vanish when the stream completes.
          onPartial:     (p) => {
            // Merge into the pending buffer (last-write-wins per key,
            // union for iocs) so a burst of partials collapses into a
            // single render.
            const prev = _pendingRef.partial || {};
            _pendingRef.partial = {
              ...prev, ...p,
              iocs: mergeIocs(prev?.iocs, p?.iocs),
            };
            _schedule();
          },
          onTiHits:      (h) => { _pendingRef.ti    = h; _schedule(); },
          onOsint:       (o) => { _pendingRef.osint = o; _schedule(); },
          onResult:      (r) => {
            // Final result — flush any pending buffer first, then apply
            // synchronously (this is the terminal state; no more events
            // will follow, so no risk of re-blocking).
            if (_pendingRef.timer) { clearTimeout(_pendingRef.timer); _pendingRef.timer = 0; }
            setAnalysis((a) => ({
              ...(a || {}),
              ...(_pendingRef.partial || {}),
              ...r,
              // Category-wise merge — deterministic + AI-enriched union.
              iocs: mergeIocs(mergeIocs(a?.iocs, _pendingRef.partial?.iocs), r?.iocs),
              // Preserve any deterministic-only fields the AI response omits.
              mitre:    (r?.mitre    && r.mitre.length)    ? r.mitre    : a?.mitre,
              lolbas:   (r?.lolbas   && r.lolbas.length)   ? r.lolbas   : a?.lolbas,
              yara:     (r?.yara     && r.yara.length)     ? r.yara     : a?.yara,
              ti_hits:  (r?.ti_hits  != null)              ? r.ti_hits  : a?.ti_hits,
              osint:    (r?.osint    != null)              ? r.osint    : a?.osint,
              chain, streaming: false,
            }));
            _pendingRef.partial = _pendingRef.ti = _pendingRef.osint = null;
          },
          onError:       (e) => setStatus(`STREAM ERROR (${e.phase}): ${e.error}`),
          onDone:        ()  => {
                                 if (_pendingRef.timer) { clearTimeout(_pendingRef.timer); _pendingRef.timer = 0; }
                                 setAnalyzing(false); streamStopRef.current = null;
                                 setStatus((s) => s.startsWith("STREAM ERROR") ? s : "ANALYSIS COMPLETE");
                                 // ▲ IUE v2.0 · Auto-enrich (P0 · 2026-03-01)
                                 // After decode + analyze completes, always
                                 // transition the pane to structured
                                 // Investigation Results so the analyst never
                                 // stares at raw decoded bytes.
                                 if (input && input.trim()) runInvestigationResults(input);
                                },
        },
      );
      streamStopRef.current = stop;
    }
  };

  const pollAnalyzeJob = async (body, chainVal) => {
    // Poll-based analysis for AI-heavy runs (bypasses SSE / proxy timeouts).
    setStatus("ANALYZING ▸ enqueuing…");
    setAnalysis({ chain: chainVal, streaming: true, job_id: null });
    let jobId;
    try {
      const r = await api.post("/analyze/async", body);
      jobId = r.data.job_id;
      setAnalysis((a) => ({ ...(a || {}), job_id: jobId }));
    } catch (e) {
      const detail = e?.response?.data?.detail || e.message || "";
      if (/AI features are disabled/i.test(String(detail))) {
        setStatus("NOTICE · AI narrative skipped (admin-disabled) · deterministic verdict shown");
      } else {
        setStatus("ERROR: " + detail);
      }
      setAnalyzing(false);
      return;
    }
    let cancelled = false;
    streamStopRef.current = () => { cancelled = true; };
    const MAX_POLLS = 90;   // 90 × 3s = 270s
    for (let i = 0; i < MAX_POLLS; i++) {
      if (cancelled) return;
      try {
        const st = await api.get(`/analyze/status/${jobId}`);
        const d = st.data;
        setAnalysis((a) => ({
          ...(a || {}),
          job_id: jobId,
          // v1.5.8 · merge, never clobber — the deterministic pipeline's
          // iocs must survive AI-job polls that return empty shells.
          iocs: mergeIocs(a?.iocs, d.iocs),
          mitre: d.mitre || a?.mitre,
          yara: d.yara || a?.yara,
          lolbas: d.lolbas || a?.lolbas,
          risk: d.risk || a?.risk,
          verdict_card: d.verdict_card || a?.verdict_card,
          ti_hits: d.ti_hits ?? a?.ti_hits,
          osint: d.osint ?? a?.osint,
          ai_verdict: d.ai_verdict ?? a?.ai_verdict,
          description: d.description ?? a?.description,
          playbooks_used: d.playbooks_used ?? a?.playbooks_used,
          chain: chainVal,
          streaming: d.status !== "done" && d.status !== "error",
        }));
        // ▲ IEDDE SSOT · async job also carries IEDDE fields.
        applyIeddeFromResponse(d);
        setStatus(`▸ ${(d.phase || "running").toUpperCase()} · ${d.progress || 0}%${d.elapsed_s ? " · " + d.elapsed_s + "s" : ""}`);
        if (d.status === "done") {
          // ARB Governance Rule 12 · verdict_card is the canonical source.
          // `risk` is a projection — reading it here would be a violation.
          const vc = d.verdict_card || {};
          const canonicalVerdict = vc.verdict || vc.label || (d.risk?.verdict) || "";
          setStatus(`ANALYSIS COMPLETE · ${canonicalVerdict}`);
          break;
        }
        if (d.status === "error") {
          // Feb 2026 — AI-off is an intentional admin policy, not a
          // failure. Deterministic decode already succeeded and the
          // verdict card is populated. Surface as a neutral NOTICE so
          // the STATUS bar doesn't scream red ERROR.
          const errMsg = String(d.error || "");
          if (/AI features are disabled/i.test(errMsg)) {
            setStatus("NOTICE · AI narrative skipped (admin-disabled) · deterministic verdict shown");
          } else {
            setStatus(`ERROR: ${d.error}`);
          }
          break;
        }
      } catch (e) {
        // Transient network hiccups — keep polling
        setStatus(`POLL WARN: ${e.message} — retrying…`);
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
    setAnalyzing(false);
    streamStopRef.current = null;
  };

  // ── IUE v2.0 · One Investigation, One Fetch (R12 · 2026-03-01) ────
  // Retrieve the Canonical Investigation Object once and derive every
  // downstream panel (Inline Attack Story, Trajectory, Analyst
  // Narrative, Understanding) from its projections.  No component may
  // orchestrate its own investigation calls (Rule R11 + R12).
  const runInvestigationResults = async (rawInput) => {
    try {
      const r = await api.post("/die/investigation-results", { input: rawInput });
      const text = r?.data?.output || "";
      const obj  = r?.data?.object || null;
      if (text) {
        setOutput(text);
        setInvestigationMode(true);
        setInvestigationObject(obj);
        // ── Phase C · projection safety (2026-02-13) ──────────────
        // The SSOT commit (setOutput/setInvestigationMode/setInvestigationObject)
        // is done. From here on, any projection failure must NOT
        // roll back the successful commit, must NOT crash React,
        // and must NOT prevent status from advancing. Wrap the
        // entire projection block in a try/catch that logs but
        // continues.
        try {
          // ▲ Rule R12 · one fetch, many projections — derive every
          // sibling panel's state from the SSOT we just retrieved so
          // no component needs to hit /die/understand, /die/analyze,
          // or /die/narrate independently.
          if (obj) {
            if (obj.understanding) setUnderstanding(obj.understanding);
            if (obj.preprocessor)  setInlineStoryPreproc(obj.preprocessor);
            if (obj.narrative)     setAnalystNarrative(obj.narrative);
            // ▲ P0e-Lift (2026-02-09) · Project the already-present
            // structured evidence from the SSOT into the `analysis`
            // state so the Workspace Threat Analysis sidebar tabs
            // (MITRE · LOLBAS · IOCS · RULES · AI · GRAPH) populate
            // for URL-acquired investigations too — the classic SSE
            // /analyze pipeline is skipped for !decodeRequired inputs
            // by design (Rule R10) so this projection is the ONLY
            // deterministic path for those fields to reach the UI.
            //
            // Source priority (proven by read-only trace):
            //   MITRE →  report_extraction.mitre_techniques  (URL-acquired · authoritative)
            //         ↳ obj.mitre                            (paste-path fallback)
            //   YARA  →  report_extraction.yara_rules        (structured)
            //         ↳ obj.narrative.yara_ideas             (deterministic narrative)
            //
            // No new inference, no new API calls, no state duplication.
            const rext = (obj && typeof obj.report_extraction === "object" && obj.report_extraction) || {};
            const _mitre =
              (Array.isArray(rext.mitre_techniques) && rext.mitre_techniques.length)
                ? rext.mitre_techniques
                : (Array.isArray(obj.mitre) ? obj.mitre : []);
            // Phase C · defensive yara-rule normalization — rule may be
            // string · object · null · undefined · array. Filter to the
            // shapes ThreatAnalysis actually understands.
            let _yara = [];
            try {
              if (Array.isArray(rext.yara_rules) && rext.yara_rules.length) {
                _yara = rext.yara_rules
                  .filter((rule) => rule != null)
                  .map((rule) => {
                    if (typeof rule === "string") return { name: rule, source: "report_extraction" };
                    if (typeof rule === "object") return rule;
                    return { name: String(rule), source: "report_extraction" };
                  });
              } else if (Array.isArray(obj.narrative?.yara_ideas)) {
                _yara = obj.narrative.yara_ideas;
              }
            } catch (yaraErr) {
              // eslint-disable-next-line no-console
              console.warn("[NIVXRAY · yara-projection soft-fail]", yaraErr);
              _yara = [];
            }
            const _exec = obj.narrative?.executive_summary || null;
            const _aiVerdict = _exec
              ? {
                  verdict:    _exec.risk || _exec.verdict || "Unknown",
                  confidence: typeof _exec.confidence === "number" ? _exec.confidence : null,
                  summary:    _exec.paragraph || _exec.summary || "",
                }
              : null;
            setAnalysis((prev) => ({
              ...(prev || {}),
              iocs:       (obj && typeof obj.iocs === "object" && obj.iocs) || {},
              // ▲ UX-FIX (2026-02-09) · Normalize lolbas entries to the
              // shape ThreatAnalysis / LolbasTab expects — the SSOT
              // schema uses {binary, legit, abuse, mitre, detection}
              // while the sidebar UI reads {binary, purposes, mitre,
              // description, snippet, url}.  Missing arrays default to
              // [] so `.map()` never crashes the panel.
              lolbas:     _normalizeLolbas(obj.lolbas),
              lolbins:    _normalizeLolbas(obj.lolbas), // fallbackGraph reads .lolbins
              mitre:      _mitre,
              yara:       _yara,
              ai_verdict: _aiVerdict || (prev && prev.ai_verdict) || null,
              // TI-HITS and OSINT intentionally NOT lifted — those
              // require the SSE analyze pipeline and would be
              // manufactured / stale if projected from the SSOT.
              streaming:  false,
            }));
          }
        } catch (projErr) {
          // eslint-disable-next-line no-console
          console.warn("[NIVXRAY · projection soft-fail — SSOT still committed]", {
            error: projErr && projErr.message,
            stack: projErr && projErr.stack,
          });
          // Do not rethrow — the SSOT commit above already succeeded
          // and the analyst can still see the investigation text +
          // narrative panels. Sidebar tabs will render empty rather
          // than crash the workspace.
        }
        return true;
      }
    } catch { /* fall through — non-blocking */ }
    return false;
  };

  const autoInvestigate = async () => {
    if (!input.trim()) { setStatus("PROVIDE INPUT FIRST"); return; }
    // ── P0 · IUE + Inline Attack Story (2026-02-28) ───────────────
    // Wire AUTO INVESTIGATE to the same understanding pipeline as
    // ANALYZE so the analyst sees the plan + timeline no matter
    // which button was clicked.
    //
    // ▲ UX-FIX (2026-02-09) — raise `analyzing` immediately so the
    // AUTO INVESTIGATE button glows the instant it's clicked
    // (previously the flag was only set inside the decode branch,
    // so URL / chain / atomic-IOC inputs gave no visual feedback
    // even though the pipeline was running).  Every terminal path
    // below clears the flag so the button returns to idle when the
    // work is complete or aborted.
    setAnalyzing(true);
    setStatus("AUTO-INVESTIGATE ▸ CLASSIFYING…");
    setUnderstanding(null);
    setUnderstandingError(null);
    setUnderstandingLoading(true);
    setInlineStoryPreproc(null);
    // Reset investigation mode — will be re-enabled by the IUE
    // classifier below if decoding isn't required.
    setInvestigationMode(false);
    setInvestigationObject(null);

    // 2026-02-09 · Fast-path detection — classify multi-layer encoded
    // inputs CLIENT-SIDE and skip `/die/understand` when we already
    // know we're going to chain-decode.  Saves the ~1–2 s round-trip
    // that provides no additional information for these inputs.
    const _fastPartsCheck = splitCommandLines(input);
    const _fastProse =
      (input || "").length > 400 &&
      /(?:^|\n)(?:the\s|talos\s|initial access|discovery|lateral movement|executive summary|engagement\s\d|mandiant|crowdstrike|microsoft defender|securex|falcon overwatch|customer\s|outcome|main research question|defensive)/i
        .test(input || "");
    const _fastMultiLayerMarker = /(?:\s-e(?:nc(?:od(?:ed(?:command)?)?)?)?\b\s*[A-Za-z0-9+/=]{100,})|FromBase64String\s*\(\s*["'][A-Za-z0-9+/=]{100,}|IO\.Compression\.Gzip|invoke-expression\s*\(\s*.+FromBase64/i;
    const _fastSingleMultiLayer =
      _fastPartsCheck && _fastPartsCheck.length === 1 &&
      typeof input === "string" &&
      input.length >= 120 &&
      _fastMultiLayerMarker.test(input) &&
      !_fastProse;
    const _fastChain =
      (_fastPartsCheck && _fastPartsCheck.length > 1 && _fastPartsCheck.length <= 20 && !_fastProse)
      || _fastSingleMultiLayer;

    if (_fastChain) {
      // Fast-path: go straight to chain analysis.  Chain-mode
      // produces MITRE + IOCs + LOLBAS + verdict + narrative all
      // by itself — no need for /die/understand or the parallel
      // /die/analyze + /die/narrate calls.
      setUnderstandingLoading(false);
      setStatus("AUTO-INVESTIGATE ▸ CHAIN DECODING…");
      try {
        await runChainAnalysis(_fastPartsCheck, { autoInvoked: true });
      } finally {
        // UX-FIX (2026-02-09) — drop the button-glow flag now that
        // the chain path has completed (or thrown).
        setAnalyzing(false);
      }
      return;
    }

    // ── IUE first — classify the input before touching decoders ──
    // Per WORKSPACE_ARCHITECTURE_RULES.md · R10: the decoder is a
    // capability, not the driver.  It runs only when the IUE says so.
    let understandingResp = null;
    try {
      understandingResp = await api.post("/die/understand", { input, execute: true });
      setUnderstanding(understandingResp?.data?.understanding || null);
      setUnderstandingLoading(false);
    } catch (e) {
      setUnderstandingError(e?.response?.data?.detail || e?.message || String(e));
      setUnderstandingLoading(false);
    }
    const decodeRequired = !!(understandingResp?.data?.understanding?.decode_required);

    // 2026-02-09 · Anti-Freeze SLA — CRITICAL PATH REORDER.
    // The classic bug: firing /die/analyze + /die/narrate in
    // parallel BEFORE the chain path is chosen means when the
    // chain response returns, THREE promise chains resolve within
    // ~100ms of each other, triggering >20 interleaved setState
    // calls.  React 18 can't auto-batch across async boundaries
    // and each setState re-reconciles the 3,787-line workspace
    // tree.  Total reconciliation work → 15 s+ → Page Unresponsive.
    //
    // Fix: DECIDE THE ROUTE FIRST.  If the input is a
    // single-command multi-layer payload, we're going to chain-
    // mode which produces ALL of analyze + narrate + iocs +
    // mitre + lolbas by itself — no need for the parallel calls.
    const parts = _fastPartsCheck;
    const looksLikeProse = _fastProse;
    const _multiLayerMarker = _fastMultiLayerMarker;
    const _isSingleMultiLayer = _fastSingleMultiLayer;
    const _willChain = _fastChain;

    // Only fire analyze + narrate when we are NOT going to chain
    // — chain-mode fully supersedes them.
    if (!_willChain) {
      // Kick off analyze + narrate in parallel — always needed for
      // Inline Story, Trajectory, Analyst Narrative panels.
      api.post("/die/analyze", { input })
        .then((r) => {
          const pre = r?.data?.result?.preprocessor
                   || r?.data?.result?.chain?.preprocessor
                   || null;
          if (pre) setInlineStoryPreproc(pre);
        })
        .catch(() => { /* silently absent */ });
      api.post("/die/narrate", { input })
      .then((r) => {
        setAnalystNarrative(r?.data?.narrative || null);
      })
      .catch(() => { /* silently absent */ });
    }  // end of `if (!_willChain)` — parallel /die/analyze + /die/narrate

    // ── If no decoding is required, hand off to the Investigation
    // Results renderer.  The pane displays deterministic findings —
    // never an echo of the input.
    if (!decodeRequired) {
      setStatus("INVESTIGATION READY · NO DECODE REQUIRED · RENDERING FINDINGS…");
      try {
        const ok = await runInvestigationResults(input);
        if (ok) {
          setStatus("INVESTIGATION READY · DETERMINISTIC RESULTS RENDERED");
        } else {
          setStatus("INVESTIGATION READY · (fallback view)");
        }
      } finally {
        // UX-FIX (2026-02-09) — drop the button-glow flag now that
        // the URL / atomic-IOC / prose path has completed.
        setAnalyzing(false);
      }
      return;
    }

    // ── Decoding required — fall through to the classic chain /
    // decode-smart pipeline (unchanged behaviour).
    // Multi-command chain? Route to /decode/chain so every stage's IOCs /
    // MITRE / LOLBAS reach the top-level Attack Graph & Kill Chain.
    //
    // 2026-02-09 · The chain-detection variables (parts, looksLikeProse,
    // _willChain, _isSingleMultiLayer) are pre-computed above so we can
    // suppress the parallel /die/analyze + /die/narrate fire-and-forget
    // when a chain is about to run.  Reuse the same values here.
    if (_willChain) {
      try {
        await runChainAnalysis(parts, { autoInvoked: true });
      } finally {
        setAnalyzing(false);
      }
      return;
    }
    streamStopRef.current?.();
    setLoading(true); setAnalyzing(true);
    setTacticFilter(null);
    setStatus("AUTO-INVESTIGATE ▸ SMART DECODING…");
    try {
      // 1) Deterministic decode first (fast — now uses smart+magic race for deepest chain)
      const r = await api.post("/decode/smart", { input });
      applyIeddeFromResponse(r.data);
      const newSteps = (r.data.recipe || []).map((s) => ({ op: s.op, args: s.args || {} }));
      setSteps(newSteps);
      // Feb 2026 · v1.5.5 · Shared canonical output selector — same
      // helper the DECODE button uses, so both flows always land the
      // same terminal artifact in the OUTPUT panel. See
      // /app/frontend/src/lib/selectCanonicalOutput.js for the
      // priority ladder (recipe → semantic → trace-tail → smart).
      const _sel = await selectCanonicalOutput({ api, input, smartResp: r.data });
      setOutput(_sel.text);
      setDetected(r.data.detected_type || null);
      const newChain = (r.data.recipe || []).map((s, i) => ({
        op: s.op, reason: s.reason || "",
        output_preview: r.data.trace?.[i]?.output_preview || "",
        custom: !!s.custom, model_id: s.model_id, model_name: s.model_name,
      }));
      setChain(newChain);
      // Decoding Trace panel data
      setDecodeTrace(r.data.trace || []);
      setDecodeWinnerEngine(r.data.engine || null);
      setDecodeConfidence(r.data.confidence ?? null);
      setReachedShellcode(!!r.data.reached_shellcode);
      setSemantic(r.data.semantic || null);
      setInvestigation(r.data.investigation || null);
      // P0.2 · RC2.9 — surface the backend verdict card immediately so
      // the top "Analysis Verdict" panel populates from the deterministic
      // decode step, not just after the async /analyze job finishes.
      setVerdictCard(r.data.verdict_card || null);
      setPasteHint(null); // dismiss the paste suggestion once we've decoded
      setLoading(false);

      // 2) Analysis via async job polling (bypasses 60s proxy timeout)
      // RC3.0: AI narrative + AI verdict fire ONLY when the analyst has
      // explicitly picked an AI persona (personaId non-empty). PLAIN mode
      // keeps everything deterministic — no LLM latency, no LLM cost.
      const aiEnabled = !!personaId;
      pollAnalyzeJob(
        { input, output: r.data.output || "", enrich_osint: true,
          describe: aiEnabled, use_ai_verdict: aiEnabled,
          persona_id: personaId || undefined, provider_id: providerId || undefined },
        newChain,
      );
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
      setLoading(false); setAnalyzing(false);
    }
  };

  const cancelStream = () => {
    streamStopRef.current?.();
    streamStopRef.current = null;
    setAnalyzing(false); setLoading(false);
    setStatus("STREAM CANCELLED");
  };

  const troubleshoot = async (useAI = false) => {
    setLoading(true);
    setStatus(useAI ? "TROUBLESHOOT ▸ deterministic + AI escalation…"
                    : "TROUBLESHOOT ▸ deterministic rules…");
    try {
      const r = await api.post(`/troubleshoot/auto?use_ai=${useAI ? "true" : "false"}`,
                               { input, steps, error: null });
      const d = r.data;
      // Auto-apply the repaired state to the workspace
      if (d.final_steps?.length) {
        setSteps(d.final_steps.map((s) => ({ op: s.op, args: s.args || {} })));
      }
      if (d.final_output != null) {
        setOutput(d.final_output);
      }
      if (d.final_engine) setDecodeWinnerEngine(d.final_engine);
      if (d.final_confidence != null) setDecodeConfidence(d.final_confidence);
      setReachedShellcode(!!d.reached_shellcode);

      // Surface diagnostics as a compact toast + trace
      const trace = (d.diagnoses || []).map((diag) => ({
        step: "troubleshoot",
        engine: diag.severity.toUpperCase(),
        note: `[${diag.code}] ${diag.message}${diag.auto_fixed ? " ✓ AUTO-FIXED" : ""}`,
      }));
      if (d.fixes_applied?.length) {
        trace.push({
          step: "done",
          note: `${d.fixes_applied.length} auto-fix(es) applied: ${d.fixes_applied.join("; ")}`,
        });
      }
      setNivxrayTrace(trace);
      setStatus(d.human_summary || (d.success ? "TROUBLESHOOT OK" : "TROUBLESHOOT — NO FIXES POSSIBLE"));
    } catch (e) {
      setStatus("ERROR: " + (e?.response?.data?.detail || e.message));
    } finally {
      setLoading(false);
    }
  };

  const doShare = async () => {
    try {
      const r = await api.post("/share", { input, steps });
      const url = `${window.location.origin}/?share=${r.data.token}`;
      setShareUrl(url);
      navigator.clipboard.writeText(url);
      setStatus("SHARE LINK COPIED");
    } catch (e) {
      setStatus("SHARE FAILED: " + e.message);
    }
  };

  const downloadReport = async (fmt = "html") => {
    if (typeof fmt !== "string") fmt = "html";
    setStatus(`GENERATING ${fmt.toUpperCase()} REPORT...`);
    try {
      const aiEnabled = !!personaId;
      const r = await api.post(`/report/${fmt}`,
        { input, output, enrich_osint: true,
          describe: !!output && aiEnabled,
          use_ai_verdict: !!output && aiEnabled,
          persona_id: personaId || undefined, provider_id: providerId || undefined },
        { responseType: "blob" }
      );
      const disp = r.headers?.["x-filename"] || r.headers?.["content-disposition"] || "";
      let filename = `nivxray_report.${fmt}`;
      const m = /filename="?([^"]+)"?/.exec(disp);
      if (m) filename = m[1];
      const url = URL.createObjectURL(r.data);
      const a = document.createElement("a");
      a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
      setStatus(`REPORT DOWNLOADED (${fmt.toUpperCase()})`);
    } catch (e) {
      setStatus("REPORT FAILED: " + (e?.response?.data?.detail || e.message));
    }
  };

  // Feb 2026 · Save the current workspace case (input+output+trace) with a
  // friendly name → recallable from Case Library page.
  const saveCase = async (opts = {}) => {
    if (!input || !output) {
      setStatus("SAVE CASE: run a decode first"); return;
    }
    // Feb-2026 UX · if the case already has a name from an earlier save,
    // reuse it silently (no prompt) so dynamic edits/re-decodes upsert
    // rather than force the analyst to re-type the name.  Only prompt on
    // the FIRST save, or when the user explicitly clicks SAVE AS (opts.forcePrompt).
    let name = savedCaseName;
    if (!name || opts.forcePrompt) {
      name = window.prompt(
        savedCaseName ? "Save this case AS a new name:" : "Name this case (for future reference):",
        savedCaseName || `Case · ${new Date().toLocaleString()}`,
      );
      if (!name) return;
    }
    setStatus(savedCaseName && !opts.forcePrompt ? `UPDATING CASE "${name}"...` : "SAVING CASE...");
    try {
      // ── Feb 2026 P0 · Full SSOT persistence bundle ───────────────────
      // Ship the complete analyst-facing Single-Source-Of-Truth so that
      // reopening the case restores 100% of the investigation WITHOUT
      // re-running /die/understand, /die/analyze or /die/narrate.
      const ssotBundle = {
        version: "1.0",
        understanding,
        analyst_narrative: analystNarrative,
        inline_story_preproc: inlineStoryPreproc,
        investigation_object: investigationObject,
        investigation_mode: investigationMode,
        verdict_card: verdictCard,
        decode_trace: decodeTrace,
        decode_winner_engine: decodeWinnerEngine,
        decode_confidence: decodeConfidence,
        iedde,
        iedde_terminal_state: iddeTerminalState,
        canonical_confidence: canonicalConfidence,
        canonical_confidence_reason: canonicalConfidenceReason,
        mitre: analysis?.mitre || [],
        lolbas: analysis?.lolbas || [],
        semantic,
        reached_shellcode: reachedShellcode,
        corrupted_container: corruptedContainer,
        chain,
        steps,
        predicted_tree: predictedTree,
        analysis,
      };
      const r = await api.post("/cases/save", {
        name,
        input,
        output,
        engine: decodeWinnerEngine || "-",
        confidence: decodeConfidence ?? null,
        chain_ids: (chain || []).map((c) => c.op_id || c.id).filter(Boolean),
        verdict: verdictCard?.verdict || analysis?.ai_verdict || null,
        iocs: analysis?.iocs || {},
        ssot: ssotBundle,
      });
      setSavedCaseName(name);
      const wasUpdate = !!r.data?.updated;
      // ▲ Phase 4 · P2.1 · resolve the case id so "Find Related" lights up
      //   without forcing a page navigation. /cases/save doesn't return
      //   the history id, so hit /history?q= with the case name.
      try {
        const hr = await api.get("/history", { params: { q: name, limit: 5 } });
        const found = (hr.data?.items || hr.data?.history || [])
          .find(x => x.case_name === name);
        if (found?.id) setCurrentCaseId(String(found.id));
      } catch (_) { /* non-fatal — button just stays disabled */ }
      setStatus(
        wasUpdate
          ? `CASE UPDATED: "${name}"`
          : `CASE SAVED: "${name}" (id=${(r.data?.id || "").slice(0, 8)})`
      );
    } catch (e) {
      const raw = e?.response?.data;
      let msg = raw?.detail || raw?.error || raw?.message || e?.message || String(e);
      if (Array.isArray(msg)) {
        msg = msg.map((v) => (v?.msg && v?.loc ? `${v.loc.join(".")}: ${v.msg}` : (v?.msg || JSON.stringify(v))))
                 .join(" · ");
      } else if (typeof msg === "object" && msg !== null) {
        msg = msg.msg || msg.error || JSON.stringify(msg);
      }
      setStatus("SAVE CASE FAILED: " + msg);
    }
  };

  const onUpload = async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    // ── Phase 5.W.2 (2026-08-10) · Anti-hang upload path ─────────────
    // Symptom: uploading a 40 KB SEP.csv left the tab frozen at
    // "UPLOADING …" with the "Page Unresponsive" dialog.
    // Guards applied here:
    //   (a) Hard client-side size cap — >2 MB is rejected with a
    //       clear message BEFORE any network work.
    //   (b) 25 s abort budget on the /upload POST — any longer and
    //       we surface an actionable error instead of hanging.
    //   (c) startTransition around all post-response setState calls
    //       so React batches the re-render with low priority and the
    //       expensive AnalystNarrativePanel / TrajectoryDiagram trees
    //       cannot starve the main thread while the analyst is
    //       still trying to type.
    //   (d) The file-input onChange dropzone is reset FIRST so a
    //       failed attempt does not leave the file selected.
    // 2026-08-11 · Client-side upload cap lowered from 2 MB → 256 KB
    // after black-screen reports on 44 KB and 530 KB uploads.  The
    // freeze is caused downstream (setInput → controlled textarea
    // re-render → AnalystNarrative + TrajectoryDiagram cascade with
    // 500+ KB of raw text in React state).  A proper large-file
    // flow (server-side content persistence, no React-state echo)
    // is required to lift this — tracked as a future enhancement.
    const MAX_UPLOAD_BYTES = 256 * 1024;   // 256 KB
    if (f.size > MAX_UPLOAD_BYTES) {
      setStatus(
        `UPLOAD REJECTED · ${f.name} is ${(f.size/1024).toFixed(0)} KB ` +
        `(current safe max 256 KB) — please sample a smaller subset. ` +
        `Large-file support without React-state echo is planned as a ` +
        `separate enhancement.`
      );
      e.target.value = "";
      return;
    }
    const fd = new FormData();
    fd.append("file", f);
    startTransition(() => {
      setStatus(`UPLOADING ${f.name}... (${(f.size/1024).toFixed(0)} KB)`);
      // Free the heavy state fields from the PREVIOUS investigation
      // BEFORE we start the upload. Without this, useIdlePersist has
      // to JSON.stringify a fully-populated investigationObject +
      // analystNarrative on every subsequent state change during the
      // upload flow, which blocks the main thread for tens of seconds.
      setInput("");
      setOutput("");
      setInvestigationObject(null);
      setAnalystNarrative(null);
      setUnderstanding(null);
      setInlineStoryPreproc(null);
      setChain([]);
      setAnalysis(null);
      setDetected(null);
    });
    try {
      const controller = new AbortController();
      workspaceAbortRef.current = controller;
      const abortTimer = setTimeout(() => controller.abort(new Error("client-upload-timeout-25s")), 25_000);
      const r = await api.post("/upload", fd, {
        headers: { "Content-Type": "multipart/form-data" },
        signal:  controller.signal,
        timeout: 25_000,
      });
      clearTimeout(abortTimer);
      workspaceAbortRef.current = null;
      const type   = r.data.file_type?.label || "?";
      const md5    = r.data.hashes?.md5 || "";
      const cnt    = r.data.content || "";
      // Batch all post-response state mutations at low priority so any
      // AnalystNarrativePanel / TrajectoryDiagram re-render cascade
      // yields to user input and paint. React 18 startTransition here
      // is the difference between "instant" and "Page Unresponsive".
      startTransition(() => {
        setInput(cnt);
        setStatus(`LOADED: ${r.data.filename} · ${r.data.size} bytes · ${type} · MD5=${md5.slice(0, 12)}…`);
      });
    } catch (e2) {
      const msg = e2?.name === "AbortError"
        ? "UPLOAD FAILED: request took longer than 25 s (network stall or backend cold-start) — retry or use a smaller sample"
        : "UPLOAD FAILED: " + (e2?.response?.data?.detail || e2.message);
      setStatus(msg);
    } finally {
      e.target.value = "";
    }
  };

  const loadExample = (ex) => {
    setInput(ex.input);
    setOutput("");
    setSteps([]);
    setChain([]);
    setAnalysis(null);
    setDetected(null);
    setStatus(`LOADED EXAMPLE: ${ex.label}`);
  };

  // support ?share=... on load
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const share = p.get("share");
    if (share) {
      api.get(`/share/${share}`).then((r) => {
        setInput(r.data.input || "");
        setSteps(r.data.steps || []);
        setStatus("LOADED SHARED RECIPE");
      }).catch(() => setStatus("INVALID SHARE LINK"));
    }
  }, []);

  return (
    <InvestigationFilterProvider>
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }} className="App">
      <Header />

      {/* Corporate hero — matches every other page. */}
      <div style={{ padding: "16px 24px 0" }}>
        <PageHeader
          testId="workspace-hero"
          eyebrow={`Analyst Workspace · ${ops.length || 87} operations · deterministic-first`}
          title="Analyst Workspace"
          subtitle="Paste an obfuscated command-line, drop a suspicious script, or drag any analyst artefact. The deterministic pipeline reconstructs the executable command, maps MITRE / LOLBAS / IOC / OSINT signals and produces an evidence-grounded verdict — with optional AI enrichment layered on top."
          icon={LayoutGrid}
          tone="accent"
          compact
        />
      </div>

      {/* Toolbar strip */}
      <div
        className="brut-border"
        style={{
          borderLeft: "none", borderRight: "none", borderTop: "none",
          padding: "10px 16px", display: "flex", gap: 8, alignItems: "center",
          flexWrap: "wrap", background: "var(--surface)",
        }}
      >
        <span className="badge">{ops.length || 87} OPS</span>
        <span className="badge warn">MITRE</span>
        <span className="badge warn">YARA</span>
        <span className="badge warn">LOLBAS</span>
        <span className="badge warn">IOC</span>
        <span className="badge warn">OSINT</span>
        <span className="badge warn">FLOW</span>
        <div style={{ flex: 1 }} />

        {(personas.length > 0 || providers.length > 0) && (
          <div style={{ display: "flex", gap: 6, alignItems: "center" }} data-testid="ai-model-picker">
            {personas.length > 0 && (
              <select
                className="brut-input"
                value={personaId}
                onChange={(e) => setPersonaId(e.target.value)}
                data-testid="ai-persona-select"
                title={
                  "AI PERSONA — the system prompt / analyst voice.\n\n" +
                  "★ NivX Cognis (recommended) — in-house flagship trained on Sophos layered-stager decoding + MITRE + LOLBAS.\n" +
                  "  Use for: malware triage, obfuscated PowerShell, LOLBin chains, shellcode reasoning.\n\n" +
                  "Default (JSON) — bare structured-output prompt.\n" +
                  "  Use for: quick sanity checks, when you want raw LLM reasoning without SOC-specific context.\n\n" +
                  "Custom personas — created in Model Studio → AI Personas."
                }
                style={{ padding: "4px 8px", fontSize: 11, height: 28, background: "var(--inset)" }}
              >
                <option value="">★ PLAIN · Deterministic (no AI)</option>
                {personas.map((p) => (
                  <option key={p.id} value={p.id}>
                    {`${/nivx\s*cognis/i.test(p.name) ? "★ PERSONA · " : "PERSONA · "}${p.name}`}
                  </option>
                ))}
              </select>
            )}
            {providers.length > 0 && (
              <select
                className="brut-input"
                value={providerId}
                onChange={(e) => setProviderId(e.target.value)}
                data-testid="ai-provider-select"
                title={
                  "LLM PROVIDER — which model executes the AI steps.\n\n" +
                  "Default (Claude Sonnet 4.5) — best balance of accuracy + speed for malware triage.\n" +
                  "  Use for: everything, unless you have a specific reason to switch.\n\n" +
                  "GPT-5.2 — stronger on obscure JavaScript / eval-chain deobfuscation.\n" +
                  "Gemini 3 Pro — strongest for multi-modal (screenshots) and non-English lures.\n\n" +
                  "All providers use the Emergent Universal LLM Key. Switch in Model Studio → LLM Providers."
                }
                style={{ padding: "4px 8px", fontSize: 11, height: 28, background: "var(--inset)" }}
              >
                <option value="">LLM · Default</option>
                {providers.map((p) => <option key={p.id} value={p.id}>{`LLM · ${p.name}`}</option>)}
              </select>
            )}
          </div>
        )}

        {/* Real-time input classifier — glows the right buttons + shows a stepper */}
        <GuidanceBanner input={input} className="nvx-guidance-banner"
                         data-testid="input-guidance-banner-wrapper" />

        {/* PRIMARY — full SOC pipeline (decode + MITRE + IOCs + LOLBAS + verdict) */}
        <button className={`nvx-btn primary${(loading || analyzing) ? " busy" : ""}`} onClick={autoInvestigate} disabled={loading || analyzing}
                data-testid="btn-auto-investigate"
                title={
                  "AUTO INVESTIGATE — the default one-click SOC brief.\n" +
                  "Runs: deterministic decode → MITRE ATT&CK map → IOCs → LOLBAS → Verdict card.\n" +
                  "AI narrative fires ONLY if you pick an AI persona from the dropdown.\n\n" +
                  "▸ USE WHEN: literally always. This is what you want 95% of the time."
                }
                style={{
                  fontSize: 13, padding: "8px 18px",
                  ...(getGuidanceGlowStyle(input, "btn-auto-investigate") || {}),
                }}>
          {(loading || analyzing)
            ? <>INVESTIGATING…</>
            : <><Sparkles size={14} /> AUTO INVESTIGATE</>}
        </button>

        {/* SECONDARY — deterministic decode only, no enrichment. Faster. */}
        <button className={`nvx-btn${(loading || analyzing) ? " busy" : ""}`} onClick={nivxrayDecode} disabled={loading || analyzing}
                data-testid="btn-nivxray-decode"
                title={
                  "DECODE — deterministic decoder chain only, no enrichment.\n" +
                  "Faster than Auto Investigate; skips MITRE/OSINT/verdict-card.\n\n" +
                  "▸ USE WHEN: you just want the payload peeled and don't need the SOC brief."
                }
                style={{ fontSize: 12, padding: "7px 14px" }}>
          {(loading || analyzing)
            ? <>DECODING…</>
            : <><Zap size={13} /> DECODE</>}
        </button>

        <button className="nvx-btn ghost" onClick={() => setAdvancedOpen((v) => !v)}
                data-testid="btn-advanced-toggle"
                title="Advanced modes: AI Decode · Smart Decode · Recovery mode">
          {advancedOpen ? "▾ ADVANCED" : "▸ ADVANCED"}
        </button>
        {analyzing && (
          <button className="nvx-btn warn" onClick={cancelStream} data-testid="btn-cancel-stream">
            <X size={13} /> CANCEL
          </button>
        )}
        <button className="nvx-btn ghost"
                onClick={() => window.location.assign("/history")}
                data-testid="btn-open-history"
                title="Investigation History (full page) — auto-saved for 30 days (starred entries kept forever).">
          📜 HISTORY
        </button>
        <button className="nvx-btn ghost" onClick={() => setCasesOpen(true)} data-testid="btn-open-cases"
                title="Case Library — named cases you've saved. Re-decode, open, or delete."
                style={{ borderColor: "#7ee3c9", color: "#7ee3c9" }}>
          💾 CASES
        </button>
        {advancedOpen && (
        <>
        <button className="nvx-btn" onClick={() => autoDecode({ smart: false })} disabled={loading} data-testid="btn-ai-decode"
                title={
                  "AI DECODE — LLM proposes a recipe (base64/gzip/XOR/etc.) with SOC anti-hallucination guard.\n" +
                  "Requires an AI persona (dropdown above) — no-op in PLAIN mode.\n\n" +
                  "▸ USE WHEN: the payload is unusual and you want the LLM to reason about the format.\n" +
                  "▸ SAFETY: if confidence < 35/100 it STOPS gracefully (no garbage output).\n" +
                  "▸ COST: 1 LLM call (~3–8s)."
                }
                style={getGuidanceGlowStyle(input, "btn-ai-decode") || undefined}>
          <Wand2 size={13} /> AI DECODE
        </button>
        <button className="nvx-btn" onClick={() => autoDecode({ smart: true })} disabled={loading} data-testid="btn-smart-decode"
                title={
                  "SMART DECODE — signature-first deterministic recipe. No AI. Faster than Auto Investigate.\n" +
                  "Rule-based recipe selection using signature prefixes (H4sI→gzip, JAB/SQBF→UTF-16LE, TVq→PE, etc).\n\n" +
                  "▸ USE WHEN: you need repeatable results (regression tests, high-volume automation, air-gapped)."
                }
                style={getGuidanceGlowStyle(input, "btn-smart-decode") || undefined}>
          <Zap size={13} /> SMART DECODE
        </button>
        {/* Feb-2026 · Corrupted-Container recovery mode toggle */}
        <div
          data-testid="recovery-mode-toggle"
          className="mono"
          style={{
            display: "inline-flex",
            alignItems: "stretch",
            border: "1px solid var(--border)",
            borderRadius: 2,
            marginLeft: 4,
            fontSize: 10,
            letterSpacing: "0.10em",
          }}
          title={
            "Corrupted-Container recovery mode.\n\n" +
            "STRICT (default) — Report CRC/trailer failures as Corrupted. Salvaged\n" +
            "  plaintext is available on `corrupted_container.salvaged` for reference.\n\n" +
            "BEST-EFFORT — Elevate salvaged plaintext to the primary output with a\n" +
            "  permanent ⚠ Integrity Warning. Verdict downgrades Corrupted → Suspicious\n" +
            "  so the payload can flow into Sample Library / TAXII / SIEM."
          }
        >
          <button
            onClick={() => setRecoveryModePersisted("strict")}
            data-testid="recovery-mode-strict"
            style={{
              padding: "4px 10px",
              background: recoveryMode === "strict" ? "var(--accent)" : "transparent",
              color: recoveryMode === "strict" ? "var(--bg)" : "var(--text-mute)",
              border: "none",
              cursor: "pointer",
            }}
          >
            STRICT
          </button>
          <button
            onClick={() => setRecoveryModePersisted("best_effort")}
            data-testid="recovery-mode-best-effort"
            style={{
              padding: "4px 10px",
              background: recoveryMode === "best_effort" ? "var(--warn)" : "transparent",
              color: recoveryMode === "best_effort" ? "var(--bg)" : "var(--text-mute)",
              border: "none",
              borderLeft: "1px solid var(--border)",
              cursor: "pointer",
            }}
          >
            BEST-EFFORT
          </button>
        </div>
        <button className="nvx-btn" onClick={magicDecode} disabled={loading} data-testid="btn-magic-decode"
                style={{ borderColor: "var(--warn)", color: "var(--warn)" }}
                title={
                  "MAGIC — Recursive multi-branch auto-decoder (CyberChef Magic parity).\n" +
                  "Tries every plausible op combination, scores each candidate (readability + shellcode prologue + IOC density), and returns the top-N chains for you to pick.\n\n" +
                  "▸ USE WHEN: input is heavily obfuscated (nested base64+gzip+XOR); you want to see multiple candidate chains ranked side-by-side.\n" +
                  "▸ COST: <500ms typically, no LLM.\n" +
                  "▸ RETURNS: top 5 chains with per-step ops + confidence score + shellcode flag."
                }>
          <Wand2 size={13} /> MAGIC
        </button>
        <button className="nvx-btn" onClick={runRecipe} disabled={loading || !steps.length} data-testid="btn-run-recipe"
                title={
                  "RUN RECIPE — Execute the current step list against the input.\n" +
                  "Use this when you've hand-built the recipe (via the Operations panel) or edited a Smart/Magic/AI Decode output.\n\n" +
                  "▸ COST: <100ms, no LLM.\n" +
                  "▸ Sends to backend. For a 0-latency preview of JS-supported ops, watch the OUTPUT card update as you edit the recipe."
                }>
          <Play size={13} /> RUN RECIPE
        </button>
        <button className="nvx-btn warn" onClick={() => troubleshoot(false)} disabled={loading} data-testid="btn-troubleshoot"
                title={
                  "TROUBLESHOOT — Universal one-click auto-fix.\n\n" +
                  "▸ WORKS OFFLINE (no LLM). Fixes at runtime:\n" +
                  "   • Base64 padding / alphabet corruption\n" +
                  "   • Truncated gzip / partial deflate\n" +
                  "   • Recipe stopped too early → applies deeper archetype\n" +
                  "   • Missing IOCs in shellcode → XOR-key sweep\n" +
                  "   • Over-decoded tail (rot13/reverse) → trimmed\n" +
                  "   • Low-confidence stall → escalates to magic-decoder\n" +
                  "   • Op crashes → rolls back to last good layer\n\n" +
                  "▸ AUTO-APPLIES the fix to the workspace (recipe + output).\n" +
                  "▸ Use `TROUBLESHOOT + AI` for LLM escalation if deterministic fails."
                }>
          <Wrench size={13} /> TROUBLESHOOT
        </button>
        <button className="nvx-btn warn" onClick={() => troubleshoot(true)} disabled={loading} data-testid="btn-troubleshoot-ai"
                title={
                  "TROUBLESHOOT + AI — Same deterministic pipeline as above, then\n" +
                  "escalates to the LLM (Claude Sonnet 4.5) ONLY if the offline rules\n" +
                  "leave the payload undecoded. LLM proposes a new recipe based on the\n" +
                  "collected diagnostics.\n\n" +
                  "Costs 1 LLM call (~3-6s) only when needed."
                }>
          <Sparkles size={13} /> TROUBLESHOOT + AI
        </button>
        </>
        )}
        <button className="nvx-btn" onClick={doShare} data-testid="btn-share"><Share2 size={13} /> SHARE</button>
        <button className="nvx-btn ghost" onClick={shareRecipe} data-testid="btn-share-url"
                title="Copy a URL that reproduces the current input + recipe (fully client-side)">
          <Share2 size={13} /> COPY LINK
        </button>
        <ReportMenu onDownload={downloadReport} />
        <button className="nvx-btn" onClick={saveCase} data-testid="btn-save-case"
                style={{borderColor:"#7ee3c9",color:"#7ee3c9"}}
                title={savedCaseName
                  ? `Update the saved case "${savedCaseName}" with the current workspace state`
                  : "Save this decoded case to the Case Library with a friendly name"}>
          💾 {savedCaseName ? `UPDATE "${savedCaseName.length > 20 ? savedCaseName.slice(0,20)+"…" : savedCaseName}"` : "SAVE CASE"}
        </button>
        {/* Phase 4 · P2.1 (2026-02-15) — Workspace-native Find Related Cases.
            Enabled only when the current workspace state is anchored to a
            saved / restored case (currentCaseId). Deterministic scan runs
            in the same overlay drawer used by History rows. */}
        <button className="nvx-btn"
                data-testid="btn-find-related-workspace"
                onClick={() => currentCaseId && setFindRelatedOpen(true)}
                disabled={!currentCaseId}
                style={{
                  borderColor: currentCaseId ? "#c4b5fd" : "rgba(148,163,184,0.20)",
                  color: currentCaseId ? "#c4b5fd" : "#64748b",
                  cursor: currentCaseId ? "pointer" : "not-allowed",
                  opacity: currentCaseId ? 1 : 0.55,
                }}
                title={currentCaseId
                  ? "Find related cases — deterministic scan across your history for shared hashes, URLs, C2, and MITRE overlap"
                  : "Save this case first (💾 SAVE CASE) or restore one from History — Find Related runs against a persisted case."}>
          🔍 FIND RELATED
        </button>
        <button className="nvx-btn" onClick={() => fileRef.current?.click()} data-testid="btn-upload">
          <Upload size={13} /> UPLOAD
        </button>
        <input type="file" ref={fileRef} onChange={onUpload} hidden data-testid="file-input" />
      </div>

      {/* Status bar */}
      <div
        style={{
          padding: "6px 16px", background: "var(--inset)",
          borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: 14,
        }}
      >
        {(() => {
          // Feb-2026 v1.2.0 · Colour-coded STATUS bar so analysts can tell
          // ERROR / SUCCESS / IN-PROGRESS / INFO apart at a glance.
          const raw = String(status || "");
          const lower = raw.toLowerCase();
          let dot = "var(--accent)"; let text = "var(--text-dim)"; let label = "STATUS";
          if (/^notice/i.test(raw)) {
            // Intentional admin-off states etc. — informational only.
            dot = "#38bdf8"; text = "#38bdf8"; label = "NOTICE";
          } else if (/error|failed|stream error|chain error|flat decode error/i.test(raw)) {
            dot = "var(--high, #ef4444)"; text = "var(--high, #ef4444)"; label = "ERROR";
          } else if (/complete|ok\b|analysis complete|success|ready|✓/i.test(lower)) {
            dot = "#22c55e"; text = "#22c55e"; label = "OK";
          } else if (/running|decoding|analyz|streaming|loading|generating|working/i.test(lower)) {
            dot = "#f59e0b"; text = "#f59e0b"; label = "RUNNING";
          } else if (/warn|partial|no.*match|not\s+found/i.test(lower)) {
            dot = "#eab308"; text = "#eab308"; label = "WARN";
          }
          return (
            <>
              <span className="mono" data-testid="status-dot" style={{ fontSize: 10, color: dot, letterSpacing: "0.2em" }}>
                ● {label}
              </span>
              <span className="mono" data-testid="status-line" style={{ fontSize: 11, color: text }}>
                {status}
              </span>
            </>
          );
        })()}
        <div style={{ flex: 1 }} />
        {savedCaseName && (
          <span
            data-testid="workspace-case-name"
            className="mono"
            style={{
              fontSize: 10, letterSpacing: "0.14em",
              color: "#7ee3c9",
              border: "1px solid #7ee3c9",
              padding: "2px 8px",
              background: "rgba(126,227,201,0.08)",
              maxWidth: 340, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}
            title={`Saved case: ${savedCaseName}`}
          >
            💾 CASE · {savedCaseName}
          </span>
        )}
        <span className="mono" style={{ fontSize: 10, color: "var(--text-mute)" }}>
          INPUT {input.length}c · OUTPUT {output.length}c
        </span>
      </div>

      {/* Examples strip */}
      <div
        style={{
          padding: "8px 16px", background: "var(--bg)",
          borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap",
        }}
      >
        <span className="mono" style={{ fontSize: 10, letterSpacing: "0.2em", color: "var(--text-mute)" }}>
          LOAD EXAMPLE:
        </span>
        {examples.map((ex) => (
          <button
            key={ex.id}
            className="nvx-btn sm ghost"
            onClick={() => loadExample(ex)}
            data-testid={`example-${ex.id}`}
          >
            ◆ {ex.label}
          </button>
        ))}
      </div>

      {/* SOC VERDICT — appears above the workspace whenever a decode
          terminates on known shellcode / PE / ELF. Google-AI-style one-line
          verdict + copy-to-clipboard SOC ticket.

          FU-5 (v1.4.3): Gated behind SHOW_LEGACY_INVESTIGATION_SUMMARY —
          this panel produces a competing verdict surface. The Investigation
          Brain is the sole analyst-facing verdict authority. */}
      {SHOW_LEGACY_INVESTIGATION_SUMMARY && (
        <SocVerdictPanel
          output={output}
          confidence={decodeConfidence}
          winnerEngine={decodeWinnerEngine}
          predictedTree={predictedTree}
        />
      )}

      {/* ▲ RC4.5.7 · Analyst Quick Actions — Executive summary,
          confidence breakdown, and one-click block-rule generation.
          Pure UI synthesis from existing verdict_card + iocs — zero
          backend changes, zero decoder-engine touch.

          FU-5 (v1.4.3): Gated — synthesises verdict/confidence from the
          legacy verdictCard which competes with the Investigation Brain. */}
      {SHOW_LEGACY_INVESTIGATION_SUMMARY && (verdictCard || analysis) && (
        <div style={{ padding: "0 16px 12px" }}>
          <AnalystQuickActions
            result={{
              verdict_card: verdictCard || undefined,
              iocs: (analysis && analysis.iocs) || undefined,
              mitre: (analysis && analysis.mitre) || undefined,
              reached_shellcode: !!(verdictCard && verdictCard.reached_shellcode),
              family: (verdictCard && verdictCard.family) || (analysis && analysis.family),
              verdict: verdictCard && verdictCard.label,
              confidence: verdictCard && verdictCard.confidence,
            }}
          />
        </div>
      )}

      {/* ▲ CANDIDATE EXPLORER (Feb-2026) — ranked encoding candidates with
          structured "why-not" breakdowns, hex, IOCs, LOLBins, MITRE ATT&CK.
          Toggle button opens the panel; renders below when active and there
          is input to analyse. */}
      <div style={{ padding: "0 16px 8px", display: "flex", alignItems: "center", gap: 8 }}>
        <button
          className={`nvx-btn sm ${showCandidateExplorer ? "" : "ghost"}`}
          onClick={() => setShowCandidateExplorer((v) => !v)}
          data-testid="toggle-candidate-explorer"
        >
          {showCandidateExplorer ? "✕ Hide" : "◈ Show"} Candidate Explorer
        </button>
        <span style={{ fontSize: 11, color: "#94a3b8" }}>
          Ranked encoding candidates · evidence · why-not breakdown · IOCs / LOLBins / MITRE
        </span>
      </div>
      {showCandidateExplorer && input && input.trim().length > 0 && (
        <div style={{ padding: "0 16px 12px", display: "grid", gridTemplateColumns: "1fr 340px", gap: 12 }}>
          <CandidateExplorer
            input={input}
            testidPrefix="workspace-candidate-explorer"
          />
          <InvestigationTimeline
            input={input}
            testidPrefix="workspace-timeline"
          />
        </div>
      )}

      {/* MoE Analyst Panel toggle */}
      <div
        style={{
          padding: "8px 16px",
          display: "flex",
          alignItems: "center",
          gap: 10,
          borderTop: "1px solid #1e293b",
        }}
      >
        <button
          className={`nvx-btn sm ${showMoePanel ? "" : "ghost"}`}
          onClick={() => setShowMoePanel((v) => !v)}
          data-testid="toggle-moe-panel"
        >
          {showMoePanel ? "✕ Hide" : "▣ Show"} MoE Analyst Panel
        </button>
        <span style={{ fontSize: 11, color: "#94a3b8" }}>
          3-critic panel · Malware Analyst · Red Team · Defensive · Synthesiser (consensus + disagreements)
        </span>
      </div>
      {showMoePanel && input && input.trim().length > 0 && (
        <div style={{ padding: "0 16px 12px" }}>
          <MoEPanel input={input} testidPrefix="workspace-moe-panel" />
        </div>
      )}

      {/* ▲ SOC EVIDENCE-DRIVEN VERDICT CARD (Feb-2026) — RC2.9 P0.2:
          the legacy VerdictCard has been REPLACED by the 7-panel
          AnalystResults view (Analysis Verdict · Recovered Payload ·
          Chain Recipe · MITRE · IOCs · Network · Behavior) rendered
          just above. Legacy block kept commented for reference but
          intentionally not rendered.
       */}
      {/* {verdictCard && (<VerdictCard verdict={verdictCard} testidPrefix="workspace-verdict" />)} */}

      {/* Jul-2026 · PowerShell EncodedCommand Decode Failure Card
          — Locked with SOC user 2026-07-25. When the deterministic
          recovery chain fails, this card supersedes the OUTPUT panel's
          garbage rendering with a structured, hex-only preview + full
          list of recovery attempts + possible causes. It always
          renders at the top of the results section so the analyst
          sees it before scrolling to the OUTPUT box.
          Source of truth: the `ps-encodedcommand-recovery` step in
          `decodeTrace` — args carries the full DecodeReport. */}
      {(() => {
        const step = (decodeTrace || []).find(
          s => s && (s.op === "ps-encodedcommand-recovery" || s.decoder === "ps-encodedcommand-recovery")
                 && s.args && s.args.decode_error
        );
        if (!step) return null;
        const a = step.args || {};
        const err = {
          status: "decode_error",
          b64_bytes: a.b64_bytes,
          b64_status: a.b64_status || "succeeded",
          b64_reason: a.b64_reason || (a.b64_bytes ? `decoded to ${a.b64_bytes} bytes` : ""),
          first_invalid_offset: a.first_invalid_offset,
          invalid_reason: a.invalid_reason,
          hex_preview: a.hex_preview,
          possible_causes: a.possible_causes || [],
          attempts: a.recovery_attempts || a.attempts || [],
          partial_recovery: a.partial_recovery || {},
          confidence_band: a.confidence_band || "none",
          confidence_reason: a.confidence_reason || "",
          recovered_layers: a.recovered_layers || "0/0",
        };
        return <WorkspaceDecodeFailureCard err={err} />;
      })()}

      {/* ▲ v1.3.0 · Investigation Summary — sole verdict authority.
          The Investigation Brain (IU → CRE → RTE → Intent → Verdict
          → Graph → Report) is the SINGLE analyst-facing verdict
          source. Consumes `r.data.investigation` from /decode/smart. */}
      {investigation && (
        <div data-testid="workspace-investigation-brain">
          <InvestigationBrainPanel investigation={investigation} />
        </div>
      )}

      {/* PR-4 · Navigation bridge → L4 SOC Investigation Workspace.
          Shows when *any* decode/investigate result exists. Creates a
          case (deterministic case_id — idempotent on repeat clicks) and
          routes to /investigate/{case_id}. ARB scope: navigation only,
          no layout redesign, no new business logic. Full route
          consolidation is PR-7. */}
      {(output || decodeTrace?.length || verdictCard || investigation) && (
        <div
          data-testid="workspace-investigation-bridge"
          style={{
            margin: "0 16px 16px",
            padding: "12px 14px",
            border: "1px solid var(--accent, #3b82a0)",
            background:
              "linear-gradient(90deg, rgba(59,130,160,0.08), rgba(59,130,160,0.02))",
            borderRadius: 8,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <div style={{ minWidth: 0 }}>
            <div
              className="mono"
              style={{
                fontSize: 10,
                letterSpacing: "0.22em",
                color: "var(--text-mute)",
                marginBottom: 4,
              }}
            >
              SOC INVESTIGATION WORKSPACE · PR-4
            </div>
            <div style={{ fontSize: 13, color: "var(--text)" }}>
              Open this artefact in the analyst workspace to review the
              Summary + Attack Story lenses.
            </div>
          </div>
          <OpenInvestigationButton
            input={input}
            output={output}
            decodeResp={{
              output,
              trace: decodeTrace,
              recipe: chain,
              detected_type: detected,
              verdict_card: verdictCard,
              investigation,
              final_artifact_hash_sha256:
                (verdictCard && verdictCard.artifact_hash) || undefined,
              reached_shellcode: reachedShellcode,
            }}
            verdictCard={verdictCard}
            investigation={investigation}
          />
        </div>
      )}


      {/* ▲ Legacy trace · rc2-orchestrator output — retired from the
          analyst-facing verdict surface on 2026-07-29 (v1.3.0). Kept
          here inside a collapsed developer-diagnostics block so we
          can still validate the new pipeline against legacy signals
          during transition. Never generates the primary verdict.

          FU-5 (v1.4.3): Fully gated behind SHOW_LEGACY_INVESTIGATION_SUMMARY
          — even the collapsed disclosure emits a competing verdict when
          expanded. */}
      {SHOW_LEGACY_INVESTIGATION_SUMMARY && (verdictCard || analysis || output) && (
        <details
          data-testid="workspace-legacy-trace"
          style={{
            margin: "16px",
            padding: "10px 14px",
            background: "#0a1220",
            border: "1px dashed #2a3f5a",
            borderRadius: 8,
            color: "#7d95b3",
            fontSize: 12,
          }}
        >
          <summary
            style={{ cursor: "pointer", color: "#8fa5c2", fontSize: 11,
                      letterSpacing: 0.8, textTransform: "uppercase" }}
          >
            Developer view · legacy rc2-orchestrator trace (not analyst-facing)
          </summary>
          <div style={{ marginTop: 8 }}>
            <AnalystResults
              verdictCard={verdictCard}
              output={output}
              decodeTrace={decodeTrace}
              decodeConfidence={decodeConfidence}
              analysis={analysis}
            />
          </div>
        </details>
      )}

      {/* ▲ Phase 9.4 · Semantic Intelligence (2026-07-27) —
          RETIRED from the analyst-facing verdict surface on v1.3.0.
          Its Behavior Storyline / Executive Summary formerly produced
          a second "Runtime Dependent" verdict that competed with the
          Investigation Brain. Kept behind a developer disclosure so
          we can still validate storyline output during transition.

          FU-5 (v1.4.3): Fully gated behind SHOW_LEGACY_INVESTIGATION_SUMMARY. */}
      {SHOW_LEGACY_INVESTIGATION_SUMMARY && semantic && (
        <details
          data-testid="workspace-semantic-intelligence"
          style={{
            margin: "16px",
            padding: "10px 14px",
            background: "#0a1220",
            border: "1px dashed #2a3f5a",
            borderRadius: 8,
            color: "#7d95b3",
            fontSize: 12,
          }}
        >
          <summary
            style={{ cursor: "pointer", color: "#8fa5c2", fontSize: 11,
                      letterSpacing: 0.8, textTransform: "uppercase" }}
          >
            Developer view · legacy semantic storyline (not analyst-facing)
          </summary>
          <div style={{ marginTop: 8 }}>
            <SemanticIntelligencePanel semantic={semantic} chainIndex={0} />
          </div>
        </details>
      )}

      {/* RC3.1 · IR HANDOFF EXPORT — downloadable SOC brief from the
          Verdict header. Backend already exposes /api/v2/analyze/report
          in md / txt / json / pdf / stix formats. Analysts click the
          format they want; we re-run the deterministic orchestrator
          against the current input so the download always reflects the
          exact same findings surface visible on screen. */}
      {(analysis || verdictCard) && (
        <div
          data-testid="ir-handoff-strip"
          style={{
            padding: "0 16px 8px", display: "flex", gap: 6, flexWrap: "wrap",
            fontFamily: "JetBrains Mono", fontSize: 10, alignItems: "center",
          }}
        >
          <span style={{ color: "var(--text-mute)", letterSpacing: "0.14em" }}>
            📥 IR HANDOFF EXPORT —
          </span>
          {[
            ["md",   "SOC BRIEF (.md)",  "text/markdown"],
            ["pdf",  "PDF REPORT",       "application/pdf"],
            ["json", "JSON",             "application/json"],
            ["stix", "STIX 2.1",         "application/stix+json"],
          ].map(([fmt, label]) => (
            <button
              key={fmt}
              type="button"
              className="nvx-btn sm ghost"
              data-testid={`btn-handoff-${fmt}`}
              title={`Download analyst-ready ${label}`}
              onClick={() => downloadHandoff(fmt)}
              style={{ padding: "2px 8px" }}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Feb-2026: ✎ Refine launcher — one button per surface. Analysts
          click the surface that has a wrong finding, pick which specific
          MITRE / IOC / LOLBIN / family / risk value is wrong inside the
          modal, then submit a correction with the 4-verdict picker. */}
      {(analysis || verdictCard) && (
        <div
          data-testid="refine-launcher-strip"
          style={{
            padding: "0 16px 10px", display: "flex", gap: 6, flexWrap: "wrap",
            fontFamily: "JetBrains Mono", fontSize: 10, alignItems: "center",
          }}
        >
          <span style={{ color: "var(--text-mute)", letterSpacing: "0.14em" }}>
            ✎ TEACH NIVXRAY —
          </span>
          {[
            ["mitre",  "MITRE"],
            ["ioc",    "IOC"],
            ["lolbas", "LOLBAS"],
            ["family", "FAMILY"],
            ["risk",   "RISK"],
          ].map(([surface, label]) => (
            <button
              key={surface}
              type="button"
              className="nvx-btn sm ghost"
              data-testid={`btn-refine-${surface}`}
              title={`Refine a wrong ${label} finding`}
              onClick={() => openRefine(surface,
                                        { kind: surface, value: "" })}
              style={{ padding: "2px 8px" }}
            >
              ✎ {label}
            </button>
          ))}
        </div>
      )}

      {/* 3-column layout */}
      <div className="nvx-workspace-grid">
        <OperationsPanel onAdd={addOp} />

        {/* Center column */}
        <section style={{ display: "flex", flexDirection: "column", minWidth: 0, overflow: "auto" }}>
          {/* Input Card */}
          <div className="nvx-card" data-testid="input-card">
            <div className="nvx-card-head">
              <div className="nvx-card-title">
                <span className="dot" />
                INPUT
                <span className="count">{input.length} chars</span>
                {plannerHint && (
                  <span className="mono" data-testid="planner-hint-chip"
                        style={{
                          fontSize: 10, padding: "2px 8px", marginLeft: 8,
                          background: "rgba(126,227,201,0.12)",
                          border: "1px solid #7ee3c9", color: "#7ee3c9",
                          letterSpacing: "0.08em", borderRadius: 3,
                        }}
                        title={plannerHint.reason}>
                    💡 {plannerHint.op} · {Math.round((plannerHint.confidence || 0) * 100)}% → try <b>{plannerHint.suggested_button}</b>
                  </span>
                )}
              </div>
              <div className="nvx-card-actions">
                <button className={`nvx-btn primary sm${(loading || analyzing) ? " busy" : ""}`} onClick={autoInvestigate} disabled={loading || analyzing} data-testid="btn-auto-investigate-inline">
                  {(loading || analyzing) ? <>INVESTIGATING…</> : <><Sparkles size={11} /> AUTO INVESTIGATE</>}
                </button>
                <button className={`nvx-btn sm${(loading || analyzing) ? " busy" : ""}`} onClick={() => autoDecode({ smart: true })} disabled={loading || analyzing} data-testid="btn-smart-decode-inline">
                  {(loading || analyzing) ? <>DECODING…</> : <><Zap size={11} /> DECODE</>}
                </button>
                <button className="nvx-btn sm ghost" onClick={clearAll} data-testid="btn-clear-input"
                        title="Clear everything: input, output, recipe, threat panels, trace, verdict, live preview.">
                  <Trash2 size={11} /> CLEAR
                </button>
              </div>
            </div>
            <div className="nvx-card-body">
              <div style={{ position: "relative" }}>
                <textarea
                  className="nvx-textarea"
                  data-testid="input-textarea"
                  placeholder="Paste anything — PowerShell, base64/hex, AES/RC4 ciphertext, JWT, PE/ELF headers, gzip/bzip2/LZMA, obfuscated JS, defanged IOCs…"
                  value={input}
                  readOnly={inputLocked}
                  onChange={(e) => setInput(e.target.value)}
                onPaste={(e) => {
                  // Client-side auto-detect: race 14 JS decoders against the pasted
                  // string INSIDE the browser (zero network). Surface the top
                  // candidate as an inline "USE THIS RECIPE" hint above the
                  // Recipe panel. If the analyst ignores it, no harm done.
                  //
                  // 2026-02-09 · Anti-hang cap.  magicLite is fast on printable
                  // strings but recursion at depth 3 on multi-layer nested
                  // (base64 → gzip → utf-16-le → PE) payloads can allocate
                  // huge intermediate buffers.  For >4 KB inputs the backend
                  // already handles decoding deterministically in <2 s —
                  // there's no analyst value in racing 14 JS decoders on the
                  // main thread.  This matches the 4096-byte guard the live
                  // preview useEffect already enforces (line 831).
                  const pasted = e.clipboardData?.getData("text") || "";
                  if (pasted.length < 12 || pasted.length > 4096) {
                    setPasteHint(null);
                    return;
                  }
                  try {
                    const m = magicLite(pasted, { maxDepth: 3, topN: 3 });
                    if (m.best && m.best.score >= 0.35) {
                      setPasteHint({
                        chain: m.best.chain,
                        score: m.best.score,
                        preview: (m.best.output || "").slice(0, 200),
                        elapsedMs: m.elapsedMs,
                        alternates: m.candidates.slice(1, 3),
                      });
                    } else {
                      setPasteHint(null);
                    }
                  } catch { setPasteHint(null); }
                }}
                rows={6}
                spellCheck={false}
                style={{ height: 180, minHeight: 180, maxHeight: 180, resize: "none", overflowY: "auto" }}
              />
              <InputToolbar
                scope="input-textarea"
                value={input}
                locked={inputLocked}
                onToggleEdit={() => setInputLocked((v) => !v)}
                onClear={() => { setInput(""); setPasteHint(null); }}
              />
              </div>
              {multiChainNotice && (
                <div
                  data-testid="multi-chain-notice"
                  style={{
                    marginTop: 8, padding: "8px 12px",
                    border: "1px solid var(--accent)", borderRadius: 3,
                    background: "rgba(74,168,144,0.10)",
                    fontFamily: "JetBrains Mono", fontSize: 11,
                    display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
                  }}
                >
                  <span style={{ color: "var(--accent)", letterSpacing: "0.14em", fontWeight: 700 }}>
                    ⚡ MULTI-COMMAND CHAIN
                  </span>
                  <span style={{ color: "var(--text-dim)" }}>
                    detected · {multiChainNotice.stages} stages analysed
                    {multiChainNotice.family && ` · ${multiChainNotice.family}`}
                    {multiChainNotice.verdict && ` · ${multiChainNotice.verdict}`}
                  </span>
                  <span style={{ flex: 1 }} />
                  <button
                    className="nvx-btn sm ghost"
                    data-testid="btn-revert-flat-decode"
                    onClick={revertToFlatDecode}
                    disabled={loading}
                    title="Bypass chain routing and decode the whole input as a single blob (useful when newlines are part of the payload itself)."
                  >
                    ▸ ANALYSE AS FLAT BLOB
                  </button>
                  <button
                    className="nvx-btn sm ghost"
                    data-testid="btn-dismiss-multi-chain-notice"
                    onClick={() => setMultiChainNotice(null)}
                  >
                    <X size={11} />
                  </button>
                </div>
              )}
              {pasteHint && (
                <div
                  className="paste-hint"
                  data-testid="paste-hint"
                  style={{
                    marginTop: 8, padding: "10px 12px",
                    border: "1px solid var(--accent)", background: "rgba(74,168,144,0.08)",
                    fontFamily: "JetBrains Mono", fontSize: 11, display: "flex",
                    alignItems: "center", gap: 12, flexWrap: "wrap",
                  }}
                >
                  <span style={{ color: "var(--accent)", letterSpacing: "0.14em", fontWeight: 700 }}>
                    ⚡ AUTO-DETECT ({pasteHint.elapsedMs}ms)
                  </span>
                  <span style={{ color: "var(--text-dim)" }}>
                    likely {pasteHint.chain.map((c) => c.op).join(" → ")} · score {pasteHint.score.toFixed(2)}
                  </span>
                  <span style={{ flex: 1 }} />
                  <button
                    className="nvx-btn sm primary"
                    data-testid="btn-use-paste-recipe"
                    onClick={() => {
                      setSteps(pasteHint.chain.map((c) => ({ op: c.op, args: c.args || {} })));
                      setPasteHint(null);
                      setStatus(`✓ APPLIED CLIENT-SIDE RECIPE (${pasteHint.chain.length} ops)`);
                    }}
                  >
                    ▸ USE THIS RECIPE
                  </button>
                  <button
                    className="nvx-btn sm ghost"
                    data-testid="btn-dismiss-paste-hint"
                    onClick={() => setPasteHint(null)}
                  >
                    <X size={11} /> DISMISS
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Multi-Stage Chain Analysis (opt-in via ADD STAGE button) */}
          {chainReplay ? (
            <ChainReplayView
              record={chainReplay}
              onRestore={restoreChainToWorkspace}
              onClose={() => setChainReplay(null)}
            />
          ) : chainOpen ? (
            <CollapsibleCard title="CHAIN ANALYSIS" storageKey="nvx.collapse.chain"
                             testid="collapse-chain-analysis">
            <ChainStageEditor
              key={chainEditorKey}
              seedInput={input}
              initialStages={pendingChainStages}
              initialResult={pendingChainResult}
              onSeedConsumed={() => { /* keep single-stage input intact */ }}
              onChainComplete={(reportText, chainData) => {
                // Feb-2026 UX fix — when the Chain Editor is driven
                // directly (no INPUT paste), populate the top OUTPUT
                // panel with the SOC report + light status update so
                // the analyst has a single glance-view.
                if (reportText) setOutput(reportText);
                const agg = chainData?.aggregate || {};
                const risk = agg?.risk || {};
                const fam  = agg?.family || {};
                const conf = Number.isFinite(risk?.score) ? risk.score : null;
                const stageCount = (chainData?.stages || []).length;
                const parts = [
                  `CHAIN COMPLETE · ${stageCount} stage${stageCount === 1 ? "" : "s"}`,
                  risk?.verdict || null,
                  fam?.family || null,
                  conf != null ? `${conf}/100` : null,
                ].filter(Boolean);
                setStatus(parts.join(" · "));
                if (conf != null) setDecodeConfidence(conf);
                setDecodeWinnerEngine("chain");
              }}
            />
            </CollapsibleCard>
          ) : (
            <div style={{ margin: "6px 12px 8px 12px", display: "flex", justifyContent: "flex-end" }}>
              <button
                className="nvx-btn sm ghost"
                data-testid="btn-open-chain-editor"
                onClick={() => setChainOpen(true)}
                title={
                  "Open Multi-Stage Chain Analysis. Decode a series of PowerShell/CMD commands (e.g. Lumma ClickFix)\n" +
                  "as one chain: per-stage deterministic decoding + unified SOC verdict + optional AI narrative for the WHOLE chain.\n\n" +
                  "▸ Paste text with BLANK LINES separating stages to auto-split.\n" +
                  "▸ Compact view auto-activates at 4+ stages."
                }
              >
                + CHAIN MODE (multi-stage)
              </button>
            </div>
          )}

          {/* Recipe */}
          <CollapsibleCard title="RECIPE" storageKey="nvx.collapse.recipe"
                           testid="collapse-recipe">
            <RecipePanel steps={steps} setSteps={setSteps} ops={ops} />
          </CollapsibleCard>

          {/* ONE-BUTTON pipeline trace */}
          {nivxrayTrace.length > 0 && (
            <div className="brut-border" style={{
              margin: "0 12px 10px 12px", background: "var(--surface)",
              padding: "8px 12px", fontFamily: "JetBrains Mono", fontSize: 11,
            }} data-testid="nivxray-decode-trace">
              <div style={{ color: "var(--accent)", letterSpacing: "0.16em",
                            fontSize: 10, fontWeight: 700, marginBottom: 6 }}>
                NIVXRAY DECODE · PIPELINE TRACE
              </div>
              {nivxrayTrace.map((t, i) => (
                <div key={i} style={{
                  display: "flex", gap: 8, alignItems: "center",
                  padding: "3px 0",
                  borderBottom: i < nivxrayTrace.length - 1 ? "1px dashed var(--border)" : "none",
                }} data-testid={`nvx-trace-step-${i}`}>
                  <span style={{ color: "var(--text-mute)", minWidth: 14 }}>#{i + 1}</span>
                  <span style={{ color: "var(--warn)", minWidth: 110,
                                 textTransform: "uppercase", letterSpacing: "0.1em" }}>
                    {t.step}
                  </span>
                  {t.engine && (
                    <span style={{ color: "var(--accent)" }}>{t.engine}</span>
                  )}
                  {t.confidence !== undefined && (
                    <span style={{ color: "var(--text-dim)" }}>· {t.confidence}%</span>
                  )}
                  <span style={{ color: "var(--text-dim)", flex: 1 }}>{t.note}</span>
                </div>
              ))}
            </div>
          )}

          {/* ▲ Global Investigation Filter Bar (R8 · 2026-02-28)
              INVISIBLE until the analyst clicks a Kill-Chain phase,
              MITRE badge, IOC or stage.  When active, shows the
              active filter chips + CLEAR ALL, and downstream
              components soft-filter to match. */}
          <InvestigationFilterBar />

          {/* ▲ Input Understanding Panel (P0 · 2026-02-28)
              MUST be the first thing the analyst sees after clicking
              ANALYZE.  Explains WHAT the paste is, WHY each engine is
              running, and TRACKS the plan execution in real time. */}
          {(understanding || understandingLoading || understandingError || understandingSkipReason) && (
            <CollapsibleSection title="Input Understanding"
                                 testid="input-understanding-section"
                                 style={{ margin: "0 12px 8px" }}>
              <InputUnderstandingPanel
                understanding={understanding}
                loading={understandingLoading}
                error={understandingError}
                skipped={!!understandingSkipReason && !understanding}
                skipReason={understandingSkipReason}
              />
            </CollapsibleSection>
          )}

          {/* ▲ IDA · Acquisition Plan projection (Slice 1.6 · 2026-03-01)
              Renders ABOVE the legacy decode trace when IDA classifies the
              paste as an acquirable URL (threat_report / code_snippet /
              repository / file_resource).  The decode trace still runs but
              this panel is the analyst's source of truth for "what the
              platform is going to do about this URL". */}
          {investigationObject?.acquisition_plan?.length > 0 && (
            <AcquisitionPlanPanel investigation={investigationObject} />
          )}

          {/* ▲ P0.15C · VEEE Acquisition Summary + Jump-to-Source (2026-02-09)
              Additive display panels · consumes ONLY the read-only
              `acquisition_summary` and `acquisition_ocr_records`
              attached by the backend on GET /cases/{id}.  No
              acquisition logic, no semantic logic — pure projection
              of existing data.  Renders nothing when the case
              predates VEEE (byte-identical legacy behaviour). */}
          {acquisitionSummary && (
            <div style={{ margin: "0 12px 8px" }}
                    data-testid="workspace-acquisition-summary-wrap">
              <AcquisitionSummary summary={acquisitionSummary} />
            </div>
          )}
          {acquisitionOcrRecords && acquisitionOcrRecords.length > 0 && (
            <div style={{ margin: "0 12px 8px" }}
                    data-testid="workspace-acquisition-evidence-wrap">
              <AcquisitionEvidenceList records={acquisitionOcrRecords} />
            </div>
          )}

          {/* R28.C · Artifact Trace projection (SSOT-only, no recompute)
              Renders Artifact → Recognizer → Capability → Evidence →
              Child-Artifact rows lifted from ``ssot.decode_trace`` via
              the backend ``project_artifact_trace`` helper.  Future
              domain artifacts (PE, PDF, Office, Shellcode, PCAP…) use
              the same projection shape — no rename after UAIE lands. */}
          {artifactTrace && artifactTrace.length > 0 && (
            <div style={{ margin: "0 12px 8px" }}>
              <ArtifactTracePanel trace={artifactTrace} />
            </div>
          )}

          {/* ▲ IDA · Investigation Session Gateway (Rule R22 · 2026-03-02)
              Replaces the inline extracted-artifacts table.  When IDA
              has acquired a document, the Workspace shows a compact
              readiness card + a single "Open Investigation Session"
              button — the deep-dive lives on /workspace/session/:id. */}
          {investigationObject?.acquired_document?.ok && (
            <InvestigationSessionGateway
              investigation={investigationObject}
              input={input}
            />
          )}

          {/* ▲ Inline Attack Story (P0 · 2026-02-28)
              Renders immediately below the IUE using the preprocessor
              stages returned by the DIE analyze envelope.  Analyst
              never needs to switch tabs to see the timeline. */}
          {inlineStoryPreproc && (
            <div style={{ margin: "0 12px 8px" }}>
              <PanelErrorBoundary panel="Inline Attack Story">
                <InlineAttackStory preprocessor={inlineStoryPreproc} />
              </PanelErrorBoundary>
            </div>
          )}

          {/* ▲ Evidence Trajectory (2026-02-28)
              Swim-lane trajectory diagram — matches the analyst-expected
              trajectory artefact.  Six lanes (Execution / Transformation
              / Network·C2 / File System / Registry / Persistence) with
              per-stage nodes and coloured edges (normal · critical ·
              persistence) between them. */}
          {/* ▲ Attack Trajectory (2026-02-28 + 2026-03-01 · ICE fallback)
              For paste-of-command inputs, uses the preprocessor stages
              from /api/die/analyze.  For URL investigations (where the
              paste is a link, not a command) we synthesise stages from
              ICE.behavior_clusters so the swim-lane view renders
              uniformly across every input class. */}
          {(() => {
            const iceClusters = investigationObject?.ice?.behavior_clusters;
            let incidentBehaviors = investigationObject?.incident?.behaviors || iceClusters || [];
            // 2026-08-11 · Lane-assignment fallback — when the CSV /
            // prose path leaves both `incident.behaviors` and
            // `ice.behavior_clusters` empty but `object.mitre[]`
            // carries per-technique tactic info, synthesise the
            // behaviors from the MITRE list so the canonical 14-lane
            // ATT&CK view renders correctly (instead of piling every
            // executable into the legacy Execution lane).
            if (!incidentBehaviors.length) {
              incidentBehaviors = _synthBehaviorsFromMitre(investigationObject?.mitre || []);
            }
            const preprocForTraj = inlineStoryPreproc
              || (iceClusters?.length
                    ? _synthPreprocFromIce(investigationObject.ice)
                    : null);
            if (!preprocForTraj && !incidentBehaviors.length) return null;
            return (
              <CollapsibleSection title="Attack Chain · MITRE ATT&CK Projection"
                                   subtitle="14 lanes · one authoritative evidence-backed MITRE surface · empty tactics stay visually silent · drag / pan / zoom"
                                   testid="attack-trajectory-section"
                                   style={{ margin: "0 12px 8px" }}>
                <TrajErrorBoundary>
                  <PanelErrorBoundary panel="Attack Trajectory">
                    <TrajectoryDiagram
                      preprocessor={preprocForTraj}
                      behaviors={incidentBehaviors}
                    />
                  </PanelErrorBoundary>
                </TrajErrorBoundary>
              </CollapsibleSection>
            );
          })()}

          {/* ── P2 UI Slice · Behavioral Evidence Timeline (ADR-0010t) ──
             Read-only projection of Sysmon Event 1 / Event 3 / EVTX
             evidence. Renders BELOW the 14-tactic Attack Chain and
             makes explicit the flow:
                Evidence → Correlation → authoritative MITRE → Attack Chain.
             Does NOT infer techniques, does NOT compute verdicts. */}
          <BehavioralTimeline caseId={currentCaseId} />

          {/* ▲ Workspace Timeline · MVP (2026-08-11) ·
              Guarded 2026-08-11 against very-large-paste UI freezes:
                · `useDeferredValue` on `input` so a paste settles
                  before Timeline/Query re-fetch.
                · Panels only mount when input.length ≤ 64 KB — larger
                  inputs go straight to the Investigate lane which
                  runs on the backend; auto-visualization is skipped
                  to keep the browser thread responsive.  A hint tells
                  the analyst what happened.
              Read-only chronological projection over the existing
              canonical investigation evidence (highconf_events +
              P0.2 evidence chain).  Only events with real timestamps
              appear here; narrative-only MITRE mentions remain in the
              MITRE panels.  Pure projection — no new detection logic. */}
          {investigationMode && input && input.trim() && input.length > 32 * 1024 && (
            <div data-testid="timeline-too-large-hint"
                 style={{ margin: "0 12px 8px", padding: 12, borderRadius: 6,
                          background: "rgba(234, 179, 8, 0.08)",
                          border: "1px dashed rgba(234, 179, 8, 0.4)",
                          color: "#fde68a", fontSize: 12, lineHeight: 1.55 }}>
              Timeline &amp; Query/Hunt auto-visualization skipped — the
              current input is <b>{Math.round(input.length / 1024)} KB</b>,
              above the 32 KB safety ceiling. The main investigation
              (Summary · MITRE · Evidence · Attack Chain · Verdict)
              still runs against the full input on the backend.
            </div>
          )}
          {investigationMode && input && input.trim() && input.length <= 32 * 1024 && (
            <CollapsibleSection title="Timeline · Evidence-backed chronology"
                                 subtitle="Chronological projection of canonical events · click to expand evidence chain"
                                 testid="timeline-section"
                                 style={{ margin: "0 12px 8px" }}>
              <PanelErrorBoundary panel="Workspace Timeline">
                <TimelinePanel rawInput={deferredInput} />
              </PanelErrorBoundary>
            </CollapsibleSection>
          )}

          {/* ▲ Workspace Query / Hunt · MVP (2026-08-11)
              Same 64 KB safety guard as Timeline above; deferred
              `input` so a large paste settles before Query re-fetch. */}
          {investigationMode && input && input.trim() && input.length <= 64 * 1024 && (
            <CollapsibleSection title="Query / Hunt · Scoped sub-view"
                                 subtitle="Optional analyst filter · Table / Timeline projections of the current investigation"
                                 testid="query-hunt-section"
                                 defaultOpen={false}
                                 style={{ margin: "0 12px 8px" }}>
              <PanelErrorBoundary panel="Query/Hunt">
                <QueryHuntPanel rawInput={deferredInput} />
              </PanelErrorBoundary>
            </CollapsibleSection>
          )}

          {/* ▲ Analyst Narrative (2026-02-28)
              Deterministic Executive Summary + Analyst Summary +
              Recommended Actions + Sigma / YARA hunts + MITRE matrix +
              Threat-actor context.  Zero LLM. */}
          {analystNarrative && (
            <div style={{ margin: "0 12px 8px" }}>
              <PanelErrorBoundary panel="Analyst Narrative">
                <AnalystNarrativePanel narrative={analystNarrative} />
              </PanelErrorBoundary>
            </div>
          )}

          {/* ▲ P0d-A (2026-02-09) · Deterministic Analyst Brief
              (9-card InvestigationSummaryPanel).  Sourced from the
              auto-minted session's `summary_narrative`.  Prev-Mode
              paste ingested URLs / prose now surfaces Executive
              Summary, Analyst Summary, Observed Behaviour, Attack
              Intent, Potential Impact, MITRE Summary, IOC
              Intelligence, Recommendations and Evidence Confidence
              without the analyst having to navigate away.  Backend
              contract: fed by /api/session/from-investigation
              (deterministic, zero LLM). */}
          {sessionSnapshot?.summary_narrative && (
            <div style={{ margin: "0 12px 8px" }}
                    data-testid="workspace-investigation-summary-wrap">
              <PanelErrorBoundary panel="Investigation Summary">
                <InvestigationSummaryPanel
                  narrative={sessionSnapshot.summary_narrative}
                  onOpenSession={() => {
                    const sid = sessionSnapshot?.session_id;
                    if (sid) window.open(`/workspace/session/${sid}`,
                                            "_blank", "noopener,noreferrer");
                  }}
                />
              </PanelErrorBoundary>
            </div>
          )}

          {/* Learning Feedback Loop — BOOST badge with source + confidence + disable/re-run */}
          {boost && (
            <div style={{ margin: "0 12px" }}>
              <BoostBadge
                boost={boost}
                boostHit={boostHit}
                engine={decodeWinnerEngine}
                onRerun={(opts) => autoDecode({ smart: true, ...opts })}
              />
            </div>
          )}

          {/* ▲ Recovery Status Ribbon (Priority 3 · 2026-02)
              Splits threat vs canonical confidence and surfaces the IEDDE
              terminal state. Additive — does NOT replace any existing panel. */}
          {(iddeTerminalState || canonicalConfidence != null || verdictCard) && (
            <div style={{ margin: "0 12px" }}>
              <RecoveryStatusRibbon
                threatConfidence={
                  typeof verdictCard?.confidence === "number"
                    ? verdictCard.confidence
                    : typeof decodeConfidence === "number"
                    ? decodeConfidence
                    : null
                }
                canonicalConfidence={canonicalConfidence}
                canonicalConfidenceReason={canonicalConfidenceReason}
                terminalState={iddeTerminalState}
                binaryArtifact={iedde?.binary_artifact || null}
              />
            </div>
          )}

          {/* ▲ IEDDE Decision Trace panel (Priority 2 · 2026-02)
              First-class visibility for the Intelligent Evidence-Driven
              Decoding Engine's reasoning trace. Additive · collapsible. */}
          {iedde && (
            <div style={{ margin: "0 12px" }}>
              <IEDDEDecisionTrace
                iedde={iedde}
                canonicalConfidence={canonicalConfidence}
                canonicalConfidenceReason={canonicalConfidenceReason}
                diagnostics={ieddeDiagnostics}
                defaultOpen={false}
              />
            </div>
          )}

          {/* ▲ Artifact Analysis Panel (Phase 3 · Cycle A · 2026-02)
              When IEDDE reaches `binary_artifact_recovered` the router-
              dispatched analysis result flows through here — routing to
              PE, PDF, or an "unavailable" card for unsupported types. */}
          {iedde?.binary_artifact?.routed_analysis && (
            <div style={{ margin: "0 12px" }}>
              <ArtifactAnalysisPanel routed={iedde.binary_artifact.routed_analysis} />
            </div>
          )}
          {iedde?.binary_artifact?.pe_analysis && !iedde?.binary_artifact?.routed_analysis && (
            <div style={{ margin: "0 12px" }}>
              <ArtifactAnalysisPanel legacyPE={iedde.binary_artifact.pe_analysis} />
            </div>
          )}

          {/* Decoding Trace — expandable per-layer view for the deterministic decoder */}
          {decodeTrace.length > 0 && (
            <div style={{ margin: "0 12px" }}>
              <DecodingTracePanel
                trace={decodeTrace}
                engine={decodeWinnerEngine}
                confidence={decodeConfidence}
                reachedShellcode={reachedShellcode}
                overallSuccess={(() => {
                  // RC3.1: signal to trace panel that the OVERALL investigation
                  // recovered actionable intelligence. Used to downgrade a
                  // terminal-layer "BROKEN" badge to "RECOVERED" when we in
                  // fact extracted a valid analyst-ready report.
                  try {
                    const iocs = analysis?.iocs || {};
                    const iocCount =
                      (iocs.urls?.length || 0) + (iocs.domains?.length || 0) +
                      (iocs.ips?.length || 0) + (iocs.hashes?.length || 0) +
                      (iocs.emails?.length || 0) + (iocs.files?.length || 0);
                    const mitreCount = (analysis?.mitre || []).length;
                    const lolbasCount = (analysis?.lolbas || []).length;
                    const familyOK = !!(verdictCard?.family || verdictCard?.family_matches?.length);
                    const verdictOK = !!(verdictCard && verdictCard.verdict && verdictCard.verdict !== "unknown");
                    return reachedShellcode || iocCount > 0 || mitreCount > 0 || lolbasCount > 0 || familyOK || verdictOK;
                  } catch (_e) {
                    return false;
                  }
                })()}
                onJumpToLayer={(i) => {
                  const layer = decodeTrace[i];
                  if (layer && !layer.error) {
                    setOutput(layer.output_preview || "");
                    setStatus(`▸ JUMPED TO LAYER ${i + 1} · ${layer.op}`);
                  }
                }}
              />
            </div>
          )}

          {/* Detected banner */}
          {detected && (
            <div className="detect-banner fade-in" data-testid="detected-banner"
              style={{
                margin: "0 12px", padding: "10px 12px", border: "1px solid var(--accent)",
                background: "rgba(74,168,144,0.08)", color: "var(--accent)",
                fontFamily: "JetBrains Mono", fontSize: 11, letterSpacing: "0.06em",
                display: "flex", alignItems: "center", gap: 8,
              }}
            >
              <span style={{ background: "var(--accent)", color: "#0a0a0c", padding: "2px 8px", fontWeight: 700, letterSpacing: "0.14em" }}>
                {'>_'}
              </span>
              <span style={{ fontWeight: 700 }}>{detected.label.toUpperCase()}</span>
              <span style={{ color: "var(--text-mute)", marginLeft: "auto" }}>{output.length} decoded chars</span>
            </div>
          )}

          {/* v1.5.1 — Zero-Miss Escalation Ladder */}
          {analysis?.layer_trace && Array.isArray(analysis.layer_trace) && analysis.layer_trace.length > 0 && (
            <EscalationLadder
              trace={analysis.layer_trace}
              winner={analysis.engine}
              confidence={analysis.confidence ?? analysis.score}
            />
          )}

          {/* v1.5.5 — TI Shield · 360° per-layer intelligence */}
          {Array.isArray(analysis?.ti_shield) && analysis.ti_shield.length > 0 && (
            <TIShieldPanel layers={analysis.ti_shield} />
          )}

          {/* Output Card — real-time preview + view toggles + byte diff */}
          <OutputView
            input={input}
            output={output}
            livePreview={livePreview}
            investigationMode={investigationMode}
            actions={<>
              <button className="nvx-btn sm" onClick={() => analyze({ describe: true, aiVerdict: true })} disabled={analyzing || !output} data-testid="btn-ai-describe">
                <Sparkles size={11} /> AI DESCRIBE
              </button>
              <button className="nvx-btn sm" onClick={() => analyze({})} disabled={analyzing || (!input && !output)} data-testid="btn-analyze">
                ANALYZE + OSINT
              </button>
              <button className="nvx-btn sm ghost" onClick={() => navigator.clipboard.writeText(output)} disabled={!output} data-testid="btn-copy-output">
                <Copy size={11} /> COPY
              </button>
              <button
                className="nvx-btn sm"
                style={{ background: "#dc2626", color: "#fff", borderColor: "#7f1d1d" }}
                onClick={() => setBadDecodeOpen(true)}
                disabled={!input}
                data-testid="btn-report-bad-decode"
                title="Report a bad / undecoded output — get AI-generated diagnosis"
              >
                REPORT BAD DECODE
              </button>
              <button
                className="nvx-btn sm primary"
                onClick={async () => {
                  // Open the RICH Investigation Session page (IOC intel
                  // cards, evidence, timeline, related campaigns) — the
                  // "old page with lot of information" the analyst
                  // expects.  Mint a session id on demand, then navigate.
                  try {
                    const inv = investigationObject || analysis?.investigation || {
                      input, output: analysis?.output || "",
                      commands: [], artifacts: [], iocs: analysis?.iocs || {},
                    };
                    const { data } = await api.post("/session/from-investigation",
                      { input, investigation: inv });
                    const sid = data?.session?.session_id;
                    if (sid) {
                      try {
                        sessionStorage.setItem(`nvx.session.${sid}`, JSON.stringify(data.session));
                        sessionStorage.setItem("nvx.session.mirror", JSON.stringify(inv));
                      } catch {}
                      window.open(`/workspace/session/${sid}`,
                                    "_blank", "noopener,noreferrer");
                      return;
                    }
                    throw new Error("no session returned");
                  } catch (e) {
                    // Fallback — lightweight deterministic summary
                    try { localStorage.setItem("nivx.investigation.text", input || ""); } catch {}
                    window.open("/investigation-summary",
                                  "_blank", "noopener,noreferrer");
                  }
                }}
                disabled={!input || !input.trim()}
                data-testid="btn-open-investigation-summary"
                title="Open the full Investigation Summary — IOC intelligence, evidence timelines, related campaigns/families, and the complete analyst brief."
              >
                📋 OPEN INVESTIGATION SUMMARY
              </button>
              <button
                className="nvx-btn sm"
                style={{ background: "#0f766e", color: "#fff", borderColor: "#134e4a" }}
                onClick={enrichIocs}
                disabled={
                  enrichingIocs ||
                  !(analysis?.iocs && Object.values(analysis.iocs).some((v) => Array.isArray(v) && v.length))
                }
                data-testid="btn-enrich-iocs"
                title="Push extracted IOCs to VirusTotal / OTX / AbuseIPDB for reputation lookup"
              >
                {enrichingIocs ? "ENRICHING…" : "ENRICH IOCs"}
              </button>
            </>}
          />

          {/* IOC enrichment pills — populated after ENRICH IOCs is clicked */}
          {iocEnrichment && iocEnrichment.length > 0 && (
            <div className="nvx-card" data-testid="ioc-enrichment-card">
              <div className="nvx-card-head">
                <div className="nvx-card-title">
                  <span className="dot" style={{ background: "#0f766e" }} />
                  IOC ENRICHMENT
                  <span className="count">{iocEnrichment.length} IOCs enriched</span>
                </div>
              </div>
              <div className="nvx-card-body" style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {iocEnrichment.map((e, i) => {
                  const isError = typeof e.value === "string" &&
                                  (e.value.startsWith("enrichment failed") ||
                                   e.value.startsWith("provider unavailable") ||
                                   e.error);
                  const bad = isError ||
                              (e.malicious_score || 0) > 0 ||
                              (e.abuse_confidence || 0) > 25 ||
                              (e.otx_pulses || 0) > 0;
                  const bg = isError ? "#991b1b" : (bad ? "#7f1d1d" : "#134e4a");
                  // v1.5.3 · richer pill label — surface OTX pulses + AbuseIPDB confidence
                  const badges = [];
                  if (!isError && e.malicious_score) badges.push(`VT:${e.malicious_score}`);
                  if (!isError && e.abuse_confidence) badges.push(`AB:${e.abuse_confidence}%`);
                  if (!isError && e.otx_pulses) badges.push(`OTX:${e.otx_pulses}`);
                  const label = isError
                    ? e.value
                    : e.value + (badges.length ? ` · ${badges.join(" · ")}` : "");
                  const icon = isError ? "⚠️ " : (bad ? "🔴 " : "🟢 ");
                  return (
                    <span
                      key={i}
                      data-testid={`ioc-pill-${i}${isError ? "-error" : ""}`}
                      style={{
                        background: bg, color: "#fff", padding: "6px 12px",
                        borderRadius: 999, fontSize: 11, letterSpacing: 0.6,
                        border: `1px solid ${isError ? "#dc2626" : "rgba(255,255,255,0.15)"}`,
                      }}
                      title={JSON.stringify(e.providers || {}, null, 2)}
                    >
                      {icon}
                      {label}
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {/* Bad-decode feedback modal */}
          <BadDecodeModal
            open={badDecodeOpen}
            onClose={() => setBadDecodeOpen(false)}
            rawInput={input}
            observedOutput={output}
            observedChain={(analysis?.chain?.steps || analysis?.chain || []).map?.((s) => s?.op || s) || []}
          />

          {/* Attack Graph Card — Tactical MITRE ATT&CK swim-lane */}
          {analysis?.description?.entity_graph?.nodes?.length > 0 && (
            <div className="nvx-card" data-testid="attack-graph-card">
              <div className="nvx-card-head">
                <div className="nvx-card-title">
                  <span className="dot" style={{ background: "var(--warn)" }} />
                  ATTACK GRAPH
                  <span className="count">
                    {analysis.description.entity_graph.nodes.length} entities · {(analysis.description.entity_graph.edges || []).length} relations
                  </span>
                </div>
                {tacticFilter && (
                  <div className="nvx-card-actions">
                    <span className="badge warn" data-testid="tactic-filter-badge">
                      FILTER · {tacticFilter}
                    </span>
                    <button className="nvx-btn sm ghost" onClick={() => setTacticFilter(null)} data-testid="btn-clear-tactic-filter">
                      <X size={11} /> CLEAR
                    </button>
                  </div>
                )}
              </div>
              <div className="nvx-card-body">
                <AttackGraph
                  nodes={analysis.description.entity_graph.nodes}
                  edges={analysis.description.entity_graph.edges || []}
                  selectedTactic={tacticFilter}
                  onTacticClick={(t) => setTacticFilter((cur) => cur === t ? null : t)}
                />
              </div>
            </div>
          )}

          {/* Kill-Chain Path card (G1/G2 toggle) removed 2026-03-02
              per user request — the same information is projected on
              the dedicated Investigation Session page (Incident Graph
              / Attack Story tabs).  Keeping the Workspace visually
              light — one launcher, one job. */}

          {/* Predicted Process Tree — appears once we have decoded output */}
          {(output || input) && (
            <ProcessTreeView
              raw={input}
              decoded={output || input}
              autoFetch={false}
              onTreeReady={setPredictedTree}
            />
          )}

          {/* Final Summary — executive briefing derived from AI describe.

              FU-5 (v1.4.3): Gated behind SHOW_LEGACY_INVESTIGATION_SUMMARY.
              This is the "NIVXRAY — FINAL INVESTIGATION SUMMARY" card whose
              risk + AI verdict badges (e.g. "Suspicious · 45/100") competed
              with the Investigation Brain's authoritative verdict. */}
          {SHOW_LEGACY_INVESTIGATION_SUMMARY && analysis?.description && (
            <FinalSummary
              description={analysis.description}
              verdict={analysis.ai_verdict}
              risk={analysis.risk}
              jobId={analysis.job_id}
              playbooksUsed={analysis.playbooks_used || []}
            />
          )}

          {/* Shellcode view — auto-renders when the magic decoder flags binary output */}
          {(shellcodeFlag || isShellcodeClient) && output && (
            <div data-testid="shellcode-view">
              <ShellcodeView output={output} />
            </div>
          )}
        </section>

        <PanelErrorBoundary panel="Threat Analysis">
          <ThreatAnalysis
            analysis={analysis}
            loading={analyzing}
            selectedTactic={tacticFilter}
            onClearTactic={() => setTacticFilter(null)}
            rawInput={input}
            decodedOutput={output}
            decodeTrace={decodeTrace}
            decodeEngine={decodeWinnerEngine}
            decodeConfidence={decodeConfidence}
            reachedShellcode={reachedShellcode}
            onRerunFromNode={(layerIdx) => {
              const layer = decodeTrace[layerIdx];
              if (layer && !layer.error) {
                setOutput(layer.output_preview || "");
                setSteps(decodeTrace.slice(0, layerIdx + 1).map((t) => ({ op: t.op, args: t.args || {} })));
                setStatus(`▸ RE-RUNNING FROM LAYER ${layerIdx + 1} (${layer.op})`);
              }
            }}
          />
        </PanelErrorBoundary>
      </div>

      {showMagic && magicResults && (
        <div
          data-testid="magic-modal"
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 50, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}
          onClick={(e) => { if (e.target === e.currentTarget) setShowMagic(false); }}
        >
          <div className="brut-border" style={{ background: "var(--surface)", maxWidth: 1000, width: "100%", maxHeight: "85vh", display: "flex", flexDirection: "column" }}>
            <div style={{ padding: "14px 18px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div className="mono" style={{ fontSize: 12, color: "var(--warn)", letterSpacing: "0.22em" }}>
                ▸ MAGIC — {magicResults.top_results?.length || 0} CANDIDATE CHAINS · explored {magicResults.candidates_explored} paths
              </div>
              <button className="nvx-btn sm ghost" onClick={() => setShowMagic(false)} data-testid="btn-magic-close">
                <X size={11} /> CLOSE
              </button>
            </div>
            <div style={{ overflow: "auto", padding: 16, display: "grid", gap: 12 }}>
              {(magicResults.top_results || []).map((r, i) => (
                <MagicResultCard key={i} r={r} idx={i} onApply={() => applyMagicResult(r)} />
              ))}
            </div>
          </div>
        </div>
      )}

      {shareUrl && (
        <div
          className="brut-border"
          style={{
            position: "fixed", right: 20, bottom: 20, background: "var(--surface)",
            padding: 12, maxWidth: 420,
          }}
          data-testid="share-toast"
        >
          <div className="mono" style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.2em", marginBottom: 4 }}>
            SHARE URL COPIED TO CLIPBOARD
          </div>
          <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", wordBreak: "break-all" }}>{shareUrl}</div>
          <button className="nvx-btn sm ghost" style={{ marginTop: 6 }} onClick={() => setShareUrl("")}>DISMISS</button>
        </div>
      )}

      {/* Phase 4 · P2.1 · Workspace-native Find Related Cases (2026-02-15) */}
      {findRelatedOpen && currentCaseId && (
        <FindRelatedDrawer
          caseId={currentCaseId}
          onClose={() => setFindRelatedOpen(false)}
        />
      )}

      <CasesDrawer
        open={casesOpen}
        onClose={() => setCasesOpen(false)}
        onRestore={(caseDoc) => {
          // Rehydrate directly from workspace_case doc — same fields as
          // history rehydrate but sourced from /cases/{id}.
          skipLivePreviewRef.current = true;
          setInput(caseDoc.input || "");
          setOutput(caseDoc.output || "");
          setDecodeWinnerEngine(caseDoc.engine || null);
          setDecodeConfidence(caseDoc.confidence ?? null);
          setSavedCaseName(caseDoc.name);
          setCurrentCaseId(String(caseDoc.id || ""));
          // ── P0.15C · VEEE additive projection (2026-02-09) ─────────
          // Hydrate the acquisition summary + OCR records that the
          // backend attaches on GET /cases/{id}.  Both are safely
          // null/empty for legacy cases predating VEEE.
          setAcquisitionSummary(caseDoc.acquisition_summary || null);
          setAcquisitionOcrRecords(Array.isArray(caseDoc.acquisition_ocr_records)
                                          ? caseDoc.acquisition_ocr_records
                                          : []);

          // ── Feb 2026 P0 · Full SSOT hydration ─────────────────────────
          // If the case was saved with the SSOT bundle we rehydrate the
          // entire workspace state deterministically and skip the three
          // API re-fires below.  This guarantees "no recomputation on
          // reopen" per NIVXRAY_ARCHITECTURE_V1.md · R27.
          const ssot = caseDoc.ssot;
          if (ssot && typeof ssot === "object") {
            // R28 · Restore is Rendering — any /die/* call fired inside
            // this block is a bug.  api.js will log + telemetry-ping it.
            beginRestoreMode(`case:${caseDoc.name || caseDoc.id}`);
            try {
            setDecodeTrace(ssot.decode_trace || []);
            setArtifactTrace(caseDoc.artifact_trace || []);
            setVerdictCard(ssot.verdict_card || caseDoc.verdict_card || null);
            setReachedShellcode(!!(ssot.reached_shellcode ?? caseDoc.reached_shellcode));
            setCorruptedContainer(ssot.corrupted_container || null);
            setSteps(ssot.steps || (caseDoc.chain_ids || []).map((op) => ({ op, args: {} })));
            setChain(ssot.chain || (caseDoc.chain_ids || []).map((op) => ({ op, reason: "", output_preview: "" })));
            setAnalysis(ssot.analysis || { iocs: caseDoc.iocs || {}, mitre: ssot.mitre || caseDoc.mitre || [], ai_verdict: caseDoc.verdict });
            setIedde(ssot.iedde || null);
            setIeddeTerminalState(ssot.iedde_terminal_state || null);
            setCanonicalConfidence(
              typeof ssot.canonical_confidence === "number" ? ssot.canonical_confidence : null,
            );
            setCanonicalConfidenceReason(ssot.canonical_confidence_reason || null);
            setUnderstanding(ssot.understanding || null);
            setUnderstandingLoading(false);
            setUnderstandingError(null);
            setAnalystNarrative(ssot.analyst_narrative || null);
            setInlineStoryPreproc(ssot.inline_story_preproc || null);
            setInvestigationObject(ssot.investigation_object || null);
            setInvestigationMode(!!ssot.investigation_mode);
            if (ssot.semantic !== undefined) setSemantic(ssot.semantic);
            if (ssot.predicted_tree !== undefined) setPredictedTree(ssot.predicted_tree);
            const droppedNote = Array.isArray(ssot.dropped_for_size) && ssot.dropped_for_size.length
              ? ` · dropped: ${ssot.dropped_for_size.join(",")}`
              : "";
            const _sv = (ssot.version && typeof ssot.version === "object")
              ? `${ssot.version.schema} · ${ssot.version.engine} · ${ssot.version.uaie} · ${ssot.version.baseline}`
              : (ssot.version || "1.0");
            setStatus(`▸ OPENED "${caseDoc.name}" · SSOT ${_sv} · no recomputation${droppedNote}`);
            } finally {
              // Defer to the next tick so any state-effect-triggered
              // fetches also get gated by the guard.
              setTimeout(() => endRestoreMode(), 0);
            }
            return;
          }

          // ── Legacy path (no SSOT persisted) — fall back to recompute ──
          setDecodeTrace([]);
          setVerdictCard(caseDoc.verdict_card || null);
          setReachedShellcode(!!caseDoc.reached_shellcode);
          setSteps((caseDoc.chain_ids || []).map((op) => ({ op, args: {} })));
          setChain((caseDoc.chain_ids || []).map((op) => ({ op, reason: "", output_preview: "" })));
          setAnalysis({ iocs: caseDoc.iocs || {}, mitre: caseDoc.mitre || [], ai_verdict: caseDoc.verdict });
          // ▲ IEDDE SSOT rehydrate (2026-02) — mirror history rehydrate.
          setIedde(caseDoc.iedde || null);
          setIeddeTerminalState(caseDoc.iedde_terminal_state || null);
          setCanonicalConfidence(
            typeof caseDoc.canonical_confidence === "number" ? caseDoc.canonical_confidence : null,
          );
          setCanonicalConfidenceReason(caseDoc.canonical_confidence_reason || null);
          setStatus(`▸ OPENED "${caseDoc.name}" (${caseDoc.engine} · ${caseDoc.confidence || 0}%) · legacy · recomputing panels…`);
          // ▲ 2026-02-28 · Restore IUE + Attack Story + Trajectory +
          // Analyst Narrative for saved cases so Prev-Mode surfaces
          // are identical to the freshly-analysed Workspace.
          const _input = caseDoc.input || "";
          if (_input.trim()) {
            setUnderstanding(null);
            setUnderstandingError(null);
            setUnderstandingSkipReason("");
            setUnderstandingLoading(true);
            setInlineStoryPreproc(null);
            setAnalystNarrative(null);
            // ▲ IUE v2.0 · reset investigation-mode; will be re-enabled
            // below when the IUE decides no decoding is required.
            setInvestigationMode(false);
            setInvestigationObject(null);
            // R28.10 · Deterministic path is INDEPENDENT of LLM outcome
            runInvestigationResults(_input);
            callLlmGracefully("/die/understand", { input: _input, execute: true }, {
              budgetBytes: LLM_INPUT_BUDGET.understand,
            }).then((res) => {
              if (res.ok) setUnderstanding(res.data?.understanding || null);
              else setUnderstandingSkipReason(res.reason || "");
              setUnderstandingLoading(false);
            });
            callLlmGracefully("/die/analyze", { input: _input }, {
              budgetBytes: LLM_INPUT_BUDGET.analyze,
            }).then((res) => {
              if (!res.ok) return;
              const pre = res.data?.result?.preprocessor
                       || res.data?.result?.chain?.preprocessor
                       || null;
              if (pre) setInlineStoryPreproc(pre);
            });
            callLlmGracefully("/die/narrate", { input: _input }, {
              budgetBytes: LLM_INPUT_BUDGET.narrate,
            }).then((res) => {
              if (res.ok) setAnalystNarrative(res.data?.narrative || null);
            });
          }
        }}
      />

      {/* Feb-2026 · Analyst-corrections modal — opened by ✎ launcher strip */}
      <CorrectionRefineModal
        open={refineOpen}
        onClose={() => setRefineOpen(false)}
        surface={refineCtx?.surface}
        wrongFinding={refineCtx?.wrong_finding || {}}
        inputText={input}
        defaultTags={[]}
        onRerun={autoInvestigate}
      />
    </div>
    </InvestigationFilterProvider>
  );
}


// 2026-02-09 · Anti-black-screen wrapper.
// Every render exception in the workspace tree — whether from the
// Trajectory canvas, a decoder response, a stale case restore, or
// an SSE stream callback — is caught here and shown as a recoverable
// error card instead of blanking the tab.  Mandatory SLA.
export default function WorkspacePage(props) {
  return (
    <WorkspaceErrorBoundary>
      <WorkspacePageInner {...props} />
    </WorkspaceErrorBoundary>
  );
}


/**
 * MagicResultCard — one candidate row inside the /decode/magic modal.
 *
 * When the candidate is flagged as shellcode by the backend
 * (`is_shellcode:true`), an inline `🔬 ANALYZE BINARY` toggle appears that
 * expands a full `ShellcodeView` (Capstone disassembly + IOC panel) directly
 * inside the modal — no need to Apply Chain first.
 */
function MagicResultCard({ r, idx, onApply }) {
  const [expanded, setExpanded] = useState(false);
  const sb = r.score_breakdown || {};
  return (
    <div className="brut-border" style={{ padding: 12, background: "var(--inset)" }}
         data-testid={`magic-result-${idx}`}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
        <div className="mono" style={{ fontSize: 12, color: "var(--accent)" }}>
          #{idx + 1} · SCORE <b style={{ color: "var(--warn)" }}>{sb.score}</b>
          {sb.printable !== undefined && ` · printable=${sb.printable}`}
          {sb.english !== undefined && ` · english=${sb.english}`}
          {r.is_shellcode && (
            <span className="badge" data-testid={`magic-result-${idx}-shellcode-badge`}
                  style={{ marginLeft: 8, background: "var(--high)22", color: "var(--high)", border: "1px solid var(--high)" }}>
              ⚠ SHELLCODE · {r.stop_condition?.reason?.replace(/_/g, " ")}
            </span>
          )}
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {r.is_shellcode && (
            <button
              className="nvx-btn sm ghost"
              onClick={() => setExpanded((v) => !v)}
              data-testid={`btn-magic-analyze-binary-${idx}`}
              style={{ borderColor: "var(--high)", color: "var(--high)" }}
            >
              <Sparkles size={11} /> {expanded ? "HIDE BINARY" : "🔬 ANALYZE BINARY"}
            </button>
          )}
          <button className="nvx-btn sm primary" onClick={onApply} data-testid={`btn-magic-apply-${idx}`}>
            <Play size={11} /> APPLY CHAIN
          </button>
        </div>
      </div>
      <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 8 }}>
        chain: {r.chain?.length ? r.chain.map((c) => c.op).join(" → ") : "(no ops — input already clean)"}
      </div>
      {sb.reasons?.length > 0 && (
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 8 }}>
          {sb.reasons.map((rr, ri) => <span key={ri} className="badge">{rr}</span>)}
        </div>
      )}
      <pre className="mono" style={{
        margin: 0, padding: 8, background: "var(--bg)", border: "1px solid var(--border)",
        fontSize: 11, color: "var(--text)", maxHeight: 160, overflow: "auto",
        whiteSpace: "pre-wrap", wordBreak: "break-all",
      }}>{(r.output || "").slice(0, 1200)}{(r.output || "").length > 1200 ? "…" : ""}</pre>

      {r.is_shellcode && expanded && (
        <div style={{ marginTop: 10 }} data-testid={`magic-shellcode-view-${idx}`}>
          <ShellcodeView output={r.output || ""} />
        </div>
      )}
    </div>
  );
}
