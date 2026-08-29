import "@/App.css";
import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate, useParams } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";

// LoginPage stays eager — must render on first paint for unauth users.
import LoginPage from "@/pages/LoginPage";
import FloatingAddNoteButton from "@/components/FloatingAddNoteButton";
import QuickOpenPalette from "@/components/QuickOpenPalette";
import PageErrorBoundary from "@/components/PageErrorBoundary";
import { Toaster } from "@/components/ui/sonner";

// NivXForge EDR reserved sub-pages (tiny stubs — no need to code-split).
import {
  EdrDetectionsPage, EdrProcessTreePage, EdrFilesPage, EdrNetworkPage,
  EdrHuntingPage, EdrForensicsPage, EdrLiveQueryPage, EdrResponsePage,
} from "@/nivxforge/pages/EdrReservedPages";

// Route-based code splitting (Perf Sprint · Feb 2026). Each page below
// ships as its own webpack chunk and downloads on-demand when the route
// is first hit. Cuts the initial JS payload from ~1.4 MB to a small
// shell + LoginPage.
const WorkspacePage         = lazy(() => import("@/pages/WorkspacePage"));
const CommandAnalyzerPage   = lazy(() => import("@/pages/CommandAnalyzerPage"));
const AdminPage             = lazy(() => import("@/pages/AdminPage"));
const ModelStudioPage       = lazy(() => import("@/pages/ModelStudioPage"));
const SampleLibraryPage     = lazy(() => import("@/pages/SampleLibraryPage"));
const ThreatIntelPage       = lazy(() => import("@/pages/ThreatIntelPage"));
const ThreatModelPage       = lazy(() => import("@/pages/ThreatModelPage"));
const CorrectionsAdminPage  = lazy(() => import("@/pages/CorrectionsAdminPage"));
const KnowledgeBasePage     = lazy(() => import("@/pages/KnowledgeBasePage"));
const DocsPage              = lazy(() => import("@/pages/DocsPage"));
const DocumentsPage         = lazy(() => import("@/pages/DocumentsPage"));
const BatchTestPage         = lazy(() => import("@/pages/BatchTestPage"));
const MitreHeatmapPage      = lazy(() => import("@/pages/MitreHeatmapPage"));
const LabPage               = lazy(() => import("@/pages/LabPage"));
const IEDDETracePage        = lazy(() => import("@/pages/IEDDETracePage"));
const HistoryPage           = lazy(() => import("@/pages/HistoryPage"));
// Phase 4 · P1 · Cross-Artifact Correlation (2026-02-15)
// First-class Investigation entity — groups correlated cases into a
// single attack story with unified chain, graph, timeline, and summary.
const InvestigationsPage       = lazy(() => import("@/pages/InvestigationsPage"));
const InvestigationDetailPage  = lazy(() => import("@/pages/InvestigationDetailPage"));
const InvestigationSummaryPage = lazy(() => import("@/pages/InvestigationSummaryPage"));
// Phase A.5 · item 3.7 · Attack Story consolidation (2026-02-16)
// The retired InvestigationReplayPage no longer routes. Existing
// bookmarks `/investigations/:id/replay` deep-link into the Story tab
// on the Investigation Detail page via the ReplayRedirect below.
const ComparePage              = lazy(() => import("@/pages/ComparePage"));
const PlatformHealthPage       = lazy(() => import("@/pages/PlatformHealthPage"));
const TrainingInboxPage     = lazy(() => import("@/pages/TrainingInboxPage"));
const LearnerPage           = lazy(() => import("@/pages/LearnerPage"));
const BenchmarkPage         = lazy(() => import("@/pages/BenchmarkPage"));
const MultiLayerBatteryPage = lazy(() => import("@/pages/MultiLayerBatteryPage"));
const AnalystWorkspacePage  = lazy(() => import("@/pages/AnalystWorkspacePage"));
const AnalystRC5Page        = lazy(() => import("@/pages/AnalystRC5Page"));
const DeviceTrajectoryPage  = lazy(() => import("@/pages/DeviceTrajectoryPage"));
const AutoInvestigatePage   = lazy(() => import("@/pages/AutoInvestigatePage"));
// Slice 1 · Canonical Incident shell (2026-08-27) — dense operational
// queue + Incident detail (Overview / Investigation / Activity /
// Response).  Reads workspace_cases through /api/incidents; does NOT
// create a parallel model, does NOT touch /analyst.
const IncidentsListPage     = lazy(() => import("@/pages/incidents/IncidentsListPage"));
const IncidentShellPage     = lazy(() => import("@/pages/incidents/IncidentShellPage"));
// Slice 1 · NivXRay XDR platform shell (owner spec 2026-08-29) — a
// navigation layer over existing NivXRay capabilities.  /analyst and
// every underlying implementation stay untouched.
const XdrDashboardPage      = lazy(() => import("@/xdr/pages/XdrDashboardPage"));
const XdrIncidentsPage      = lazy(() => import("@/xdr/pages/XdrIncidentsPage"));
const XdrIncidentDetailPage = lazy(() => import("@/xdr/pages/XdrIncidentDetailPage"));
// NivXForge EDR Console (owner spec 2026-08-29) — Incident always
// enters through /edr (Console Overview) and pivots into the
// existing /edr/trajectory implementation from the sidebar.
const EdrOverviewPage       = lazy(() => import("@/nivxforge/pages/EdrOverviewPage"));
// L4 · Investigation Session (Rule R22 · 2026-03-02) — dedicated
// deep-dive surface for a completed threat-report investigation.
// Every extracted artifact is a first-class Investigation Input.
const InvestigationSessionPage      = lazy(() => import("@/pages/InvestigationSessionPage"));
const InvestigationInputDetailPage  = lazy(() => import("@/pages/InvestigationInputDetailPage"));

const V2CaseWorkspaceShell  = lazy(() => import("@/v2/pages/CaseWorkspaceShell"));
// L4 Analyst Workspace shell (PR-3 · Blueprint v1.1 §7-§9). Additive
// route; every existing route above stays live. Content lands in PR-4+.
const AnalystWorkspaceShellPage = lazy(() => import("@/workspace_v4/AnalystWorkspaceShellPage"));
const V2DeviceTrajectory    = lazy(() => import("@/v2/pages/DeviceTrajectoryV2"));
const V2IRGWorkspace        = lazy(() => import("@/v2/pages/IRGWorkspace"));
const V2CompareWorkspace    = lazy(() => import("@/v2/pages/CompareWorkspace"));
const V2ProcessAncestry     = lazy(() => import("@/v2/pages/ProcessAncestry"));
// v2 · Unified Investigation Workspace shell (Phase 1 of the Enterprise
// Attack Investigation Platform pivot). Additive — every existing route
// stays live. Loads the Investigation Knowledge Graph (IKG) and embeds
// the Trajectory canvas as one tab.
const V2InvestigationWorkspace = lazy(() => import("@/v2/pages/InvestigationWorkspace"));
// v2 · Investigation Ingestion Engine (Phase 4.1) — drag-drop uploader,
// canonical event schema normalizer, golden corpus seed buttons.
const V2IngestionPage          = lazy(() => import("@/v2/pages/IngestionPage"));
// v2 · Validation Pack (Phase 4.2) — Golden Corpus × Expected Investigation matrix.
const V2ValidationPage         = lazy(() => import("@/v2/pages/ValidationPage"));

// NivXForge (Preview) — evidence-driven governance surface. Read-only.
// ADR-0005 authorised the router mount (2026-02-28); this page consumes
// /api/nivxforge/preview/* GET endpoints only.
const NivxForgePreviewPage     = lazy(() => import("@/nivxforge/pages/PreviewPage"));
const NivxForgeInvestigatePage = lazy(() => import("@/nivxforge/pages/InvestigatePage"));
const NivxForgeDashboardPage   = lazy(() => import("@/nivxforge/pages/DashboardPage"));
const NivxForgeThreatIntelPage    = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.ThreatIntelPage })));
const NivxForgeThreatHuntingPage  = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.ThreatHuntingPage })));
const NivxForgeKnowledgeBasePage  = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.KnowledgeBasePage })));
const NivxForgeReportsPage        = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.ReportsPage })));
const NivxForgeHistoryPage        = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.HistoryPage })));

// X-Lab observational surface removed 2026-08-11 (owner directive after
// ADR-005 X-Lab Removal Impact Audit). The `/nivxforge/x-lab*` routes
// and the ?lab2=1 renderer toggle are gone; `/nivxforge/investigate`
// now exclusively mounts the legacy production renderer.

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

// Phase A.5 · item 3.7 · Attack Story consolidation.
// `/investigations/:id/replay` no longer has its own page — the deep
// link now hydrates the Story tab on the Investigation Detail page.
function ReplayRedirect() {
  const { id } = useParams();
  return <Navigate to={`/investigations/${id}?tab=story`} replace />;
}

// Lightweight route-transition fallback. Rendered while the target
// chunk is fetching; kept intentionally minimal to avoid any layout
// shift or perceived flash.
function RouteFallback() {
  return (
    <div
      data-testid="route-suspense-fallback"
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "60vh",
        color: "#94a3b8",
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 12,
        letterSpacing: "0.08em",
      }}
    >
      <span style={{ opacity: 0.7 }}>loading …</span>
    </div>
  );
}

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <AuthProvider>
          <Suspense fallback={<RouteFallback />}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/" element={<Protected><PageErrorBoundary><WorkspacePage /></PageErrorBoundary></Protected>} />
              <Route path="/analyze" element={<Protected><CommandAnalyzerPage /></Protected>} />
              <Route path="/threat-intel" element={<Protected><ThreatIntelPage /></Protected>} />
              <Route path="/threat-model" element={<Protected><ThreatModelPage /></Protected>} />
              <Route path="/admin/corrections" element={<Protected><CorrectionsAdminPage /></Protected>} />
              <Route path="/docs" element={<Protected><DocsPage /></Protected>} />
              <Route path="/documents" element={<Protected><DocumentsPage /></Protected>} />
              <Route path="/kb" element={<Protected><KnowledgeBasePage /></Protected>} />
              <Route path="/admin" element={<Protected><AdminPage /></Protected>} />
              <Route path="/admin/models" element={<Protected><ModelStudioPage /></Protected>} />
              <Route path="/admin/samples" element={<Protected><SampleLibraryPage /></Protected>} />
              <Route path="/admin/training-inbox" element={<Protected><TrainingInboxPage /></Protected>} />
              <Route path="/batch-test" element={<Protected><BatchTestPage /></Protected>} />
              <Route path="/heatmap" element={<Protected><MitreHeatmapPage /></Protected>} />
              <Route path="/lab" element={<Protected><LabPage /></Protected>} />
              <Route path="/iedde" element={<Protected><IEDDETracePage /></Protected>} />
              <Route path="/history" element={<Protected><HistoryPage /></Protected>} />
              {/* Phase 4 · P1 · Cross-Artifact Correlation (2026-02-15) */}
              <Route path="/investigations" element={<Protected><InvestigationsPage /></Protected>} />
              <Route path="/investigations/:id" element={<Protected><InvestigationDetailPage /></Protected>} />
              <Route path="/investigation-summary" element={<Protected><InvestigationSummaryPage /></Protected>} />
              <Route path="/investigations/:id/replay" element={<Protected><ReplayRedirect /></Protected>} />
              <Route path="/compare" element={<Protected><ComparePage /></Protected>} />
              <Route path="/compare/:caseA/:caseB" element={<Protected><ComparePage /></Protected>} />
              <Route path="/platform" element={<Protected><PlatformHealthPage /></Protected>} />
              <Route path="/learner" element={<Protected><LearnerPage /></Protected>} />
              <Route path="/benchmark" element={<BenchmarkPage />} />
              <Route path="/battery"   element={<Protected><MultiLayerBatteryPage /></Protected>} />
              <Route path="/analyst"   element={<Protected><AnalystWorkspacePage /></Protected>} />
              <Route path="/analyst/rc5" element={<Protected><AnalystRC5Page /></Protected>} />
              {/* NivXRay Forge · EDR Device Trajectory (owner spec 2026-08-26) */}
              <Route path="/edr/trajectory" element={<Protected><DeviceTrajectoryPage /></Protected>} />
              {/* Slice 1 · Canonical Incident shell (owner spec 2026-08-27) */}
              <Route path="/incidents"      element={<Protected><IncidentsListPage /></Protected>} />
              <Route path="/incidents/:id"  element={<Protected><IncidentShellPage /></Protected>} />
              {/* NivXRay XDR platform shell (owner spec 2026-08-29) */}
              <Route path="/xdr"                 element={<Protected><XdrDashboardPage /></Protected>} />
              <Route path="/xdr/incidents"       element={<Protected><XdrIncidentsPage /></Protected>} />
              <Route path="/xdr/incidents/:id"   element={<Protected><XdrIncidentDetailPage /></Protected>} />

              {/* NivXForge EDR Console (owner spec 2026-08-29) — endpoint
                  security console inside NivXRay XDR.  /edr/trajectory
                  is UNCHANGED and remains the Device Trajectory surface;
                  we simply wrap it in the Console shell via sidebar
                  navigation. */}
              <Route path="/edr"               element={<Protected><EdrOverviewPage /></Protected>} />
              <Route path="/edr/detections"    element={<Protected><EdrDetectionsPage /></Protected>} />
              <Route path="/edr/process-tree"  element={<Protected><EdrProcessTreePage /></Protected>} />
              <Route path="/edr/files"         element={<Protected><EdrFilesPage /></Protected>} />
              <Route path="/edr/network"       element={<Protected><EdrNetworkPage /></Protected>} />
              <Route path="/edr/hunting"       element={<Protected><EdrHuntingPage /></Protected>} />
              <Route path="/edr/forensics"     element={<Protected><EdrForensicsPage /></Protected>} />
              <Route path="/edr/live-query"    element={<Protected><EdrLiveQueryPage /></Protected>} />
              <Route path="/edr/response"      element={<Protected><EdrResponsePage /></Protected>} />
              <Route path="/auto-investigate" element={<Protected><AutoInvestigatePage /></Protected>} />
              {/* L4 · Investigation Session · Rule R22 (2026-03-02) */}
              <Route path="/workspace/session/:sessionId"
                     element={<Protected><InvestigationSessionPage /></Protected>} />
              <Route path="/workspace/session/:sessionId/input/:inputId"
                     element={<Protected><InvestigationInputDetailPage /></Protected>} />
              {/* Legacy alias — the previous "Evidence Explorer" route
                  still resolves so existing bookmarks keep working. */}
              <Route path="/evidence-explorer"
                     element={<Protected><InvestigationSessionPage /></Protected>} />
              {/* v2 · Case Workspace shell — flag-gated inside the
                  component. Reachable only via direct URL, never
                  linked from primary navigation. */}
              <Route path="/v2/workspace/:caseId" element={<Protected><V2CaseWorkspaceShell /></Protected>} />
              <Route path="/v2/workspace" element={<Protected><V2CaseWorkspaceShell /></Protected>} />
              {/* v2 · Device Trajectory (Phase 3e) — flag-gated inside component. */}
              <Route path="/v2/trajectory/:caseId" element={<Protected><V2DeviceTrajectory /></Protected>} />
              <Route path="/v2/trajectory"         element={<Protected><V2DeviceTrajectory /></Protected>} />
              {/* v2 · Investigation Relationship Graph (IRG) — new top-level view */}
              <Route path="/v2/irg/:caseId"        element={<Protected><V2IRGWorkspace /></Protected>} />
              <Route path="/v2/irg"                element={<Protected><V2IRGWorkspace /></Protected>} />
              {/* v2 · Side-by-side case comparison */}
              <Route path="/v2/compare"                       element={<Protected><V2CompareWorkspace /></Protected>} />
              <Route path="/v2/compare/:caseA/:caseB"         element={<Protected><V2CompareWorkspace /></Protected>} />
              <Route path="/v2/ancestry/:caseId/:processIid" element={<Protected><V2ProcessAncestry /></Protected>} />
              {/* v2 · Unified Investigation Workspace (Phase 1) — reads
                  the IKG once and hosts every view. Legacy routes remain
                  untouched; existing links keep working. */}
              <Route path="/v2/case/:caseId" element={<Protected><V2InvestigationWorkspace /></Protected>} />
              {/* v2 · Investigation Ingestion Engine — drag-drop upload page */}
              <Route path="/v2/ingest" element={<Protected><V2IngestionPage /></Protected>} />
              {/* v2 · Validation Pack — 34-dataset Golden Corpus matrix */}
              <Route path="/v2/validation" element={<Protected><V2ValidationPage /></Protected>} />
              {/* NivXForge (ADR-0006 · Phase 1 + platform shell) · analyst-parity surface + governance */}
              <Route path="/nivxforge"              element={<Protected><NivxForgeDashboardPage /></Protected>} />
              <Route path="/nivxforge/dashboard"    element={<Protected><NivxForgeDashboardPage /></Protected>} />
              <Route path="/nivxforge/investigate"  element={<Protected><NivxForgeInvestigatePage /></Protected>} />
              <Route path="/nivxforge/threat-intel" element={<Protected><NivxForgeThreatIntelPage /></Protected>} />
              <Route path="/nivxforge/hunting"      element={<Protected><NivxForgeThreatHuntingPage /></Protected>} />
              <Route path="/nivxforge/knowledge"    element={<Protected><NivxForgeKnowledgeBasePage /></Protected>} />
              <Route path="/nivxforge/reports"      element={<Protected><NivxForgeReportsPage /></Protected>} />
              <Route path="/nivxforge/history"      element={<Protected><NivxForgeHistoryPage /></Protected>} />
              <Route path="/nivxforge/governance"   element={<Protected><NivxForgePreviewPage /></Protected>} />
              {/* L4 Analyst Workspace (PR-3 · Blueprint v1.1). Additive:
                  every legacy route above continues to work unchanged.
                  Shell only in this PR; lens content lands in PR-4+. */}
              <Route path="/investigate"           element={<Protected><AnalystWorkspaceShellPage /></Protected>} />
              <Route path="/investigate/:caseId"   element={<Protected><AnalystWorkspaceShellPage /></Protected>} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
          <FloatingAddNoteButton />
          <QuickOpenPalette />
          <Toaster richColors position="bottom-right" data-testid="toaster" />
        </AuthProvider>
      </BrowserRouter>
    </div>
  );
}

export default App;
