import "@/App.css";
import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";

// LoginPage stays eager — must render on first paint for unauth users.
import LoginPage from "@/pages/LoginPage";
import FloatingAddNoteButton from "@/components/FloatingAddNoteButton";
import QuickOpenPalette from "@/components/QuickOpenPalette";
import { Toaster } from "@/components/ui/sonner";

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
const TrainingInboxPage     = lazy(() => import("@/pages/TrainingInboxPage"));
const LearnerPage           = lazy(() => import("@/pages/LearnerPage"));
const BenchmarkPage         = lazy(() => import("@/pages/BenchmarkPage"));
const MultiLayerBatteryPage = lazy(() => import("@/pages/MultiLayerBatteryPage"));
const AnalystWorkspacePage  = lazy(() => import("@/pages/AnalystWorkspacePage"));
const AnalystRC5Page        = lazy(() => import("@/pages/AnalystRC5Page"));
const AutoInvestigatePage   = lazy(() => import("@/pages/AutoInvestigatePage"));
const SemanticMappingInspectorPage = lazy(() => import("@/pages/SemanticMappingInspectorPage"));

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
const NivxForgeGraphPopoutPage = lazy(() => import("@/nivxforge/pages/XLabGraphPopoutPage"));
const NivxForgeDashboardPage   = lazy(() => import("@/nivxforge/pages/DashboardPage"));
const NivxForgeThreatIntelPage    = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.ThreatIntelPage })));
const NivxForgeThreatHuntingPage  = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.ThreatHuntingPage })));
const NivxForgeKnowledgeBasePage  = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.KnowledgeBasePage })));
const NivxForgeReportsPage        = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.ReportsPage })));
const NivxForgeHistoryPage        = lazy(() => import("@/nivxforge/pages/PlaceholderSections").then(m => ({ default: m.HistoryPage })));

// X-Lab · redirect stub that forces the ?lab2=1 feature flag on. When
// legacy Lab is deleted this route will point directly at the X-Lab
// renderer without the flag dance.
function NivxForgeXLabRedirect() {
  return <Navigate to="/nivxforge/investigate?lab2=1" replace />;
}

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return children;
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
              <Route path="/" element={<Protected><WorkspacePage /></Protected>} />
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
              <Route path="/learner" element={<Protected><LearnerPage /></Protected>} />
              <Route path="/benchmark" element={<BenchmarkPage />} />
              <Route path="/battery"   element={<Protected><MultiLayerBatteryPage /></Protected>} />
              <Route path="/analyst"   element={<Protected><AnalystWorkspacePage /></Protected>} />
              <Route path="/analyst/rc5" element={<Protected><AnalystRC5Page /></Protected>} />
              <Route path="/auto-investigate" element={<Protected><AutoInvestigatePage /></Protected>} />
              {/* Semantic Mapping Inspector — Stage 3 engineering surface (Feb 2026). */}
              <Route path="/lab/semantic-mapping-inspector" element={<Protected><SemanticMappingInspectorPage /></Protected>} />
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
              {/* X-Lab · Unified next-generation investigation workspace.
                  Forces the lab2 flag on so the shell always mounts the
                  X-Lab renderer. Legacy /nivxforge/investigate remains
                  available during the parity-migration window. */}
              <Route path="/nivxforge/x-lab" element={<Protected><NivxForgeXLabRedirect /></Protected>} />
              <Route path="/nivxforge/x-lab/graph" element={<Protected><NivxForgeGraphPopoutPage /></Protected>} />
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
