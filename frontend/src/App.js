import "@/App.css";
import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";

// LoginPage stays eager — must render on first paint for unauth users.
import LoginPage from "@/pages/LoginPage";
import FloatingAddNoteButton from "@/components/FloatingAddNoteButton";

// Route-based code splitting (Perf Sprint · Feb 2026). Each page below
// ships as its own webpack chunk and downloads on-demand when the route
// is first hit. Cuts the initial JS payload from ~1.4 MB to a small
// shell + LoginPage.
const WorkspacePage         = lazy(() => import("@/pages/WorkspacePage"));
const DashboardPage         = lazy(() => import("@/pages/DashboardPage"));
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
const TrainingInboxPage     = lazy(() => import("@/pages/TrainingInboxPage"));
const LearnerPage           = lazy(() => import("@/pages/LearnerPage"));
const BenchmarkPage         = lazy(() => import("@/pages/BenchmarkPage"));
const MultiLayerBatteryPage = lazy(() => import("@/pages/MultiLayerBatteryPage"));
const AnalystWorkspacePage  = lazy(() => import("@/pages/AnalystWorkspacePage"));
const AnalystRC5Page        = lazy(() => import("@/pages/AnalystRC5Page"));
const PreviewCommandHub     = lazy(() => import("@/pages/PreviewCommandHub"));
const CommandHubPage        = lazy(() => import("@/pages/CommandHubPage"));

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
              <Route path="/dashboard" element={<Protected><DashboardPage /></Protected>} />
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
              <Route path="/learner" element={<Protected><LearnerPage /></Protected>} />
              <Route path="/benchmark" element={<BenchmarkPage />} />
              <Route path="/battery"   element={<Protected><MultiLayerBatteryPage /></Protected>} />
              <Route path="/analyst"   element={<Protected><AnalystWorkspacePage /></Protected>} />
              <Route path="/analyst/rc5" element={<Protected><AnalystRC5Page /></Protected>} />
              {/* Feb-2026 · Command Hub — production route (authed). */}
              <Route path="/command-hub" element={<Protected><CommandHubPage /></Protected>} />
              {/* Feb-2026 · design preview — public, NOT wired into production nav. */}
              <Route path="/preview/command-hub" element={<PreviewCommandHub />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
          <FloatingAddNoteButton />
        </AuthProvider>
      </BrowserRouter>
    </div>
  );
}

export default App;
