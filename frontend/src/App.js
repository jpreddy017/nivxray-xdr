import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";
import LoginPage from "@/pages/LoginPage";
import WorkspacePage from "@/pages/WorkspacePage";
import CommandAnalyzerPage from "@/pages/CommandAnalyzerPage";
import AdminPage from "@/pages/AdminPage";
import ModelStudioPage from "@/pages/ModelStudioPage";
import SampleLibraryPage from "@/pages/SampleLibraryPage";
import ThreatIntelPage from "@/pages/ThreatIntelPage";
import ThreatModelPage from "@/pages/ThreatModelPage";
import CorrectionsAdminPage from "@/pages/CorrectionsAdminPage";
import KnowledgeBasePage from "@/pages/KnowledgeBasePage";
import DocsPage from "@/pages/DocsPage";
import FloatingAddNoteButton from "@/components/FloatingAddNoteButton";

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/" element={<Protected><WorkspacePage /></Protected>} />
            <Route path="/analyze" element={<Protected><CommandAnalyzerPage /></Protected>} />
            <Route path="/threat-intel" element={<Protected><ThreatIntelPage /></Protected>} />
            <Route path="/threat-model" element={<Protected><ThreatModelPage /></Protected>} />
            <Route path="/admin/corrections" element={<Protected><CorrectionsAdminPage /></Protected>} />
            <Route path="/docs" element={<Protected><DocsPage /></Protected>} />
            <Route path="/kb" element={<Protected><KnowledgeBasePage /></Protected>} />
            <Route path="/admin" element={<Protected><AdminPage /></Protected>} />
            <Route path="/admin/models" element={<Protected><ModelStudioPage /></Protected>} />
            <Route path="/admin/samples" element={<Protected><SampleLibraryPage /></Protected>} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          <FloatingAddNoteButton />
        </AuthProvider>
      </BrowserRouter>
    </div>
  );
}

export default App;
