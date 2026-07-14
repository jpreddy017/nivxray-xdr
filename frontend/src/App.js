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
