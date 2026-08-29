/**
 * NivXRay XDR standalone router.
 *
 * Routes are kept at their pathnames as they existed in the base app
 * (e.g. `/xdr`, `/xdr/incidents/:id`, `/edr/detections`) so every
 * data-testid and internal navigate() call in the moved source stays
 * byte-identical.  Vite `base: "/xdr/"` handles asset URL prefixing.
 */
import React, { lazy, Suspense } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";

import { useAuth } from "@/lib/auth";
import LoginPage from "@/pages/LoginPage";

const XdrDashboardPage       = lazy(() => import("@/xdr/pages/XdrDashboardPage"));
const XdrIncidentsPage       = lazy(() => import("@/xdr/pages/XdrIncidentsPage"));
const XdrIncidentDetailPage  = lazy(() => import("@/xdr/pages/XdrIncidentDetailPage"));

const EdrOverviewPage        = lazy(() => import("@/nivxforge/pages/EdrOverviewPage"));
const EdrDetectionsPage      = lazy(() => import("@/nivxforge/pages/EdrDetectionsPage"));
const EdrProcessTreePage     = lazy(() => import("@/nivxforge/pages/EdrProcessTreePage"));

const EdrReserved = lazy(() =>
  import("@/nivxforge/pages/EdrReservedPages").then((m) => ({ default: m })),
);

// Reserved endpoint-console tabs — each is a tiny stub in the source.
const EdrFilesPage      = lazy(() => import("@/nivxforge/pages/EdrReservedPages").then(m => ({ default: m.EdrFilesPage })));
const EdrNetworkPage    = lazy(() => import("@/nivxforge/pages/EdrReservedPages").then(m => ({ default: m.EdrNetworkPage })));
const EdrHuntingPage    = lazy(() => import("@/nivxforge/pages/EdrReservedPages").then(m => ({ default: m.EdrHuntingPage })));
const EdrForensicsPage  = lazy(() => import("@/nivxforge/pages/EdrReservedPages").then(m => ({ default: m.EdrForensicsPage })));
const EdrLiveQueryPage  = lazy(() => import("@/nivxforge/pages/EdrReservedPages").then(m => ({ default: m.EdrLiveQueryPage })));
const EdrResponsePage   = lazy(() => import("@/nivxforge/pages/EdrReservedPages").then(m => ({ default: m.EdrResponsePage })));

function Protected({ children }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return null;
  if (!user) {
    // Preserve the requested URL so login can bounce back.
    const returnTo = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?returnTo=${returnTo}`} replace />;
  }
  return children;
}

function RouteFallback() {
  return (
    <div
      data-testid="xdr-route-suspense-fallback"
      style={{
        display: "flex", justifyContent: "center", alignItems: "center",
        minHeight: "60vh", color: "#94a3b8",
        fontFamily: "'IBM Plex Mono', monospace", fontSize: 12,
        letterSpacing: "0.08em",
      }}
    >
      <span style={{ opacity: 0.7 }}>loading …</span>
    </div>
  );
}

export default function App() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        {/* Standalone login — reuses POST /api/auth/login. */}
        <Route path="/login" element={<LoginPage />} />

        {/* Root of the standalone app. */}
        <Route path="/xdr"                 element={<Protected><XdrDashboardPage /></Protected>} />
        <Route path="/xdr/incidents"       element={<Protected><XdrIncidentsPage /></Protected>} />
        <Route path="/xdr/incidents/:id"   element={<Protected><XdrIncidentDetailPage /></Protected>} />

        {/* NivXForge EDR Console — pivots to /edr/trajectory in the
            ORIGINAL NivXRay app via a new browser tab (never
            duplicated inside this bundle). */}
        <Route path="/edr"               element={<Protected><EdrOverviewPage /></Protected>} />
        <Route path="/edr/detections"    element={<Protected><EdrDetectionsPage /></Protected>} />
        <Route path="/edr/process-tree"  element={<Protected><EdrProcessTreePage /></Protected>} />
        <Route path="/edr/files"         element={<Protected><EdrFilesPage /></Protected>} />
        <Route path="/edr/network"       element={<Protected><EdrNetworkPage /></Protected>} />
        <Route path="/edr/hunting"       element={<Protected><EdrHuntingPage /></Protected>} />
        <Route path="/edr/forensics"     element={<Protected><EdrForensicsPage /></Protected>} />
        <Route path="/edr/live-query"    element={<Protected><EdrLiveQueryPage /></Protected>} />
        <Route path="/edr/response"      element={<Protected><EdrResponsePage /></Protected>} />

        <Route path="*" element={<Navigate to="/xdr" replace />} />
      </Routes>
    </Suspense>
  );
}
