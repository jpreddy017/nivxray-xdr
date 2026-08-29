/**
 * IncidentShellPage · `/incidents/:id`
 *
 * Canonical Incident shell — Slice 1.
 *   • Header (number · name · priority · severity · verdict · assignee)
 *   • Lifecycle stepper (5 states)
 *   • 4 top-level tabs: Overview · Investigation · Activity · Response
 *
 * Reuses existing capabilities via deep links.  Does NOT duplicate
 * Device Trajectory, MITRE, Process Tree, Command Intelligence, or
 * Verdict.  Does NOT touch `/analyst`.
 */
import React, { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { AlertOctagon, ChevronLeft } from "lucide-react";

import Header from "@/components/Header";
import IncidentHeader   from "@/components/incidents/IncidentHeader";
import LifecycleBar     from "@/components/incidents/LifecycleBar";
import OverviewTab      from "@/components/incidents/tabs/OverviewTab";
import InvestigationTab from "@/components/incidents/tabs/InvestigationTab";
import ActivityTab      from "@/components/incidents/tabs/ActivityTab";
import ResponseTab      from "@/components/incidents/tabs/ResponseTab";

import { getIncident, transitionIncidentState } from "@/lib/incidentsApi";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

const TOP_TABS = [
  { key: "overview",      label: "Overview" },
  { key: "investigation", label: "Investigation" },
  { key: "activity",      label: "Activity" },
  { key: "response",      label: "Response" },
];

export default function IncidentShellPage() {
  const { id } = useParams();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [activeTab, setActiveTab] = useState("overview");

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true); setError(null);
    try {
      const data = await getIncident(id);
      setIncident(data);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load incident.");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const handleTransition = async (targetState) => {
    const updated = await transitionIncidentState(id, targetState);
    setIncident(updated);
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg, #020617)", color: "#e2e8f0" }}>
      <Header />
      <main
        data-testid={T.shellPage}
        style={{ maxWidth: 1400, margin: "0 auto", padding: "24px 22px 48px" }}
      >
        <div style={{ marginBottom: 12 }}>
          <Link
            to="/incidents"
            style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 11, letterSpacing: "0.14em",
              color: "rgba(148,163,184,0.85)",
              textDecoration: "none",
              textTransform: "uppercase",
            }}
          >
            <ChevronLeft size={13} /> Back to queue
          </Link>
        </div>

        {loading && (
          <div data-testid={T.shellLoading}
               style={{
                 padding: "60px 0", textAlign: "center",
                 color: "rgba(148,163,184,0.75)",
                 fontFamily: "JetBrains Mono, monospace",
                 fontSize: 12, letterSpacing: "0.14em",
               }}>
            LOADING INCIDENT …
          </div>
        )}

        {!loading && error && (
          <div data-testid={T.shellError}
               style={{
                 padding: 18,
                 border: "1px solid rgba(239,68,68,0.4)",
                 borderRadius: 10,
                 background: "rgba(239,68,68,0.06)",
                 color: "#fca5a5",
                 display: "flex", gap: 10, alignItems: "flex-start",
                 fontFamily: "JetBrains Mono, monospace",
                 fontSize: 12,
               }}>
            <AlertOctagon size={16} style={{ marginTop: 2 }} />
            <span>{String(error)}</span>
          </div>
        )}

        {!loading && !error && incident && (
          <>
            <IncidentHeader incident={incident} />
            <LifecycleBar
              state={incident.state}
              onTransition={handleTransition}
            />

            {/* Top-level tabs strip */}
            <nav
              role="tablist"
              data-testid={T.topTabs}
              aria-label="Incident top-level tabs"
              style={{
                marginTop: 18,
                display: "flex", gap: 4,
                padding: 4,
                borderRadius: 10,
                background: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.62))",
                border: "1px solid rgba(148,163,184,0.14)",
              }}
            >
              {TOP_TABS.map((tab) => {
                const isActive = tab.key === activeTab;
                return (
                  <button
                    key={tab.key}
                    role="tab"
                    type="button"
                    onClick={() => setActiveTab(tab.key)}
                    data-testid={T.topTab(tab.key)}
                    data-active={isActive || undefined}
                    aria-selected={isActive}
                    style={{
                      padding: "8px 16px",
                      borderRadius: 6,
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: 11, letterSpacing: "0.14em",
                      textTransform: "uppercase",
                      fontWeight: 600,
                      cursor: "pointer",
                      color: isActive ? "#86efac" : "rgba(203,213,225,0.75)",
                      background: isActive
                        ? "linear-gradient(160deg, rgba(34,197,94,0.16), rgba(34,197,94,0.03))"
                        : "transparent",
                      border: `1px solid ${isActive ? "rgba(34,197,94,0.55)" : "transparent"}`,
                      transition: "color 160ms ease, background 200ms ease, border-color 200ms ease",
                    }}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </nav>

            <div style={{ marginTop: 16 }}>
              {activeTab === "overview"      && <OverviewTab      incident={incident} />}
              {activeTab === "investigation" && <InvestigationTab incident={incident} />}
              {activeTab === "activity"      && <ActivityTab      incident={incident} />}
              {activeTab === "response"      && <ResponseTab />}
            </div>
          </>
        )}
      </main>
    </div>
  );
}
