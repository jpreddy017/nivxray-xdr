/**
 * IncidentShellPage · `/incidents/:id` — NivXRay ONE XDR skin.
 *
 * Reference: nivxray-one-xdr-console-8.html.
 *   • inc-header  (§inc-header)
 *   • progression (§progression) — 5-state lifecycle
 *   • tabbar/tabpanel with purple underline for the active tab
 *   • Investigation sub-tabbar with mint underline (rendered inside
 *     the Investigation tab itself)
 *
 * Reuses existing implementations via deep links — never duplicates
 * Device Trajectory, MITRE, Process Tree, Command Intelligence, or
 * Verdict.  Does NOT touch /analyst.
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
import "./xdr.css";

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
  const [tab, setTab]           = useState("overview");

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true); setError(null);
    try {
      setIncident(await getIncident(id));
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load incident.");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const handleTransition = async (target) => {
    const updated = await transitionIncidentState(id, target);
    setIncident(updated);
  };

  return (
    <div className="xdr-scope">
      <Header />
      <main data-testid={T.shellPage} className="x-container">
        <div style={{ marginBottom: 10 }}>
          <Link
            to="/incidents"
            style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              color: "var(--xmuted)", textDecoration: "none",
              fontSize: 10.5, letterSpacing: ".4px",
              textTransform: "uppercase", fontWeight: 700,
            }}
          >
            <ChevronLeft size={12} /> Back to queue
          </Link>
        </div>

        {loading && (
          <div data-testid={T.shellLoading} className="x-empty">
            LOADING INCIDENT…
          </div>
        )}
        {!loading && error && (
          <div data-testid={T.shellError} className="x-empty" style={{ color: "#ff9494" }}>
            <AlertOctagon size={14} style={{ verticalAlign: "middle", marginRight: 6 }} />
            {String(error)}
          </div>
        )}

        {!loading && !error && incident && (
          <>
            <IncidentHeader incident={incident} />
            <LifecycleBar
              state={incident.state}
              onTransition={handleTransition}
            />

            <nav
              className="tabbar"
              role="tablist"
              aria-label="Incident top-level tabs"
              data-testid={T.topTabs}
            >
              {TOP_TABS.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  role="tab"
                  className={`tabbtn ${tab === t.key ? "active" : ""}`}
                  data-testid={T.topTab(t.key)}
                  data-active={tab === t.key || undefined}
                  aria-selected={tab === t.key}
                  onClick={() => setTab(t.key)}
                >
                  {t.label}
                </button>
              ))}
            </nav>

            <div className="tabpanel">
              {tab === "overview"      && <OverviewTab      incident={incident} />}
              {tab === "investigation" && <InvestigationTab incident={incident} />}
              {tab === "activity"      && <ActivityTab      incident={incident} />}
              {tab === "response"      && <ResponseTab />}
            </div>
          </>
        )}
      </main>
    </div>
  );
}
