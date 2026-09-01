/**
 * XdrIncidentDetailPage · `/xdr/incidents/:id`
 *
 * Layer 3 · full product-quality rebuild of the Incident Record.
 * Defender/SIR-inspired: light analyst workspace for header /
 * lifecycle / tabs / executive / technical / evidence / notes /
 * timeline / related / closure surfaces + dark analyst canvas for
 * the deep engine panels (MITRE trajectory, Attack Story process
 * tree, Completeness + Recommendations).  Reuses the Layer 2 chip
 * primitives.
 *
 * Owner-locked rules:
 *   · Engine lock absolute — no engine is modified or invoked here.
 *   · Anti-fabrication kept honest: NOT_RUN · NO EVIDENCE ·
 *     NOT AVAILABLE · UNKNOWN · —.
 *   · Phase-3 lifecycle policy is NOT implemented here — the closure
 *     surface only invokes the existing state PATCH endpoint.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { AlertOctagon } from "lucide-react";

import { useAuth } from "@/lib/auth";
import { getIncident, transitionIncidentState } from "@/lib/incidentsApi";
import XdrShell from "@/xdr/XdrShell";
import AnalystResponseDrawer from "@/xdr/respond/AnalystResponseDrawer";

import RecordHeader          from "./incidents/record/RecordHeader";
import LifecycleStrip        from "./incidents/record/LifecycleStrip";
import RecordTabs, { RECORD_TABS } from "./incidents/record/RecordTabs";
import ExecutiveTab          from "./incidents/record/tabs/ExecutiveTab";
import TechnicalTab          from "./incidents/record/tabs/TechnicalTab";
import EvidenceTab           from "./incidents/record/tabs/EvidenceTab";
import AutoInvestigationTab  from "./incidents/record/tabs/AutoInvestigationTab";
import MitreTab              from "./incidents/record/tabs/MitreTab";
import AttackStoryTab        from "./incidents/record/tabs/AttackStoryTab";
import AttackGraphTab        from "./incidents/record/tabs/AttackGraphTab";
import RecommendationsTab    from "./incidents/record/tabs/RecommendationsTab";
import ReportTab             from "./incidents/record/tabs/ReportTab";
import {
  RecommendationsTabV2,
  MitreTabV2,
  RecordHeaderV2,
  IncidentOverviewV2,
  isDesignV2EnabledFor,
} from "@/xdr/design";
import NotesTab              from "./incidents/record/tabs/NotesTab";
import TimelineTab           from "./incidents/record/tabs/TimelineTab";
import RelatedTab            from "./incidents/record/tabs/RelatedTab";
import ClosureTab            from "./incidents/record/tabs/ClosureTab";

import "./incidents/queue-theme.css";
import "./incidents/record/record-theme.css";


const DEFAULT_TAB = "executive";
const TAB_KEYS = new Set(RECORD_TABS.map(t => t.key));


export default function XdrIncidentDetailPage() {
  const { id }              = useParams();
  const [params, setParams] = useSearchParams();
  const { user }            = useAuth();

  const [incident, setIncident] = useState(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [drawerOpen, setDrawer] = useState(false);

  const urlTab = params.get("tab");
  const tab = TAB_KEYS.has(urlTab) ? urlTab : DEFAULT_TAB;
  const setTab = (k) => {
    const next = new URLSearchParams(params);
    if (k === DEFAULT_TAB) next.delete("tab"); else next.set("tab", k);
    setParams(next, { replace: true });
  };

  useEffect(() => {
    if (params.get("respond") === "1") setDrawer(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true); setError(null);
    try {
      const doc = await getIncident(id);
      setIncident(doc);
    } catch (e) {
      setError(e?.response?.data?.detail?.error
        || e?.response?.data?.detail
        || e?.message || "Failed to load incident.");
    } finally { setLoading(false); }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const handleTransition = async (target) => {
    const updated = await transitionIncidentState(id, target);
    setIncident(updated);
  };

  const drawerDefaults = useMemo(() => {
    const hosts = incident?.assets?.hosts || incident?.hosts || [];
    const users = incident?.assets?.users || incident?.users || [];
    return {
      hostId: hosts[0]?.host_id || hosts[0]?.id || hosts[0]?.name || "",
      userId: users[0]?.user_id || users[0]?.id || users[0]?.email || "",
    };
  }, [incident]);

  return (
    <XdrShell>
      <div className="xdr-record-l3" data-testid="xdr-record-l3">
        {loading && (
          <div className="rl-loading" data-testid="xdr-record-loading">
            LOADING INCIDENT…
          </div>
        )}
        {!loading && error && (
          <div className="rl-error" data-testid="xdr-record-error">
            <AlertOctagon size={13} style={{ verticalAlign: "-2px", marginRight: 6 }} />
            {String(error)}
          </div>
        )}
        {!loading && !error && incident && (
          <>
            {isDesignV2EnabledFor("incident-header")
              ? <RecordHeaderV2
                  incident={incident}
                  onOpenRespond={() => setDrawer(true)}
                />
              : <RecordHeader
                  incident={incident}
                  onOpenRespond={() => setDrawer(true)}
                />}
            <LifecycleStrip
              state={incident.state}
              onTransition={handleTransition}
            />
            <RecordTabs current={tab} onChange={setTab} />
            <div
              className="rl-tabpanel"
              data-testid={`xdr-record-tabpanel-${tab}`}
            >
              {tab === "executive"          && (isDesignV2EnabledFor("incident-overview")
                ? <IncidentOverviewV2 incident={incident} />
                : <ExecutiveTab       incident={incident} />)}
              {tab === "technical"          && <TechnicalTab         incident={incident} />}
              {tab === "evidence"           && <EvidenceTab          incident={incident} />}
              {tab === "auto_investigation" && <AutoInvestigationTab incident={incident} />}
              {tab === "mitre"              && (isDesignV2EnabledFor("mitre")
                ? <MitreTabV2 incident={incident} />
                : <MitreTab   incident={incident} />)}
              {tab === "attack_story"       && <AttackStoryTab       incident={incident} />}
              {tab === "attack_graph"       && <AttackGraphTab       incident={incident} />}
              {tab === "report"             && <ReportTab            incident={incident} />}
              {tab === "notes"              && <NotesTab             incident={incident} />}
              {tab === "timeline"           && <TimelineTab          incident={incident} />}
              {tab === "related"            && <RelatedTab           incident={incident} />}
              {tab === "closure"            && <ClosureTab           incident={incident}
                                                                              onUpdated={setIncident} />}
            </div>
          </>
        )}

        <AnalystResponseDrawer
          open={drawerOpen}
          onClose={() => setDrawer(false)}
          incident={incident}
          analystEmail={user?.email}
          defaultHostId={drawerDefaults.hostId}
          defaultUserId={drawerDefaults.userId}
        />
      </div>
    </XdrShell>
  );
}


/* Tiny spinner utility — kept local so the record theme can drive
   both the button and the lifecycle strip animations without
   depending on the .xdr-console keyframes. */
if (typeof document !== "undefined"
    && !document.getElementById("rl-spin-style")) {
  const s = document.createElement("style");
  s.id = "rl-spin-style";
  s.textContent = `
    @keyframes rl-spin { to { transform: rotate(360deg); } }
    .rl-spin { animation: rl-spin 0.7s linear infinite; }
  `;
  document.head.appendChild(s);
}
