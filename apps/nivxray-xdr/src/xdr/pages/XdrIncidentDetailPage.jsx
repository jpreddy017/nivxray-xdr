/**
 * XdrIncidentDetailPage · `/xdr/incidents/:id`
 *
 * The single canonical Incident detail page.  Wraps the enriched
 * incident shell in the XDR chrome and reuses existing NivXRay
 * capabilities via deep-linked new tabs — never duplicates them.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { AlertOctagon, ChevronLeft, ExternalLink, Lock, Loader2, Zap } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import LifecycleBar from "@/components/incidents/LifecycleBar";
import ActivityTab  from "@/components/incidents/tabs/ActivityTab";
import Pivot       from "@/xdr/components/Pivot";
import DomainCardsGrid from "@/xdr/components/DomainCardsGrid";
import AnalystResponseDrawer from "@/xdr/respond/AnalystResponseDrawer";
import EvidenceFirstInvestigationWorkspace
  from "@/xdr/investigation/EvidenceFirstInvestigationWorkspace";
import { XdrVerdictPanel, XdrInvestigationReportPanel }
  from "@/xdr/adopt/consumerPanels";
import { XdrDieChainPanel, XdrIeddeStagePanel,
  XdrIueTimelinePanel, XdrUaieCatalogPanel,
  XdrUilClassifierPanel }
  from "@/xdr/adopt/enginePanels";
import XdrRecommendationsPanel from "@/xdr/intel/XdrRecommendationsPanel";
import XdrCompletenessPanel   from "@/xdr/investigation/XdrCompletenessPanel";
import ProcessTreePanel       from "@/xdr/investigation/ProcessTreePanel";
import AttackChainPanel       from "@/xdr/investigation/AttackChainPanel";
import { WorkspaceSelectionProvider }
  from "@/xdr/investigation/WorkspaceSelectionContext";

import { getIncident, getIncidentSummary, transitionIncidentState } from "@/lib/incidentsApi";
import { useAuth } from "@/lib/auth";
import api from "@/lib/api";

const SEV_CLASS = {
  malicious:  "sev-critical",
  suspicious: "sev-medium",
  benign:     "sev-low",
  unknown:    "sev-info",
};
const SEV_LABEL = {
  malicious: "Malicious", suspicious: "Suspicious",
  benign: "Benign",       unknown:    "Unknown",
};

const TOP_TABS = [
  { key: "overview",      label: "Overview" },
  { key: "investigation", label: "Investigation" },
  { key: "activity",      label: "Activity" },
  { key: "response",      label: "Response" },
];

const SUBTABS = [
  { key: "evidence",       label: "Evidence" },
  { key: "timeline",       label: "Timeline" },
  { key: "attack_story",   label: "Attack Story" },
  { key: "evidence_graph", label: "Evidence Graph" },
  { key: "attck",          label: "ATT&CK" },
  { key: "verdict",        label: "Verdict" },
  { key: "report",         label: "Report" },
];

export default function XdrIncidentDetailPage() {
  const { id } = useParams();
  const [searchParams] = useSearchParams();
  const { user } = useAuth();
  const [incident, setIncident] = useState(null);
  const [loading, setL]         = useState(true);
  const [error, setError]       = useState(null);
  const [tab, setTab]           = useState(
    searchParams.get("tab") || "overview");
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Open the analyst response drawer if the URL asks for it — used by
  // pivot menu "Run response action…" and any other deep-link entry
  // point that wants to jump straight to the drawer.
  useEffect(() => {
    if (searchParams.get("respond") === "1") setDrawerOpen(true);
    const t = searchParams.get("tab");
    if (t && t !== tab) setTab(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const load = useCallback(async () => {
    if (!id) return;
    setL(true); setError(null);
    try { setIncident(await getIncident(id)); }
    catch (e) { setError(e?.response?.data?.detail || e?.message || "Failed to load incident."); }
    finally  { setL(false); }
  }, [id]);
  useEffect(() => { load(); }, [load]);

  const handleTransition = async (target) => {
    const updated = await transitionIncidentState(id, target);
    setIncident(updated);
  };

  // Prefill host / user from incident assets when opening the drawer.
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
      <div style={{ marginBottom: 10, display: "flex", alignItems: "center" }}>
        <Link to="/xdr/incidents" style={{
          display: "inline-flex", alignItems: "center", gap: 6,
          color: "var(--muted)", textDecoration: "none",
          fontSize: 10.5, letterSpacing: ".4px",
          textTransform: "uppercase", fontWeight: 700,
        }}>
          <ChevronLeft size={12} /> Back to queue
        </Link>
        <span style={{ flex: 1 }} />
        <button className="btn primary" onClick={() => setDrawerOpen(true)}
                  disabled={!incident}
                  data-testid="xdr-incident-respond-btn"
                  style={{ padding: "5px 12px" }}>
          <Zap size={11} /> Respond
        </button>
      </div>

      {loading && (
        <div className="x-empty" data-testid="xdr-incident-loading">LOADING INCIDENT…</div>
      )}
      {!loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }} data-testid="xdr-incident-error">
          <AlertOctagon size={14} style={{ verticalAlign: "middle", marginRight: 6 }} />
          {String(error)}
        </div>
      )}
      {!loading && !error && incident && (
        <div data-testid="xdr-incident-detail">
          <StatusRibbon incident={incident} />
          <IncidentHeader incident={incident} />
          <LifecycleBar
            state={incident.state}
            onTransition={handleTransition}
          />
          <TopTabs tab={tab} onChange={setTab} />
          <div className="tabpanel" data-testid={`xdr-incident-tab-${tab}`}>
            {tab === "overview"      && <OverviewTab      incident={incident} />}
            {tab === "investigation" && <InvestigationTab incident={incident} />}
            {tab === "activity"      && <ActivityTab      incident={incident} />}
            {tab === "response"      && <ResponseTab      incident={incident}
                                                                  onOpenDrawer={() => setDrawerOpen(true)} />}
          </div>
        </div>
      )}
      <AnalystResponseDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        incident={incident}
        analystEmail={user?.email}
        defaultHostId={drawerDefaults.hostId}
        defaultUserId={drawerDefaults.userId}
      />
    </XdrShell>
  );
}

/* ── Status Ribbon ────────────────────────────────────────────── */
function StatusRibbon({ incident }) {
  const chips = incident.status_chips || [];
  if (chips.length === 0) return null;
  return (
    <div className="status-ribbon" data-testid="xdr-incident-status-ribbon">
      {chips.map((c, i) => (
        <span
          key={`${c.label}-${i}`}
          className={`rib tone-${c.tone || "cyan"}`}
          data-testid={`xdr-incident-ribbon-chip-${(c.label || 'chip').toLowerCase()}`}
        >
          <span className="k">{c.label}</span>
          <span className="v">{c.value}</span>
        </span>
      ))}
    </div>
  );
}

/* ── Header ───────────────────────────────────────────────────── */
function IncidentHeader({ incident }) {
  const sevCls = SEV_CLASS[incident.severity] || "sev-info";
  const prioCls = (incident.priority?.code || "P5").toLowerCase();
  return (
    <section className="inc-header" data-testid="xdr-incident-header">
      <div className="inc-top">
        <div className="grow">
          <div className="inc-id" data-testid="xdr-incident-number">
            {incident.number}
            <span className="sep">·</span>
            First seen {fmtDate(incident.created_at)}
            <span className="sep">·</span>
            Last activity {fmtDate(incident.updated_at)}
          </div>
          <h1 className="inc-title" data-testid="xdr-incident-title">
            {incident.name || "(unnamed incident)"}
          </h1>
          <div className="inc-badges">
            <span className={`badge ${sevCls}`} data-testid="xdr-incident-severity">
              {SEV_LABEL[incident.severity] || incident.severity}
            </span>
            <span className={`prio ${prioCls}`} data-testid="xdr-incident-priority">
              {incident.priority?.code} · {incident.priority?.label}
            </span>
            <span className={`status-pill state-${incident.state}`}>
              {(incident.state || "new").replace("_", " ")}
            </span>
          </div>
          <div className="inc-meta">
            {(incident.header_meta || []).map((m, i) => (
              <div key={`${m.k}-${i}`} className="m">
                <span className="k">{m.k}</span>
                <span className="v">{m.v}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="hdr-actions">
          <button className="btn" disabled title="Reassignment console — later slice">REASSIGN</button>
          <button className="btn" disabled title="Notes / Attachments — later slice">ADD NOTE</button>
          <button className="btn" disabled title="Report writer — later slice">GENERATE REPORT</button>
        </div>
      </div>
    </section>
  );
}

/* ── Tabs ─────────────────────────────────────────────────────── */
function TopTabs({ tab, onChange }) {
  return (
    <nav className="tabbar" role="tablist" data-testid="xdr-incident-top-tabs">
      {TOP_TABS.map((t) => (
        <button
          key={t.key}
          type="button"
          role="tab"
          className={`tabbtn ${tab === t.key ? "active" : ""}`}
          aria-selected={tab === t.key}
          onClick={() => onChange(t.key)}
          data-testid={`xdr-incident-tabbtn-${t.key}`}
        >
          {t.label}
        </button>
      ))}
    </nav>
  );
}

/* ── Overview ─────────────────────────────────────────────────── */
function OverviewTab({ incident }) {
  const v = incident.verdict_summary;
  const prog = incident.attack_progression || [];

  // Derive per-domain evidence counts from the incident's SSOT
  // pointers when available.  Never fabricate — a missing pointer
  // maps to zero and the domain card renders SEARCHED honestly.
  const evidenceCounts = React.useMemo(() => {
    const out = {};
    for (const p of (incident.evidence_pointers || [])) {
      const map = { edr: "endpoints", endpoint: "endpoints",
                     identity: "identity", itdr: "identity",
                     file: "files", files: "files",
                     network: "network", ndr: "network",
                     email: "email", cloud: "cloud" };
      const k = map[p.domain] || p.domain;
      const n = Array.isArray(p.bullets) ? p.bullets.length : 0;
      out[k] = (out[k] || 0) + n;
    }
    return out;
  }, [incident]);

  return (
    <div>
      {v ? (
        <>
          <div className="section-title" style={{ marginBottom: 6 }}>Verdict</div>
          <div className="verdict-grid" data-testid="xdr-incident-verdict-grid">
            <VerdictCard tone="crit" lbl="VERDICT"    val={v.verdict} />
            <VerdictCard tone="info" lbl="SCORE"      val={v.score != null ? `${v.score} / 100` : "—"} />
            <VerdictCard tone="high" lbl="CONFIDENCE" val={v.confidence || "—"} />
            <VerdictCard tone="na reason" lbl="REASON" val={v.reason} />
          </div>
        </>
      ) : (
        <div className="x-empty" style={{ marginBottom: 14 }}>
          Stage-2 verdict has not been computed for this incident yet.
        </div>
      )}

      {prog.length > 0 && (
        <>
          <div className="section-title" style={{ marginBottom: 6 }}>Attack Progression</div>
          <div className="progression" data-testid="xdr-incident-attack-progression">
            {prog.map((s, i) => (
              <React.Fragment key={s.index}>
                <div className={`stage ${s.hit ? "hit" : ""}`}>
                  <div className="dot">{s.index}</div>
                  <div className="lbl">{s.label}</div>
                </div>
                {i < prog.length - 1 && <span className="stage-arrow" />}
              </React.Fragment>
            ))}
          </div>
        </>
      )}

      {/* Slice 7 · Incident Evidence Across Domains grid — every
          domain card carries an honest state and navigates to the
          native XDR domain-detail route (never the base UI). */}
      <DomainCardsGrid incident={incident}
                          evidenceCounts={evidenceCounts} />

      {/* Deterministic Summary body — Verdict / Observed Facts /
          Suspicious Elements (Slice 3 table) / Evidence Gaps /
          Recommended Next Evidence.  Lives natively under Overview
          (Slice 7 IA fix — used to be a duplicate "Summary" sub-tab
          on the Investigation lens; that sub-tab is now removed). */}
      <div style={{ marginTop: 14 }}>
        <SummarySubtabBody incident={incident} />
      </div>
    </div>
  );
}

function VerdictCard({ tone, lbl, val }) {
  return (
    <div className={`verdict-card ${tone}`}>
      <div className="lbl">{lbl}</div>
      <div className="val">{val ?? "—"}</div>
    </div>
  );
}

/* ── Investigation Workspace (Evidence-First canvas + subtabs) ─ */
function InvestigationTab({ incident }) {
  const [sub, setSub] = useState(SUBTABS[0].key);
  const caps = buildCaps(incident);
  const cap  = caps[sub];
  return (
    <WorkspaceSelectionProvider incident={incident}>
    <div>
      <EvidenceFirstInvestigationWorkspace incident={incident} />

      {/* ATT&CK Chain — ordered tactic → technique projection from
             the same canonical evidence.  OBSERVED / SEQUENCED /
             CORRELATED / INFERRED relationship badges preserve the
             invariant: ATT&CK mapping ≠ verdict. */}
      <AttackChainPanel incident={incident} />

      {/* Process Tree — canonical process evidence from incident +
             optional /api/edr/process-tree enrichment.  Badges are
             OBSERVED / DETECTED / CORRELATED / SUSPICIOUS.  Process
             behavior is NEVER a verdict. */}
      <ProcessTreePanel incident={incident} />

      {/* Investigation Completeness — deterministic gap checker */}
      <XdrCompletenessPanel incident={incident} />

      {/* Authoritative Verdict Stage-2 (consumed from base) */}
      <XdrVerdictPanel incident={incident} />
      {/* Recommended Next Steps — deterministic, evidence-driven,
             composed from base recommender + rules + IOC + verdict +
             playbook state.  Recalculates on evidence change. */}
      <XdrRecommendationsPanel incident={incident} />
      {/* Authoritative Investigation Report (consumed from base) */}
      <XdrInvestigationReportPanel incident={incident} />

      {/* P1 Engine Adoption Wave — consume NivXRay's authoritative
             engines (DIE / IEDDE / IUE / UAIE) inline.  Never
             re-implement, never fabricate.  See docs/
             NIVXRAY_XDR_TECHNOLOGY_ADOPTION_MATRIX.md § 1. */}
      <XdrDieChainPanel incident={incident} />
      <XdrIeddeStagePanel incident={incident} />
      <XdrIueTimelinePanel incident={incident} />
      <XdrUaieCatalogPanel />
      <XdrUilClassifierPanel incident={incident} />

      {/* Legacy deep-link subtabs preserved below the workspace so
             every capability the previous view surfaced still lands
             in a single click.  The canvas replaces decorative
             "reserved" cards with a real evidence-backed graph.  */}
      <div style={{ marginTop: 18, borderTop: "1px solid var(--border)",
                        paddingTop: 12 }}>
        <div className="section-title" style={{ marginBottom: 6 }}>
          Related capabilities
        </div>
        <div className="subnav" role="tablist" data-testid="xdr-incident-subnav">
          {SUBTABS.map((s) => (
            <button
              key={s.key}
              type="button"
              role="tab"
              className={`subtabbtn ${sub === s.key ? "active" : ""}`}
              aria-selected={sub === s.key}
              onClick={() => setSub(s.key)}
              data-testid={`xdr-incident-subtab-${s.key}`}
            >
              {s.label}
            </button>
          ))}
        </div>
        <SubtabBody sub={sub} cap={cap} />
      </div>
    </div>
    </WorkspaceSelectionProvider>
  );
}

/** Summary sub-tab — deterministic, evidence-backed, four states.
 *  Sourced from GET /api/incidents/:id/summary. */
function SummarySubtabBody({ incident }) {
  const [state, setState] = useState({ loading: true, err: null, data: null });
  useEffect(() => {
    if (!incident?.id) return;
    let cancelled = false;
    (async () => {
      setState({ loading: true, err: null, data: null });
      try {
        const data = await getIncidentSummary(incident.id);
        if (!cancelled) setState({ loading: false, err: null, data });
      } catch (e) {
        if (!cancelled) setState({
          loading: false,
          err: e?.response?.data?.detail || e?.message || "Failed to load summary.",
          data: null,
        });
      }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  if (state.loading) return (
    <div className="x-empty" data-testid="xdr-incident-summary-loading">
      <Loader2 size={13} className="spin" style={{ verticalAlign: "middle", marginRight: 6 }} />
      Loading summary …
    </div>
  );
  if (state.err) return (
    <div className="x-empty" style={{ color: "#ff9494" }}
         data-testid="xdr-incident-summary-error">
      {String(state.err)}
    </div>
  );
  const s = state.data;
  const stateBadge = (st) => {
    const map = {
      ok:                   { label: "OK",                    color: "var(--mint)"  },
      no_matching_evidence: { label: "NO MATCHING EVIDENCE",   color: "var(--yellow)" },
      not_connected:        { label: "NOT CONNECTED",          color: "var(--faint)" },
      not_available:        { label: "NOT AVAILABLE",          color: "var(--muted)" },
      error:                { label: "ERROR",                  color: "#ff9494"      },
    };
    const m = map[st] || map.not_available;
    return (
      <span style={{
        display: "inline-block", padding: "2px 7px", borderRadius: 3,
        border: `1px solid ${m.color}`, color: m.color,
        fontFamily: "var(--xmono)", fontSize: 9.5, letterSpacing: ".4px",
        fontWeight: 800, textTransform: "uppercase",
      }}>{m.label}</span>
    );
  };

  return (
    <div data-testid="xdr-incident-summary-body">
      <Block title="Deterministic Verdict"
             testid="xdr-summary-verdict">
        {s.deterministic_verdict ? (
          <div className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>
            <b style={{ color: "var(--text)" }}>{(s.deterministic_verdict.label || "").toUpperCase()}</b>
            {" · "}risk {s.deterministic_verdict.risk_score ?? "—"}
            {" · "}confidence {s.deterministic_verdict.confidence ?? "—"}
            {" · "}{s.deterministic_verdict.contributing_signals} contributing signal(s)
            <div style={{ marginTop: 4, fontSize: 10.5, color: "var(--faint)" }}>
              Engine: {s.deterministic_verdict.engine}
            </div>
          </div>
        ) : stateBadge("not_available")}
      </Block>

      <Block title="Observed Facts" testid="xdr-summary-observed">
        {(s.observed_facts || []).length === 0
          ? stateBadge("no_matching_evidence")
          : <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, lineHeight: 1.6 }}>
              {s.observed_facts.map((f, i) => (
                <li key={i} style={{ color: "var(--text-dim)" }}>
                  {f.fact}
                  <span className="mono" style={{ marginLeft: 6, color: "var(--faint)", fontSize: 10 }}>
                    · {f.provenance}
                  </span>
                </li>
              ))}
            </ul>}
      </Block>

      <Block title="Suspicious Elements" testid="xdr-summary-suspicious">
        {(s.suspicious_elements || []).length === 0
          ? stateBadge("no_matching_evidence")
          : <table className="x-table" style={{ width: "100%" }}
                    data-testid="xdr-summary-suspicious-table">
              <thead>
                <tr>
                  <th style={{ width: "24%" }}>Rule</th>
                  <th style={{ width: "10%" }}>Weight</th>
                  <th style={{ width: "34%" }}>Detected By</th>
                  <th>Provenance</th>
                </tr>
              </thead>
              <tbody>
                {s.suspicious_elements.map((r, i) => {
                  const key = `${r.rule_id || "rule"}-${i}`;
                  const engine = r.detected_by || null;
                  const pivotCtx = {
                    incident_id: incident?.id,
                    rule_id:     r.rule_id,
                  };
                  return (
                    <tr key={key}
                          data-testid={`xdr-summary-suspicious-row-${i}`}>
                      <td>
                        <Pivot
                          kind="rule"
                          value={r.rule_id}
                          ctx={pivotCtx}
                          testid={`xdr-summary-suspicious-rule-${i}`}
                        />
                      </td>
                      <td className="mono" style={{
                          color: (r.weight || 0) >= 20 ? "var(--amber)" : "var(--text-dim)"
                        }}
                        data-testid={`xdr-summary-suspicious-weight-${i}`}>
                        {r.weight != null ? `+${r.weight}` : "—"}
                      </td>
                      <td data-testid={`xdr-summary-suspicious-detected-by-${i}`}>
                        {engine
                          ? <Pivot
                              kind="engine"
                              value={engine}
                              ctx={pivotCtx}
                              testid={`xdr-summary-suspicious-engine-${i}`}
                            />
                          : stateBadge("not_available")}
                      </td>
                      <td className="mono" style={{
                          color: "var(--faint)", fontSize: 10.5,
                        }}
                        data-testid={`xdr-summary-suspicious-provenance-${i}`}>
                        {r.provenance || stateBadge("not_available")}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>}
      </Block>

      <Block title="Evidence Gaps · Negative Explainability"
             testid="xdr-summary-gaps">
        <table className="x-table" style={{ width: "100%" }}>
          <thead><tr>
            <th>Claim</th><th>State</th><th>Searched</th><th>Reason</th>
          </tr></thead>
          <tbody>
            {(s.evidence_gaps || []).map((g, i) => (
              <tr key={i} data-testid={`xdr-summary-gap-${g.state}-${i}`}>
                <td style={{ color: "var(--text)", fontWeight: 600 }}>{g.claim}</td>
                <td>{stateBadge(g.state)}</td>
                <td className="mono" style={{ color: "var(--muted)" }}>
                  {(g.searched || []).join(", ") || "—"}
                </td>
                <td className="mono" style={{ color: "var(--text-dim)" }}>{g.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Block>

      <Block title="Recommended Next Evidence"
             testid="xdr-summary-recommended">
        {(s.recommended_next || []).length === 0
          ? stateBadge("no_matching_evidence")
          : <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, lineHeight: 1.7 }}>
              {s.recommended_next.map((r, i) => (
                <li key={i}>
                  <a href={r.target} target="_blank" rel="noopener noreferrer"
                     style={{ color: "var(--purple)", fontWeight: 700, textDecoration: "underline" }}>
                    {r.action} <ExternalLink size={10} style={{ verticalAlign: "middle" }} />
                  </a>
                </li>
              ))}
            </ul>}
      </Block>
    </div>
  );
}

function Block({ title, testid, children }) {
  return (
    <div className="panel2" style={{
      padding: "12px 14px", marginBottom: 10,
    }} data-testid={testid}>
      <div className="section-title" style={{ marginBottom: 8 }}>{title}</div>
      {children}
    </div>
  );
}

function buildCaps(incident) {
  const id = incident?.id || "";
  const enc = encodeURIComponent(id);
  return {
    evidence: id ? { title: "Structured Evidence (existing Analyst Workspace)",
        body: "Structured Evidence lives inside the existing Analyst Workspace where the case was decoded.",
        link: `/history?case=${enc}`, external: true } : null,
    timeline: id ? { title: "Attack Story Timeline (existing IUE projection)",
        body: "Reuses the IUE timeline projection surfaced today inside the Analyst Workspace Story lens.",
        link: `/analyst?case=${enc}&tab=story`, external: true } : null,
    attack_story: id ? { title: "Attack Story lens (existing)",
        body: "The Attack Story lens already lives inside the Analyst Workspace — we deep-link, we do not duplicate.",
        link: `/analyst?case=${enc}&tab=story`, external: true } : null,
    evidence_graph: id ? { title: "Investigation Relationship Graph (v2 IRG)",
        body: "Reuses the existing IRG workspace — the same graph implementation used across NivXRay v2.",
        link: `/v2/irg/${enc}`, external: true } : null,
    attck: { title: "MITRE ATT&CK Heatmap (existing)",
        body: "Uses the existing global MITRE heatmap. Per-incident filtering will land in a later slice.",
        link: "/heatmap", external: true },
    verdict: id ? { title: "Stage-2 Deterministic Verdict",
        body: incident.verdict_stage2
          ? `Current Stage-2 label: ${incident.verdict_stage2.label} · confidence ${incident.verdict_stage2.confidence_bucket} · risk ${incident.verdict_stage2.risk_score}. Full explainability lives in the EDR Verdict Card.`
          : "Stage-2 has not been computed for this incident yet.",
        link: "/edr/trajectory", external: true } : null,
    report: { title: "Incident Report", reserved: "later slice",
        body: "Deterministic report generation for the canonical Incident is scheduled for a later slice." },
  };
}

function SubtabBody({ sub, cap }) {
  if (!cap) {
    return <div className="x-empty" data-testid={`xdr-incident-subbody-${sub}`}>
      No data attached to this incident yet.
    </div>;
  }
  const isReserved = !!cap.reserved;
  const openTab = () => {
    if (isReserved || !cap.link) return;
    window.open(cap.link, "_blank", "noopener,noreferrer");
  };
  return (
    <div className="x-reserved" data-testid={`xdr-incident-subbody-${sub}`}>
      <div className="lock">
        {isReserved ? <Lock size={11} /> : <ExternalLink size={11} />}
        {isReserved ? `Reserved · ${cap.reserved}` : "Reuses existing capability"}
      </div>
      <div className="title">{cap.title}</div>
      <div className="body">{cap.body}</div>
      {!isReserved && cap.link && (
        <button
          type="button"
          className="btn primary"
          style={{ alignSelf: "flex-start", marginTop: 4 }}
          onClick={openTab}
          data-testid={`xdr-incident-sublaunch-${sub}`}
        >
          Open in new tab <ExternalLink size={11} />
        </button>
      )}
    </div>
  );
}

/* ── Response tab (approval flow + IOC actions, stubbed safely) ── */
const RESPONSE_STAGES = [
  "Pending Approval", "Approved", "Queued", "Executing",
  "Succeeded / Failed", "Verified",
];
const IOC_ACTIONS = [
  { key: "block-hash",   label: "Block Hash",   iocKey: "hash" },
  { key: "block-ip",     label: "Block IP",     iocKey: "ip" },
  { key: "block-domain", label: "Block Domain", iocKey: "domain" },
  { key: "block-url",    label: "Block URL",    iocKey: "url" },
];

function ResponseTab({ incident, onOpenDrawer }) {
  const iocs = incident?.iocs || {};
  return (
    <div>
      <div className="section-title" style={{ marginBottom: 6, display: "flex",
                                                        alignItems: "center", gap: 12 }}>
        <span>Response Workflow</span>
        <button className="btn primary"
                  onClick={onOpenDrawer}
                  data-testid="xdr-incident-response-open-drawer"
                  style={{ padding: "3px 10px", fontSize: 10.5 }}>
          Open Analyst Response Drawer
        </button>
      </div>
      <div className="progression" data-testid="xdr-incident-response-workflow">
        {RESPONSE_STAGES.map((label, i) => (
          <React.Fragment key={label}>
            <div className="stage">
              <div className="dot">{i + 1}</div>
              <div className="lbl">{label}</div>
            </div>
            {i < RESPONSE_STAGES.length - 1 && <span className="stage-arrow" />}
          </React.Fragment>
        ))}
      </div>

      <div className="section-title" style={{ marginTop: 12, marginBottom: 6 }}>IOC Response Actions</div>
      <div style={{ color: "var(--muted)", fontSize: 11, marginBottom: 10 }}>
        Every destructive action clears Approval → Execution → Evidence Forwarding.  Buttons
        below deep-link into the Analyst Response Drawer with the target pre-filled.
      </div>
      <div className="row" data-testid="xdr-incident-ioc-actions">
        {IOC_ACTIONS.map((a) => {
          const count = Array.isArray(iocs[a.iocKey]) ? iocs[a.iocKey].length : 0;
          return (
            <button
              key={a.key}
              className="btn"
              disabled
              title={count > 0 ? `${count} ${a.iocKey} indicator${count === 1 ? "" : "s"} — approval workflow lands in Slice 3` : "No IOCs of this type on the incident"}
              data-testid={`xdr-incident-ioc-${a.key}`}
            >
              {a.label} · {count}
            </button>
          );
        })}
      </div>

      <div className="x-reserved" style={{ marginTop: 16 }}>
        <div className="lock"><Lock size={11} /> Reserved · later slice</div>
        <div className="title">Approval / Execution / Verification / Audit</div>
        <div className="body">
          The full response task workflow — including approver assignment, queued execution,
          verification, and immutable audit — arrives in Slice 3.  Every action creates an
          immutable Activity record on the canonical incident.
        </div>
      </div>
    </div>
  );
}

/* ── Utils ────────────────────────────────────────────────────── */
function fmtDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, 16) + "Z"; }
  catch { return iso; }
}
