/**
 * XdrIncidentDetailPage · `/xdr/incidents/:id`
 *
 * The single canonical Incident detail page.  Wraps the enriched
 * incident shell in the XDR chrome and reuses existing NivXRay
 * capabilities via deep-linked new tabs — never duplicates them.
 */
import React, { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AlertOctagon, ChevronLeft, ExternalLink, Lock, Loader2 } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import LifecycleBar from "@/components/incidents/LifecycleBar";
import ActivityTab  from "@/components/incidents/tabs/ActivityTab";

import { getIncident, getIncidentSummary, transitionIncidentState } from "@/lib/incidentsApi";
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
  { key: "summary",        label: "Summary" },
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
  const [incident, setIncident] = useState(null);
  const [loading, setL]         = useState(true);
  const [error, setError]       = useState(null);
  const [tab, setTab]           = useState("overview");

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

  return (
    <XdrShell>
      <div style={{ marginBottom: 10 }}>
        <Link to="/xdr/incidents" style={{
          display: "inline-flex", alignItems: "center", gap: 6,
          color: "var(--muted)", textDecoration: "none",
          fontSize: 10.5, letterSpacing: ".4px",
          textTransform: "uppercase", fontWeight: 700,
        }}>
          <ChevronLeft size={12} /> Back to queue
        </Link>
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
            {tab === "response"      && <ResponseTab      incident={incident} />}
          </div>
        </div>
      )}
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

      <div className="section-title" style={{ marginBottom: 6 }}>
        Incident Evidence Across Domains
      </div>
      <div style={{ color: "var(--muted)", fontSize: 11, marginBottom: 10 }}>
        Each card opens the complete telemetry surface in a new browser tab.
        Unconnected domains are surfaced honestly — no fake placeholders.
      </div>
      <div className="edom-grid" data-testid="xdr-incident-edom-grid">
        {(incident.evidence_pointers || []).map((p) => (
          <DomainCard key={p.domain} pointer={p} />
        ))}
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

function DomainCard({ pointer }) {
  const stateCls = {
    available:            "related",
    no_matching_evidence: "searched",
    not_connected:        "notconnected",
    not_available:        "notconnected",
  }[pointer.status] || "notconnected";
  const isAvail = pointer.status === "available" && !!pointer.deep_link;

  // The `deep_link` returned by the base backend is a RELATIVE path
  // (e.g. `/edr?incident_id=…`).  Because this app is served from a
  // different origin (nivxray-xdr.vercel.app), we must rewrite it to
  // land on the EXISTING NivXRay host and, for the EDR domain, deep
  // link directly into the Device Trajectory telemetry canvas rather
  // than the intermediate NivXForge Console overview.
  const resolveLaunchUrl = () => {
    if (!pointer.deep_link) return null;
    const BASE = (process.env.REACT_APP_BACKEND_URL || "").replace(/\/+$/, "");
    let path = pointer.deep_link;
    if (pointer.domain === "edr" && path.startsWith("/edr")) {
      // /edr?…  →  /edr/trajectory?…   (existing NivXRay canvas)
      path = path.replace(/^\/edr(?=$|[/?])/, "/edr/trajectory");
    }
    // If the backend ever returns an absolute URL, honor it as-is.
    if (/^https?:\/\//i.test(path)) return path;
    // Otherwise anchor the relative path onto the base NivXRay origin
    // so the tab always leaves the standalone XDR app.
    return BASE ? `${BASE}${path}` : path;
  };

  const openTab = () => {
    if (!isAvail) return;
    const url = resolveLaunchUrl();
    if (url) window.open(url, "_blank", "noopener,noreferrer");
  };

  const countLabel = pointer.bullets?.length
    ? pointer.bullets.length
    : (isAvail ? "→" : (pointer.status === "no_matching_evidence" ? "0" : "—"));

  const buttonLabel = ({
    available:            `Open ${pointer.label} →`,
    no_matching_evidence: "No matching evidence",
    not_connected:        "Not connected",
    not_available:        "Not available",
  })[pointer.status] || "Not available";

  return (
    <div
      className={`edom-card ${stateCls}`}
      data-testid={`xdr-incident-edom-card-${pointer.domain}`}
    >
      <div className="edom-top">
        <span className="edom-name">{pointer.label}</span>
        <span className="edom-count">{countLabel}</span>
      </div>
      {pointer.bullets?.length > 0 && (
        <ul className="edom-bullets">
          {pointer.bullets.map((b, i) => <li key={i}>{b}</li>)}
        </ul>
      )}
      {pointer.why && (
        <div className={`edom-why ${isAvail ? "" : "muted"}`}>
          <b>Why it matters:</b> {pointer.why}
        </div>
      )}
      {!pointer.why && pointer.reason && (
        <div className="edom-why muted">{pointer.reason}</div>
      )}
      <button
        type="button"
        className="edom-open"
        disabled={!isAvail}
        onClick={openTab}
        data-testid={`xdr-incident-edom-launch-${pointer.domain}`}
      >
        {buttonLabel}
      </button>
    </div>
  );
}

/* ── Investigation (7 sub-tabs, all reuse existing capabilities) ─ */
function InvestigationTab({ incident }) {
  const [sub, setSub] = useState(SUBTABS[0].key);
  const caps = buildCaps(incident);
  const cap  = caps[sub];
  return (
    <div>
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
      {sub === "summary"
        ? <SummarySubtabBody incident={incident} />
        : <SubtabBody sub={sub} cap={cap} />}
    </div>
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
          : <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, lineHeight: 1.6 }}>
              {s.suspicious_elements.map((r, i) => (
                <li key={i} style={{ color: "var(--text-dim)" }}>
                  <span className="mono" style={{ color: "var(--amber)" }}>{r.rule_id}</span>
                  {r.weight != null && <span className="mono" style={{ color: "var(--faint)" }}> · +{r.weight}</span>}
                  <span className="mono" style={{ marginLeft: 6, color: "var(--mint)", fontSize: 10 }}>
                    · detected_by: {r.detected_by}
                  </span>
                </li>
              ))}
            </ul>}
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

function ResponseTab({ incident }) {
  const iocs = incident?.iocs || {};
  return (
    <div>
      <div className="section-title" style={{ marginBottom: 6 }}>Response Workflow</div>
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
        No destructive action executes on one click.  Every action must clear Approval → Execution →
        Verification.  In this slice the buttons record intent only; execution lands in Slice 3.
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
