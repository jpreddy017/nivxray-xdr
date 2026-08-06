/**
 * InvestigationSessionPage · Rule R22 (2026-03-02)
 * ────────────────────────────────────────────────
 * Dedicated deep-dive surface for a completed threat-report
 * investigation.  The Workspace is the orchestration launcher; this
 * page is the incident case file — it hosts every projection ICE
 * produces from the Canonical Investigation Object (SSOT).
 *
 * Route:   /workspace/session/:sessionId
 * Source:  GET /api/session/:sessionId  (backend-persisted)
 *          fallback → sessionStorage["nivxray:last_investigation"]
 *          (mirror-cache written by the Workspace at completion time
 *           so refresh-during-mint doesn't dead-end).
 *
 * The page reads a SESSION envelope of shape:
 *
 *   {
 *     session_id, created_at, schema,
 *     original_input:     {raw, kind, label, confidence},
 *     document_profile:   {vendor, title, …},
 *     acquired_document:  {ok, url, vendor, title, …},
 *     investigation_inputs: [{id, index, type, type_label, value,
 *                             preview, source, section, status,
 *                             investigation}, …],
 *     incident:           {…SSOT.incident…},
 *     readiness:          {…},
 *     summary:            {vendor, title, actor, severity, objective,
 *                          checks[], counts{}, input_count, investigated},
 *     raw_investigation:  {…full SSOT…}
 *   }
 *
 * Everything below is a PURE PROJECTION.  This page never re-parses
 * the SSOT nor calls the pipeline again (Rule R16 · IVE only
 * projects).  All heavy correlation lives in ICE.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Link, useParams, useNavigate } from "react-router-dom";

import ExtractedArtifactsPanel from "@/components/investigation/ExtractedArtifactsPanel";
import AcquisitionPlanPanel   from "@/components/investigation/AcquisitionPlanPanel";
import api from "@/lib/api";

const MIRROR_KEY = "nivxray:last_investigation";
const SESSION_KEY = (id) => `nivxray:session:${id}`;

const TABS = [
  { id: "summary",  label: "Document Summary",   testid: "tab-summary"  },
  { id: "inputs",   label: "Investigation Inputs", testid: "tab-inputs" },
  { id: "story",    label: "Attack Story",       testid: "tab-story"    },
  { id: "timeline", label: "Timeline",           testid: "tab-timeline" },
  { id: "graph",    label: "Incident Graph",     testid: "tab-graph"    },
  { id: "evidence", label: "Evidence Explorer",  testid: "tab-evidence" },
  { id: "nist",     label: "NIST IR Report",     testid: "tab-nist"     },
];

// ══════════════════════════════════════════════════════════════════
// Page
// ══════════════════════════════════════════════════════════════════
export default function InvestigationSessionPage() {
  const { sessionId } = useParams();
  const navigate      = useNavigate();
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [active,  setActive]  = useState("summary");

  // Load: backend first, then per-session sessionStorage cache, then
  // the legacy mirror cache written by the Workspace on completion.
  useEffect(() => {
    let alive = true;
    setLoading(true);
    (async () => {
      if (sessionId) {
        try {
          const { data } = await api.get(`/session/${sessionId}`);
          if (alive && data?.session) {
            setSession(data.session);
            try {
              sessionStorage.setItem(SESSION_KEY(sessionId),
                                       JSON.stringify(data.session));
            } catch { /* noop */ }
            setLoading(false);
            return;
          }
        } catch (e) { /* fall through to caches */ }
        try {
          const raw = sessionStorage.getItem(SESSION_KEY(sessionId));
          if (raw && alive) {
            setSession(JSON.parse(raw));
            setLoading(false);
            return;
          }
        } catch { /* noop */ }
      }
      // Last-resort: legacy mirror cache (Evidence Explorer path).
      try {
        const raw = sessionStorage.getItem(MIRROR_KEY);
        if (raw && alive) {
          const inv = JSON.parse(raw);
          setSession({
            session_id: sessionId || "mirror",
            schema: "session-v1",
            summary: {
              vendor:    inv?.document_profile?.vendor || "",
              title:     inv?.document_profile?.title  || "Investigation",
              actor:     inv?.incident?.summary?.actor,
              severity:  inv?.incident?.summary?.severity,
              objective: inv?.incident?.summary?.objective,
              checks:    [],
              counts:    {},
              input_count:  0,
              investigated: 0,
            },
            document_profile: inv?.document_profile || {},
            acquired_document: inv?.acquired_document || {},
            incident: inv?.incident || null,
            investigation_inputs: [],
            raw_investigation: inv,
          });
          setLoading(false);
          return;
        }
      } catch { /* noop */ }
      if (alive) {
        setError("No investigation found for this session.");
        setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, [sessionId]);

  if (loading) return <LoadingShell />;
  if (error || !session) return <EmptyShell msg={error} />;

  const sum      = session.summary || {};
  const acq      = session.acquired_document || {};
  const inc      = session.incident || {};
  const raw      = session.raw_investigation || {};
  const inputs   = session.investigation_inputs || [];

  return (
    <div style={sx.page} data-testid="investigation-session-page">
      <Breadcrumb sessionId={session.session_id} />
      <Header session={session} />
      <Tabs active={active} onChange={setActive} />
      <div style={sx.body}>
        {active === "summary"  && <SummaryTab  session={session} />}
        {active === "inputs"   && <InputsTab   session={session} navigate={navigate} />}
        {active === "story"    && <StoryTab    incident={inc} raw={raw} />}
        {active === "timeline" && <TimelineTab incident={inc} />}
        {active === "graph"    && <GraphTab    incident={inc} />}
        {active === "evidence" && (
          <div>
            {raw?.acquisition_plan?.length > 0 && (
              <AcquisitionPlanPanel investigation={raw} />
            )}
            {raw?.acquired_document?.ok && (
              <ExtractedArtifactsPanel investigation={raw} />
            )}
          </div>
        )}
        {active === "nist"     && <NistTab     incident={inc} raw={raw} />}
      </div>
    </div>
  );
}


// ══════════════════════════════════════════════════════════════════
// Sub-components
// ══════════════════════════════════════════════════════════════════
function Breadcrumb({ sessionId }) {
  return (
    <div style={sx.breadcrumb} data-testid="session-breadcrumb">
      <Link to="/" style={sx.crumbLink}>Workspace</Link>
      <span style={sx.crumbSep}>›</span>
      <span style={sx.crumbActive}>Investigation Session</span>
      {sessionId && sessionId !== "mirror" && (
        <span style={sx.crumbId}>· {sessionId}</span>
      )}
    </div>
  );
}

function Header({ session }) {
  const sum = session.summary || {};
  return (
    <header style={sx.header}>
      <div>
        <div style={sx.eyebrow}>▸ INVESTIGATION SESSION</div>
        <div style={sx.title}>{sum.title || "Investigation"}</div>
        <div style={sx.meta}>
          {sum.vendor  && <><strong style={sx.metaStrong}>{sum.vendor}</strong> · </>}
          {sum.actor   && <><span style={sx.actor}>{sum.actor}</span> · </>}
          {sum.severity && <SeverityChip sev={sum.severity} />}
          {sum.objective && <span style={sx.objective}>{sum.objective}</span>}
        </div>
      </div>
      <div style={sx.headerRight}>
        <div style={sx.statBlock}>
          <div style={sx.statLabel}>Investigation Inputs</div>
          <div style={sx.statValue}>{sum.input_count || 0}</div>
        </div>
        <div style={sx.statBlock}>
          <div style={sx.statLabel}>Investigated</div>
          <div style={sx.statValue}>{sum.investigated || 0}</div>
        </div>
        {session.created_at && (
          <div style={sx.statBlock}>
            <div style={sx.statLabel}>Created</div>
            <div style={sx.statValueSm}>
              {new Date(session.created_at).toLocaleString()}
            </div>
          </div>
        )}
      </div>
    </header>
  );
}

function SeverityChip({ sev }) {
  const color = sev === "critical" ? "#ff9a9a"
              : sev === "high"     ? "#ffb26b"
              : sev === "medium"   ? "#ffd66b"
              :                       "#96c9aa";
  return (
    <span style={{ ...sx.sevChip, color, borderColor: color }}
           data-testid="severity-chip">
      {sev?.toUpperCase()}
    </span>
  );
}

function Tabs({ active, onChange }) {
  return (
    <nav style={sx.tabsBar} data-testid="session-tabs">
      {TABS.map(t => (
        <button key={t.id}
                onClick={() => onChange(t.id)}
                data-testid={t.testid}
                style={{
                  ...sx.tabBtn,
                  ...(active === t.id ? sx.tabBtnActive : {}),
                }}>
          {t.label}
        </button>
      ))}
    </nav>
  );
}

// ── Summary tab ────────────────────────────────────────────────────
function SummaryTab({ session }) {
  const sum   = session.summary || {};
  const prof  = session.document_profile || {};
  const acq   = session.acquired_document || {};
  const inc   = session.incident?.summary || {};
  return (
    <div style={sx.card} data-testid="session-summary-tab">
      <h3 style={sx.h3}>Document Profile</h3>
      <KV rows={[
        ["Title",   prof.title  || acq.title  || "—"],
        ["Vendor",  prof.vendor || acq.vendor || "—"],
        ["Source",  acq.url     || acq.final_url || "—"],
        ["Fetched", acq.fetched_bytes
                       ? `${acq.fetched_bytes.toLocaleString()} bytes · ${acq.duration_ms || 0} ms`
                       : "—"],
      ]} />

      <h3 style={sx.h3}>Incident</h3>
      <KV rows={[
        ["Actor",      inc.actor      || "—"],
        ["Objective",  inc.objective  || sum.objective || "—"],
        ["Severity",   inc.severity   || "—"],
        ["Confidence", inc.confidence_percent != null
                         ? `${inc.confidence_percent}%` : "—"],
        ["Tactics",    (inc.tactics_observed || []).join(", ") || "—"],
      ]} />

      <h3 style={sx.h3}>Readiness</h3>
      <div style={sx.checks}>
        {(sum.checks || []).map((c, i) => (
          <div key={i} style={sx.check} data-testid={`summary-check-${i}`}>
            <span style={sx.checkOk}>✓</span>
            <span>{c.label}</span>
            {c.detail && <span style={sx.checkDetail}>· {c.detail}</span>}
          </div>
        ))}
        {!(sum.checks || []).length && (
          <div style={sx.dim}>No readiness signals captured yet.</div>
        )}
      </div>
    </div>
  );
}

// ── Investigation Inputs tab ──────────────────────────────────────
function InputsTab({ session, navigate }) {
  const inputs = session.investigation_inputs || [];
  if (!inputs.length) {
    return <EmptyCard msg="No Investigation Inputs promoted from this session." />;
  }
  return (
    <div style={sx.card} data-testid="session-inputs-tab">
      <h3 style={sx.h3}>Investigation Inputs ({inputs.length})</h3>
      <p style={sx.leadDim}>
        Every artifact extracted from the source document is a first-class
        investigation.  Click a row to open its full DIE analysis
        (decode · MITRE · LOLBAS · behavior · risk · verdict).
      </p>
      <ul style={sx.inputList}>
        {inputs.map((inp, i) => (
          <li key={inp.id}
              data-testid={`input-row-${i}`}
              style={sx.inputRow}
              onClick={() => navigate(`/workspace/session/${session.session_id}/input/${inp.id}`)}>
            <span style={sx.inputIdx}>#{inp.index}</span>
            <StatusPill status={inp.status} />
            <span style={sx.inputType}>{inp.type_label}</span>
            <span style={sx.inputValue}>{inp.preview || inp.value}</span>
            <span style={sx.inputArrow}>›</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function StatusPill({ status }) {
  const color = status === "investigated" ? "#3ddc84"
              : status === "correlated"   ? "#7ee6a8"
              :                              "#96c9aa";
  return (
    <span style={{ ...sx.statusPill, color, borderColor: color }}
           data-testid={`status-${status}`}>
      {status === "investigated" ? "✓" : status === "correlated" ? "◆" : "·"}
    </span>
  );
}

// ── Attack Story tab — projects incident.behaviors + phases ──────
function StoryTab({ incident, raw }) {
  const behaviors = incident?.behaviors || [];
  const phases    = incident?.phases    || [];
  if (!behaviors.length && !phases.length) {
    return <EmptyCard msg="No attack story derived yet." />;
  }
  return (
    <div style={sx.card} data-testid="session-story-tab">
      <h3 style={sx.h3}>Attack Story</h3>
      {phases.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={sx.eyebrow}>▸ KILL-CHAIN PHASES</div>
          <ol style={sx.phaseList}>
            {phases.map((p) => (
              <li key={p.tactic} style={sx.phaseItem}
                  data-testid={`story-phase-${p.tactic}`}>
                <strong style={sx.phaseLabel}>{p.label}</strong>
                <span style={sx.phaseMeta}>{p.command_count} cmds · {(p.mitre || []).join(", ")}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
      <div style={sx.eyebrow}>▸ BEHAVIORS</div>
      <ul style={sx.behaviorList}>
        {behaviors.map((b, i) => (
          <li key={i} style={sx.behaviorItem}
              data-testid={`story-behavior-${i}`}>
            <div style={sx.behaviorHead}>
              <strong>{b.label}</strong>
              <span style={sx.dim}>{b.command_count} cmds · {b.confidence?.toUpperCase()}</span>
            </div>
            {(b.mitre || []).length > 0 && (
              <div style={sx.behaviorMitre}>
                {b.mitre.map((m) => (
                  <span key={m.id} style={sx.mitrePill}>{m.id}</span>
                ))}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

// ── Timeline tab ──────────────────────────────────────────────────
function TimelineTab({ incident }) {
  const items = incident?.timeline || [];
  if (!items.length) return <EmptyCard msg="No timeline events." />;
  return (
    <div style={sx.card} data-testid="session-timeline-tab">
      <h3 style={sx.h3}>Timeline ({items.length})</h3>
      <ol style={sx.timelineList}>
        {items.map((e, i) => (
          <li key={i} style={sx.timelineItem}
              data-testid={`timeline-${i}`}>
            <span style={sx.timelineKind}>{e.kind}</span>
            {e.date && <span style={sx.timelineDate}>{e.date}</span>}
            {e.step && <span style={sx.timelineStep}>step {e.step}</span>}
            <span style={sx.timelineEvent}>{e.event}</span>
            {e.command && (
              <div style={sx.timelineCmd}>{e.command}</div>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

// ── Incident Graph tab (text projection until interactive lands) ──
function GraphTab({ incident }) {
  const g = incident?.graph || { nodes: [], edges: [] };
  if (!g.nodes?.length) return <EmptyCard msg="No incident graph." />;
  return (
    <div style={sx.card} data-testid="session-graph-tab">
      <h3 style={sx.h3}>Incident Graph</h3>
      <p style={sx.leadDim}>
        {g.nodes.length} nodes · {g.edges.length} edges.  Interactive
        canvas ships next.
      </p>
      <div style={sx.graphList}>
        {g.nodes.map((n) => (
          <div key={n.id} style={sx.graphNode}
               data-testid={`graph-node-${n.kind}`}>
            <span style={sx.graphKind}>{n.kind}</span>
            <strong>{n.label}</strong>
            {n.primary_tactic && <span style={sx.dim}>· {n.primary_tactic}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── NIST IR tab — reads incident directly ─────────────────────────
function NistTab({ incident, raw }) {
  if (!incident) return <EmptyCard msg="No incident report available." />;
  const sum   = incident.summary || {};
  const rec   = incident.recommendations || [];
  const ready = incident.readiness || {};
  return (
    <div style={sx.card} data-testid="session-nist-tab">
      <h3 style={sx.h3}>NIST SP 800-61 r2 · Incident Report</h3>

      <div style={sx.section}>
        <div style={sx.eyebrow}>▸ EXECUTIVE DECISION</div>
        <KV rows={[
          ["Actor",      sum.actor      || "—"],
          ["Severity",   sum.severity   || "—"],
          ["Confidence", sum.confidence_percent != null ? `${sum.confidence_percent}%` : "—"],
          ["Objective",  sum.objective  || "—"],
          ["Status",     sum.status     || "—"],
        ]} />
      </div>

      <div style={sx.section}>
        <div style={sx.eyebrow}>▸ INVESTIGATION READINESS</div>
        <div>{ready.overall_percent || 0}% · {(ready.confidence_label || "").toUpperCase()}</div>
        {ready.recommended_next && (
          <div style={sx.next}>NEXT → {ready.recommended_next}</div>
        )}
      </div>

      <div style={sx.section}>
        <div style={sx.eyebrow}>▸ RECOMMENDATIONS ({rec.length})</div>
        {rec.length ? (
          <ul style={sx.recList}>
            {rec.map((r, i) => (
              <li key={i} style={sx.recItem}
                  data-testid={`nist-rec-${i}`}>
                <span style={sx.prio}>{r.priority}</span>
                <div>
                  <strong>{r.title}</strong>
                  <div style={sx.dim}>{r.reason}</div>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div style={sx.dim}>No recommendations generated yet.</div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
// Utilities
// ══════════════════════════════════════════════════════════════════
function KV({ rows }) {
  return (
    <div style={sx.kvBlock}>
      {rows.map(([k, v]) => (
        <div key={k} style={sx.kvRow}>
          <span style={sx.kvKey}>{k}</span>
          <span style={sx.kvVal}>{v || "—"}</span>
        </div>
      ))}
    </div>
  );
}

function EmptyShell({ msg }) {
  return (
    <div style={sx.page} data-testid="session-empty">
      <Breadcrumb />
      <div style={{ ...sx.card, marginTop: 24 }}>
        <h3 style={sx.h3}>No investigation to explore</h3>
        <p style={sx.dim}>
          {msg || "Run an AUTO INVESTIGATE on a URL from the Workspace, then reopen the session from there."}
        </p>
        <p><Link to="/" style={sx.link}>← Back to Workspace</Link></p>
      </div>
    </div>
  );
}

function EmptyCard({ msg }) {
  return <div style={sx.card}><p style={sx.dim}>{msg}</p></div>;
}

function LoadingShell() {
  return (
    <div style={sx.page} data-testid="session-loading">
      <Breadcrumb />
      <div style={{ ...sx.card, marginTop: 24 }}>
        <p style={sx.dim}>Loading investigation session …</p>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
// Styles
// ══════════════════════════════════════════════════════════════════
const sx = {
  page: {
    background: "#001a0d", minHeight: "100vh",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    color: "#c5f5d6", padding: "18px 24px 60px",
  },
  breadcrumb: {
    fontSize: 11, color: "#7ee6a8", letterSpacing: 1.4,
    marginBottom: 12, display: "flex", alignItems: "center", gap: 8,
  },
  crumbLink:   { color: "#7ee6a8", textDecoration: "none" },
  crumbSep:    { color: "#4a8b63" },
  crumbActive: { color: "#e6ffe9" },
  crumbId:     { color: "#4a8b63", marginLeft: 4 },
  header: {
    display: "flex", justifyContent: "space-between", alignItems: "flex-end",
    padding: "8px 0 16px",
    borderBottom: "1px solid rgba(126, 230, 168, 0.2)",
  },
  eyebrow:  { fontSize: 10, letterSpacing: 2, color: "#7ee6a8", marginBottom: 4 },
  title:    { fontSize: 22, color: "#e6ffe9", marginTop: 2 },
  meta:     { fontSize: 12, color: "#96c9aa", marginTop: 6,
              display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6 },
  metaStrong: { color: "#c5f5d6" },
  actor:      { color: "#ffe0b3" },
  objective:  { color: "#c5f5d6" },
  sevChip: {
    fontSize: 10, letterSpacing: 1.4, border: "1px solid",
    padding: "2px 6px", borderRadius: 3,
  },
  headerRight: { display: "flex", gap: 22, alignItems: "flex-end" },
  statBlock:   { textAlign: "right" },
  statLabel:   { fontSize: 9, letterSpacing: 1.6, color: "#4a8b63" },
  statValue:   { fontSize: 22, color: "#e6ffe9" },
  statValueSm: { fontSize: 12, color: "#c5f5d6" },
  tabsBar: {
    display: "flex", flexWrap: "wrap", gap: 4,
    padding: "12px 0", borderBottom: "1px solid rgba(126, 230, 168, 0.1)",
  },
  tabBtn: {
    background: "transparent", border: "1px solid rgba(126, 230, 168, 0.18)",
    color: "#96c9aa", padding: "6px 12px", borderRadius: 3,
    fontFamily: "inherit", fontSize: 11, letterSpacing: 1.2,
    cursor: "pointer", textTransform: "uppercase",
  },
  tabBtnActive: {
    background: "rgba(126, 230, 168, 0.12)",
    borderColor: "#7ee6a8", color: "#e6ffe9",
  },
  body: { paddingTop: 18 },
  card: {
    padding: "16px 20px",
    border: "1px solid rgba(126, 230, 168, 0.18)",
    background: "rgba(0, 30, 15, 0.4)", borderRadius: 4,
    marginBottom: 16,
  },
  h3: { fontSize: 13, color: "#e6ffe9", letterSpacing: 1.4,
        margin: "0 0 12px", textTransform: "uppercase" },
  leadDim: { fontSize: 11, color: "#96c9aa", marginBottom: 12 },
  section: { marginBottom: 14 },
  kvBlock: { display: "grid", gridTemplateColumns: "180px 1fr", gap: "6px 12px",
             fontSize: 12, marginBottom: 12 },
  kvKey: { color: "#7ee6a8", letterSpacing: 1 },
  kvVal: { color: "#e6ffe9", wordBreak: "break-all" },
  checks:      { display: "flex", flexDirection: "column", gap: 4, fontSize: 12 },
  check:       { display: "flex", gap: 8, color: "#e6ffe9" },
  checkOk:     { color: "#3ddc84" },
  checkDetail: { color: "#7ee6a8", opacity: 0.7 },
  dim: { color: "#96c9aa", fontSize: 11 },
  link: { color: "#7ee6a8", textDecoration: "underline" },
  inputList: { listStyle: "none", padding: 0, margin: 0,
                display: "flex", flexDirection: "column", gap: 4 },
  inputRow: {
    display: "grid",
    gridTemplateColumns: "36px 22px 130px 1fr 20px",
    gap: 12, alignItems: "center",
    padding: "8px 10px", border: "1px solid rgba(126, 230, 168, 0.14)",
    borderRadius: 3, cursor: "pointer",
    background: "rgba(0, 40, 22, 0.28)",
  },
  inputIdx:   { color: "#4a8b63", fontSize: 11 },
  inputType:  { color: "#7ee6a8", fontSize: 11, letterSpacing: 1 },
  inputValue: { color: "#e6ffe9", fontSize: 12,
                overflow: "hidden", textOverflow: "ellipsis",
                whiteSpace: "nowrap" },
  inputArrow: { color: "#7ee6a8", textAlign: "right" },
  statusPill: {
    display: "inline-block", textAlign: "center", width: 20,
    border: "1px solid", borderRadius: 3, fontSize: 11,
  },
  phaseList: { listStyle: "none", padding: 0, margin: 0,
                display: "flex", flexDirection: "column", gap: 4 },
  phaseItem: { display: "flex", justifyContent: "space-between",
                padding: "6px 8px",
                border: "1px solid rgba(126, 230, 168, 0.16)",
                borderRadius: 3, background: "rgba(0, 40, 22, 0.28)" },
  phaseLabel: { color: "#e6ffe9", fontSize: 12 },
  phaseMeta:  { color: "#7ee6a8", fontSize: 11 },
  behaviorList: { listStyle: "none", padding: 0, margin: 0,
                   display: "flex", flexDirection: "column", gap: 6 },
  behaviorItem: { padding: "8px 10px",
                   border: "1px solid rgba(126, 230, 168, 0.14)",
                   borderRadius: 3, background: "rgba(0, 40, 22, 0.24)" },
  behaviorHead: { display: "flex", justifyContent: "space-between",
                   fontSize: 12, color: "#e6ffe9" },
  behaviorMitre: { marginTop: 6, display: "flex", gap: 4, flexWrap: "wrap" },
  mitrePill: { fontSize: 10, padding: "1px 6px",
                border: "1px solid rgba(126, 230, 168, 0.3)",
                borderRadius: 2, color: "#c5f5d6" },
  timelineList: { listStyle: "none", padding: 0, margin: 0,
                   display: "flex", flexDirection: "column", gap: 4 },
  timelineItem: { padding: "6px 10px",
                   border: "1px solid rgba(126, 230, 168, 0.14)",
                   borderRadius: 3, background: "rgba(0, 40, 22, 0.22)",
                   display: "grid",
                   gridTemplateColumns: "80px 120px 60px 1fr",
                   gap: 8, alignItems: "center", fontSize: 11 },
  timelineKind: { color: "#7ee6a8", textTransform: "uppercase", letterSpacing: 1 },
  timelineDate: { color: "#ffe0b3" },
  timelineStep: { color: "#96c9aa" },
  timelineEvent: { color: "#e6ffe9" },
  timelineCmd: { gridColumn: "1 / -1", color: "#c5f5d6", fontSize: 11,
                  marginTop: 4, wordBreak: "break-all" },
  graphList: { display: "flex", flexWrap: "wrap", gap: 8 },
  graphNode: { padding: "4px 8px",
                border: "1px solid rgba(126, 230, 168, 0.24)",
                background: "rgba(0, 40, 22, 0.28)",
                fontSize: 11, color: "#e6ffe9",
                display: "flex", gap: 6 },
  graphKind: { color: "#7ee6a8", textTransform: "uppercase", letterSpacing: 1 },
  next: { marginTop: 6, padding: "4px 8px",
           background: "rgba(60, 40, 10, 0.4)", border: "1px solid #ffe0b3",
           color: "#ffe0b3", fontSize: 11, borderRadius: 3 },
  recList: { listStyle: "none", padding: 0, margin: 0,
              display: "flex", flexDirection: "column", gap: 6 },
  recItem: { display: "grid", gridTemplateColumns: "40px 1fr", gap: 10,
              padding: "6px 8px",
              border: "1px solid rgba(126, 230, 168, 0.16)",
              borderRadius: 3, background: "rgba(0, 40, 22, 0.28)",
              fontSize: 12, color: "#e6ffe9" },
  prio: { fontSize: 10, letterSpacing: 1,
          border: "1px solid #ffd66b", color: "#ffd66b",
          borderRadius: 2, padding: "1px 4px", textAlign: "center",
          alignSelf: "start" },
};
