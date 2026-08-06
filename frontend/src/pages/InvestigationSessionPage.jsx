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
import TrajectoryDiagram      from "@/components/investigation/TrajectoryDiagram";
import CollapsibleSection     from "@/components/investigation/CollapsibleSection"; // eslint-disable-line no-unused-vars
import InvestigationSummaryPanel from "@/components/investigation/InvestigationSummaryPanel";
import api from "@/lib/api";

const MIRROR_KEY = "nivxray:last_investigation";
const SESSION_KEY = (id) => `nivxray:session:${id}`;

const TABS = [
  { id: "narrative", label: "Investigation Summary", testid: "tab-narrative" },
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
  const [active,  setActive]  = useState("narrative");

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
        {active === "narrative" && (
          <div data-testid="session-narrative-tab">
            {session.summary_narrative
              ? <InvestigationSummaryPanel
                  narrative={session.summary_narrative}
                  onOpenSession={() => setActive("inputs")} />
              : <EmptyCard msg="No narrative synthesised yet." />}
          </div>
        )}
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
        {active === "nist"     && <NistTab     incident={inc} raw={raw} session={session} />}
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

// ── Attack Story tab — trajectory swim-lane + phases + behaviors ─
function StoryTab({ incident, raw }) {
  const behaviors = incident?.behaviors || raw?.ice?.behavior_clusters || [];
  const phases    = incident?.phases    || [];
  const preproc   = _preprocForTrajectory(raw, incident);
  const hasAny    = behaviors.length || phases.length || preproc;
  if (!hasAny) return <EmptyCard msg="No attack story derived yet." />;
  return (
    <div data-testid="session-story-tab">
      {(preproc || behaviors.length > 0) && (
        <CollapsibleSection
          title="Attack Chain · MITRE ATT&CK Projection"
          subtitle="14 lanes · one per ATT&CK tactic · empty tactics collapse · behaviors span multiple lanes"
          testid="section-attack-chain"
        >
          <TrajectoryDiagram
            preprocessor={preproc}
            behaviors={behaviors}
          />
        </CollapsibleSection>
      )}
      {phases.length > 0 && (
        <CollapsibleSection
          title="Kill-Chain Phases"
          right={`${phases.length} phase${phases.length === 1 ? "" : "s"}`}
          testid="section-kill-chain-phases"
        >
          <ol style={sx.phaseList}>
            {phases.map((p) => (
              <li key={p.tactic} style={sx.phaseItem}
                  data-testid={`story-phase-${p.tactic}`}>
                <strong style={sx.phaseLabel}>{p.label}</strong>
                <span style={sx.phaseMeta}>{p.command_count} cmds · {(p.mitre || []).join(", ")}</span>
              </li>
            ))}
          </ol>
        </CollapsibleSection>
      )}
      {behaviors.length > 0 && (
        <CollapsibleSection
          title="Behaviors"
          right={`${behaviors.length} observed`}
          testid="section-behaviors"
        >
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
        </CollapsibleSection>
      )}
    </div>
  );
}

// Build a preprocessor-shaped envelope from either the raw SSOT's
// preprocessor (paste flow) or the ICE behavior clusters (URL flow)
// so the same TrajectoryDiagram renders across every input class.
function _preprocForTrajectory(raw, incident) {
  const pre = raw?.preprocessor;
  if (pre?.stages?.length) return pre;
  const clusters = incident?.behaviors || raw?.ice?.behavior_clusters || [];
  if (!clusters.length) return null;
  const label = {
    initial_access:       "Initial Access",
    execution:            "Execution",
    persistence:          "Persistence",
    privilege_escalation: "Privilege Escalation",
    defense_evasion:      "Defense Evasion",
    credential_access:    "Credential Access",
    discovery:            "Discovery",
    lateral_movement:     "Lateral Movement",
    collection:           "Collection",
    command_and_control:  "Command and Control",
    exfiltration:         "Exfiltration",
    impact:               "Impact",
  };
  // Purpose label → { family slug, fallback tactic, mitre[] } — used
  // when the recursive DIE investigation didn't attach a MITRE
  // technique.  The slug feeds TrajectoryDiagram.FAMILY_LANE_OVERRIDE
  // and pins each node to its correct swim lane deterministically.
  // The mitre[] array ensures every node carries a MITRE ATT&CK ID
  // alongside its Cyber Kill Chain phase — the two dimensions the
  // analyst reasons about.
  const PURPOSE_MAP = {
    "Shadow copy deletion":                       { family: "shadow-copy-deletion",     tactic: "Impact",              mitre: ["T1490"] },
    "Shadow copy deletion (WMIC)":                { family: "shadow-copy-deletion",     tactic: "Impact",              mitre: ["T1490"] },
    "Software uninstall (defense evasion)":       { family: "uac-disable",              tactic: "Defense Evasion",     mitre: ["T1562.001"] },
    "MSI installation":                           { family: "msi-install",              tactic: "Execution",           mitre: ["T1218.007"] },
    "MSI installer child (embedded)":             { family: "msi-install",              tactic: "Execution",           mitre: ["T1218.007"] },
    "MSI execution":                              { family: "msi-install",              tactic: "Execution",           mitre: ["T1218.007"] },
    "Reverse SSH tunnel":                         { family: "reverse-ssh-tunnel",       tactic: "Command and Control", mitre: ["T1572"] },
    "SSH remote session":                         { family: "reverse-ssh-tunnel",       tactic: "Command and Control", mitre: ["T1021.004"] },
    "SSH client execution":                       { family: "reverse-ssh-tunnel",       tactic: "Command and Control", mitre: ["T1021.004"] },
    "Data staging / exfil (rclone-style)":        { family: "sync-rclone-style",        tactic: "Exfiltration",        mitre: ["T1567.002"] },
    "Lateral movement via PsExec":                { family: "psexec-lateral",           tactic: "Lateral Movement",    mitre: ["T1021.002"] },
    "Lateral movement via Impacket":              { family: "psexec-lateral",           tactic: "Lateral Movement",    mitre: ["T1021.002"] },
    "Account / group discovery":                  { family: "account-discovery",        tactic: "Discovery",           mitre: ["T1087"] },
    "Domain trust discovery":                     { family: "ad-discovery",             tactic: "Discovery",           mitre: ["T1482"] },
    "Current-user discovery":                     { family: "session-discovery",        tactic: "Discovery",           mitre: ["T1033"] },
    "Host discovery":                             { family: "host-discovery",           tactic: "Discovery",           mitre: ["T1082"] },
    "Active Directory discovery":                 { family: "ad-discovery",             tactic: "Discovery",           mitre: ["T1087.002"] },
    "Registry Run-key persistence":               { family: "registry-modification",    tactic: "Persistence",         mitre: ["T1547.001"] },
    "Registry modification":                      { family: "registry-modification",    tactic: "Defense Evasion",     mitre: ["T1112"] },
    "Scheduled-task persistence":                 { family: "persistence-scheduled-task", tactic: "Persistence",       mitre: ["T1053.005"] },
    "PowerShell in-memory execution":             { family: null,                       tactic: "Execution",           mitre: ["T1059.001"] },
    "PowerShell download-and-execute":            { family: null,                       tactic: "Command and Control", mitre: ["T1105"] },
    "PowerShell encoded command":                 { family: null,                       tactic: "Defense Evasion",     mitre: ["T1027"] },
    "PowerShell process enumeration":             { family: null,                       tactic: "Discovery",           mitre: ["T1057"] },
    "PowerShell execution":                       { family: null,                       tactic: "Execution",           mitre: ["T1059.001"] },
    "PowerShell execution via CMD (execution-policy bypass)": { family: null,           tactic: "Defense Evasion",     mitre: ["T1059.001"] },
    "Host / domain reconnaissance":               { family: "host-discovery",           tactic: "Discovery",           mitre: ["T1082"] },
    "Download from remote resource":              { family: null,                       tactic: "Command and Control", mitre: ["T1105"] },
    "Certutil download / decode":                 { family: null,                       tactic: "Command and Control", mitre: ["T1105"] },
    "BITSAdmin download":                         { family: null,                       tactic: "Command and Control", mitre: ["T1105"] },
    "AutoHotkey stager":                          { family: null,                       tactic: "Execution",           mitre: ["T1059"] },
    "Microsoft Edge launch (extension load — Edgecution)":         { family: null,     tactic: "Execution",           mitre: ["T1176"] },
    "Microsoft Edge launch (headless, extension load — Edgecution)": { family: null,   tactic: "Execution",           mitre: ["T1176"] },
    "Self-deletion of stager":                    { family: null,                       tactic: "Defense Evasion",     mitre: ["T1070.004"] },
    "Unzip Python interpreter stager":            { family: null,                       tactic: "Execution",           mitre: ["T1059"] },
    "Unzip encrypted payload archive":            { family: null,                       tactic: "Execution",           mitre: ["T1140"] },
    "Archive extraction":                         { family: null,                       tactic: "Execution",           mitre: ["T1140"] },
  };
  const stages = clusters.map((c, i) => {
    const meta = PURPOSE_MAP[c.label] || {};
    const tactic = label[c.primary_tactic] || meta.tactic || "Execution";
    // Merge MITRE from DIE-attached techniques with our deterministic
    // fallback so every node carries an ATT&CK ID.
    const attached = (c.mitre || []).map(m => m.id || m).filter(Boolean);
    const mitre    = attached.length ? attached : (meta.mitre || []);
    return {
      id:              `ice-stage-${i}`,
      title:           c.label,
      tactic,
      mitre,
      command_family:  meta.family || c.label,
      kind:            "behavior_cluster",
      confidence:      c.confidence === "high"   ? 0.95
                     : c.confidence === "medium" ? 0.7
                     :                              0.4,
    };
  });
  return { stages, process_edges: [] };
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

// ── Attack Lifecycle panel — walks the MITRE kill-chain and lists
// behaviors + actual commands per tactic. Same depth Talos / Mandiant
// publish in their engagement reports.
const _TACTIC_ORDER = [
  ["initial_access",       "Initial Access"],
  ["execution",            "Execution"],
  ["persistence",          "Persistence"],
  ["privilege_escalation", "Privilege Escalation"],
  ["defense_evasion",      "Defense Evasion"],
  ["credential_access",    "Credential Access"],
  ["discovery",            "Discovery"],
  ["lateral_movement",     "Lateral Movement"],
  ["collection",           "Collection"],
  ["command_and_control",  "Command and Control"],
  ["exfiltration",         "Exfiltration"],
  ["impact",               "Impact"],
];

function AttackLifecyclePanel({ incident }) {
  const behaviors = incident?.behaviors || [];
  if (!behaviors.length) return null;
  const byTactic = {};
  for (const b of behaviors) {
    const t = b.primary_tactic || "execution";
    (byTactic[t] = byTactic[t] || []).push(b);
  }
  const present = _TACTIC_ORDER.filter(([k]) => (byTactic[k] || []).length);
  if (!present.length) return null;
  return (
    <CollapsibleSection
      title="Attack Lifecycle · Cyber Kill Chain × MITRE ATT&CK"
      subtitle="Per-tactic walkthrough — behavior · MITRE ID · raw commands"
      right={`${behaviors.length} behaviors · ${present.length} tactics`}
      testid="section-nist-attack-lifecycle"
    >
      {present.map(([key, label]) => (
        <div key={key} style={{ marginBottom: 10 }}
             data-testid={`nist-lifecycle-${key}`}>
          <div style={{ fontWeight: 700, color: "#7ee6a8",
                        fontSize: 12, marginBottom: 4 }}>
            {label.toUpperCase()}
          </div>
          {(byTactic[key] || []).map((b, i) => {
            const mitre = (b.mitre || []).map(m => m.id || m).join(", ") || "—";
            return (
              <div key={i} style={{ marginBottom: 6, paddingLeft: 8 }}>
                <div style={{ fontSize: 12 }}>
                  <strong>{b.label}</strong>
                  <span style={{ color: "#94a3b8", marginLeft: 8 }}>[{mitre}]</span>
                  <span style={{ color: "#94a3b8", marginLeft: 8 }}>
                    · {b.command_count || 0} observed · {(b.confidence || "low").toUpperCase()}
                  </span>
                </div>
                {(b.commands || []).slice(0, 2).map((c, j) => (
                  <div key={j} style={{ fontFamily: "JetBrains Mono, monospace",
                                          fontSize: 10.5, color: "#c5f5d6",
                                          background: "rgba(0,40,22,0.4)",
                                          padding: "4px 8px", borderRadius: 3,
                                          marginTop: 3, wordBreak: "break-all" }}>
                    {(c.command || "").slice(0, 240)}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      ))}
    </CollapsibleSection>
  );
}

function AttackTimelinePanel({ session }) {
  const events = session?.summary_narrative?.attack_timeline
                 || session?.raw_investigation?.report_extraction?.timeline
                 || [];
  if (!events.length) return null;
  return (
    <CollapsibleSection
      title="Attack Timeline"
      subtitle="Chronological events reconstructed from the acquired source"
      right={`${events.length}`}
      testid="section-nist-attack-timeline"
    >
      <ol style={{ margin: 0, paddingLeft: 20 }}>
        {events.slice(0, 20).map((e, i) => (
          <li key={i} style={{ marginBottom: 4, fontSize: 12 }}
              data-testid={`nist-timeline-${i}`}>
            <span style={{ color: "#7ee6a8", fontWeight: 700, marginRight: 6 }}>
              {e.date || "·"}
            </span>
            <span>{e.event}</span>
          </li>
        ))}
      </ol>
    </CollapsibleSection>
  );
}

// ── NIST IR tab — reads incident directly + downloadable exports ─
function NistTab({ incident, raw, session }) {
  const md = useMemo(
    () => (incident ? _buildNistMarkdown(incident, session, raw) : ""),
    [incident, session, raw],
  );
  if (!incident) return <EmptyCard msg="No incident report available." />;
  const sum   = incident.summary || {};
  const rec   = incident.recommendations || [];
  const ready = incident.readiness || {};

  function download(name, mime, content) {
    try {
      const blob = new Blob([content], { type: mime });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { /* noop */ }
  }
  const sid = session?.session_id || "session";
  const isServerPersisted = sid && !sid.startsWith("ses_local_");
  const BACKEND = process.env.REACT_APP_BACKEND_URL || "";

  // Body-driven render: guarantees PDF/MD downloads even when the
  // session lives only in the client cache (fallback id or never-
  // persisted).  Streams the response and triggers a Save dialog.
  async function fetchAndSave(path, filename, mime) {
    try {
      const resp = await api.post(path, { session }, { responseType: "blob" });
      const blob = new Blob([resp.data],
                              { type: resp.headers?.["content-type"] || mime });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      // If body-render fails (shouldn't) and the session IS on the
      // server, fall back to the GET path.
      if (isServerPersisted) {
        window.open(
          `${BACKEND}/api/session/${sid}${path.replace("/session/render", "")}`,
          "_blank");
      }
    }
  }

  return (
    <div style={sx.card} data-testid="session-nist-tab">
      <div style={{ display: "flex", justifyContent: "space-between",
                     alignItems: "flex-start", marginBottom: 10 }}>
        <h3 style={{ ...sx.h3, margin: 0 }}>
          NIST SP 800-61 r2 · Incident Report
        </h3>
        <div style={sx.dlBtnGroup} data-testid="nist-downloads">
          <button type="button" style={sx.dlBtn}
                  data-testid="btn-download-nist-pdf"
                  onClick={() => fetchAndSave(
                    "/session/render/nist.pdf",
                    `${sid}.nist.pdf`, "application/pdf")}>
            ⤓ PDF
          </button>
          <button type="button" style={sx.dlBtn}
                  data-testid="btn-download-nist-md"
                  onClick={() => fetchAndSave(
                    "/session/render/nist.md",
                    `${sid}.nist.md`, "text/markdown")}>
            ⤓ Markdown
          </button>
          <button type="button" style={sx.dlBtn}
                  data-testid="btn-download-nist-json"
                  onClick={() => download(`${sid}.incident.json`,
                                            "application/json",
                                            JSON.stringify(incident, null, 2))}>
            ⤓ Incident JSON
          </button>
          <button type="button" style={sx.dlBtn}
                  data-testid="btn-download-session-json"
                  onClick={() => download(`${sid}.session.json`,
                                            "application/json",
                                            JSON.stringify(session, null, 2))}>
            ⤓ Session JSON
          </button>
        </div>
      </div>

      <CollapsibleSection title="Executive Decision" testid="section-executive-decision">
        <KV rows={[
          ["Actor",      sum.actor      || "—"],
          ["Severity",   sum.severity   || "—"],
          ["Confidence", sum.confidence_percent != null ? `${sum.confidence_percent}%` : "—"],
          ["Objective",  sum.objective  || "—"],
          ["Status",     sum.status     || "—"],
        ]} />
      </CollapsibleSection>

      {/* ── Attack Lifecycle (per-tactic walkthrough) ─────── */}
      <AttackLifecyclePanel incident={incident} />

      {/* ── Attack Timeline (dated events extracted from source) ─── */}
      <AttackTimelinePanel session={session} />

      <CollapsibleSection title="Investigation Readiness"
                            right={`${ready.overall_percent || 0}% · ${(ready.confidence_label || "").toUpperCase()}`}
                            testid="section-investigation-readiness">
        {ready.recommended_next ? (
          <div style={sx.next}>NEXT → {ready.recommended_next}</div>
        ) : (
          <div style={sx.dim}>All readiness gates passed.</div>
        )}
      </CollapsibleSection>

      <CollapsibleSection title="Recommendations"
                            right={`${rec.length}`}
                            testid="section-recommendations">
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
      </CollapsibleSection>

      <CollapsibleSection title="Report Preview"
                            subtitle="Markdown that will export"
                            testid="section-report-preview"
                            defaultOpen={false}>
        <pre style={{ ...sx.dim, background: "rgba(0, 40, 22, 0.4)",
                       padding: "10px 12px", borderRadius: 3,
                       maxHeight: 320, overflow: "auto",
                       whiteSpace: "pre-wrap", wordBreak: "break-word",
                       color: "#c5f5d6", fontSize: 11 }}
             data-testid="nist-preview">{md}</pre>
      </CollapsibleSection>
    </div>
  );
}


// Deterministic NIST SP 800-61 r2 Markdown builder — synthesised
// purely from the SSOT / ICE incident block.  Zero LLM.
function _buildNistMarkdown(incident, session, raw) {
  const sum   = incident.summary || {};
  const ready = incident.readiness || {};
  const rec   = incident.recommendations || [];
  const gaps  = incident.gaps || [];
  const phases    = incident.phases || [];
  const behaviors = incident.behaviors || [];
  const mitre     = incident.mitre || [];
  const timeline  = incident.timeline || [];
  const prov      = incident.provenance || {};
  const now       = new Date().toISOString();
  const lines = [];
  lines.push(`# NIST SP 800-61 r2 · Incident Report`);
  lines.push(``);
  lines.push(`- **Session**: ${session?.session_id || "n/a"}`);
  lines.push(`- **Generated**: ${now}`);
  lines.push(`- **Source**: ${prov.source_vendor || "n/a"} · ${prov.source_url || ""}`);
  lines.push(``);
  lines.push(`## 1. Executive Decision`);
  lines.push(``);
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Incident | ${sum.title || "Threat Investigation"} |`);
  lines.push(`| Actor | ${sum.actor || "unattributed"} |`);
  lines.push(`| Severity | ${sum.severity || "unknown"} |`);
  lines.push(`| Confidence | ${sum.confidence_percent ?? 0}% |`);
  lines.push(`| Objective | ${sum.objective || "under investigation"} |`);
  lines.push(`| Status | ${sum.status || "under_investigation"} |`);
  lines.push(``);
  lines.push(`## 2. Kill-Chain Phases`);
  lines.push(``);
  if (phases.length) {
    for (const p of phases) {
      lines.push(`- **${p.label}** — ${p.command_count} cmds · ${(p.mitre || []).join(", ")}`);
    }
  } else {
    lines.push(`_None observed._`);
  }
  lines.push(``);
  lines.push(`## 3. Behaviors`);
  lines.push(``);
  if (behaviors.length) {
    for (const b of behaviors) {
      lines.push(`- **${b.label}** — ${b.command_count} cmds · confidence: ${b.confidence}`);
      const ms = (b.mitre || []).map(m => m.id || m).join(", ");
      if (ms) lines.push(`  - MITRE: ${ms}`);
    }
  } else {
    lines.push(`_No behaviors correlated._`);
  }
  lines.push(``);
  lines.push(`## 4. MITRE ATT&CK Matrix (${mitre.length})`);
  lines.push(``);
  if (mitre.length) {
    lines.push(`| ID | Name | Tactic | Source |`);
    lines.push(`|----|------|--------|--------|`);
    for (const m of mitre) {
      lines.push(`| ${m.id} | ${m.name || ""} | ${m.tactic || ""} | ${m.source || ""} |`);
    }
  } else {
    lines.push(`_None mapped._`);
  }
  lines.push(``);
  lines.push(`## 5. Timeline (${timeline.length})`);
  lines.push(``);
  if (timeline.length) {
    for (const e of timeline) {
      const when = e.date || (e.step ? `step ${e.step}` : "");
      lines.push(`- [${e.kind}] ${when} — ${e.event}`);
      if (e.command) lines.push(`  \`${e.command}\``);
    }
  } else {
    lines.push(`_No timeline events._`);
  }
  lines.push(``);
  lines.push(`## 6. Investigation Readiness`);
  lines.push(``);
  lines.push(`- Overall: **${ready.overall_percent || 0}%** · ${ready.confidence_label || "n/a"}`);
  if (ready.recommended_next) lines.push(`- Next: ${ready.recommended_next}`);
  for (const b of (ready.bars || [])) {
    lines.push(`  - ${b.dim}: ${b.percent}% (${b.state})`);
  }
  lines.push(``);
  lines.push(`## 7. Gaps`);
  lines.push(``);
  if (gaps.length) {
    for (const g of gaps) lines.push(`- **${g.dim}** — ${g.reason} · _${g.action}_`);
  } else {
    lines.push(`_No gaps flagged._`);
  }
  lines.push(``);
  lines.push(`## 8. Recommendations`);
  lines.push(``);
  if (rec.length) {
    for (const r of rec) lines.push(`- **${r.priority}** — ${r.title} (${r.reason})`);
  } else {
    lines.push(`_No recommendations._`);
  }
  lines.push(``);
  lines.push(`## 9. Provenance`);
  lines.push(``);
  lines.push(`- Source URL: ${prov.source_url || "—"}`);
  lines.push(`- Source Vendor: ${prov.source_vendor || "—"}`);
  lines.push(`- Source Title: ${prov.source_title || "—"}`);
  lines.push(`- Fetched Bytes: ${prov.acquired_bytes || "—"}`);
  lines.push(`- Duration (ms): ${prov.fetched_at_ms || "—"}`);
  lines.push(``);
  lines.push(`---`);
  lines.push(`_Generated deterministically from the SSOT.  Zero LLM._`);
  return lines.join("\n");
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
  dlBtnGroup: { display: "flex", gap: 6, flexWrap: "wrap" },
  dlBtn: {
    background: "transparent", color: "#7ee6a8",
    border: "1px solid rgba(126, 230, 168, 0.35)",
    padding: "5px 10px", borderRadius: 3,
    fontFamily: "inherit", fontSize: 10, letterSpacing: 1.2,
    cursor: "pointer", textTransform: "uppercase",
  },
};
