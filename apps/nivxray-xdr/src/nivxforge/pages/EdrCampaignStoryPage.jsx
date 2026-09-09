/**
 * NivXForge EDR · Campaign Story (P0-F.7).
 *
 * One intrusion, told once, from the authoritative records. This page has
 * no model of its own: every value comes from `/api/edr/campaign-story`,
 * which is a read projection over workspace_cases (incident + campaign +
 * IUE/ICE/VEEE), edr_raw_events, the canonical evidence plane and
 * edr_response_commands.
 *
 * The two things it must never do: imply an event happened because a
 * neighbouring one did, and present a response request as a result. So
 * every step carries its provenance chain, every absence is named with
 * its epistemic state, and the response block renders the backend's own
 * proof verdict.
 */
import React, { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AlertTriangle, ChevronDown, ChevronRight, GitBranch, Loader2,
         Radar, ShieldAlert, ShieldCheck } from "lucide-react";

import NivXForgeConsole, { useIncidentContext } from
  "@/nivxforge/NivXForgeConsole";
import api from "@/lib/api";

const STATE_COLOR = {
  OBSERVED: "#5FD4A0", NOT_OBSERVED: "#FFB454", NOT_COLLECTED: "#FFB454",
  NOT_SUPPORTED: "#8A93A0", PARSER_FAILED: "#FF8A8A", UNKNOWN: "#FFB454",
  OK: "#5FD4A0",
};

const Tag = ({ children, color, testid }) => (
  <span className="mono" data-testid={testid}
        style={{ fontSize: 9, padding: "1px 6px", borderRadius: 2,
                 border: `1px solid ${color || "#2A3540"}`,
                 color: color || "var(--text-dim)" }}>
    {children}
  </span>
);

const Row = ({ label, value, testid }) => (
  <div style={{ minWidth: 190, maxWidth: 560 }} data-testid={testid}>
    <div style={{ color: "var(--faint)", fontSize: 8.5, fontWeight: 800,
                  textTransform: "uppercase", letterSpacing: ".4px" }}>
      {label}
    </div>
    <div className="mono" style={{ fontSize: 10, marginTop: 2,
                                   wordBreak: "break-all",
                                   color: value ? "var(--text)"
                                                : "var(--faint)" }}>
      {value || "◇ not reported"}
    </div>
  </div>
);

function Activity({ a, i }) {
  const [open, setOpen] = useState(false);
  const p = a.process || {};
  return (
    <div data-testid={`story-activity-${i}`}
         style={{ borderBottom: "1px solid #141C24" }}>
      <div onClick={() => setOpen((o) => !o)}
           data-testid={`story-activity-toggle-${i}`}
           style={{ display: "flex", gap: 10, alignItems: "center",
                    padding: "7px 4px", cursor: "pointer",
                    flexWrap: "wrap" }}>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <span className="mono" style={{ fontSize: 10,
                                        color: "var(--cyan)" }}>
          {(a.at || "").slice(11, 19)}
        </span>
        <Tag color={a.verdict === "MALICIOUS" ? "#FF8A8A" : "#FFB454"}
             testid={`story-activity-verdict-${i}`}>
          {a.verdict} {a.score}
        </Tag>
        <span className="mono" style={{ fontSize: 10, color: "var(--text)",
                                        maxWidth: 620,
                                        overflow: "hidden",
                                        textOverflow: "ellipsis",
                                        whiteSpace: "nowrap" }}>
          {p.command_line || p.image_path || p.name || "no observed image"}
        </span>
        <span className="mono" style={{ fontSize: 9.5,
                                        color: "var(--text-dim)" }}>
          pid {p.pid} · {a.evidence_states?.parent_process === "OBSERVED"
            ? `parent ${p.parent_name}`
            : `parent ${a.evidence_states?.parent_process}`}
        </span>
        {(a.rule_ids || []).map((r) => (
          <Tag key={r} color="#7FB3FF"
               testid={`story-activity-rule-${r}-${i}`}>{r}</Tag>
        ))}
      </div>
      {open && (
        <div style={{ padding: "2px 4px 14px 26px", background: "#080C10" }}
             data-testid={`story-activity-detail-${i}`}>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap",
                        marginTop: 8 }}>
            <Row label="Image path" value={p.image_path} />
            <Row label="User" value={p.user} />
            <Row label="Started" value={p.start_time} />
            <Row label="Start ticks (identity)"
                 value={p.start_ticks ?? ""} />
            <Row label="Parent lookup" value={p.parent_lookup_state} />
          </div>
          <div style={{ marginTop: 12, fontSize: 8.5, fontWeight: 800,
                        letterSpacing: ".5px", textTransform: "uppercase",
                        color: "var(--cyan)" }}>
            Provenance chain
          </div>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap",
                        marginTop: 6 }}
               data-testid={`story-provenance-${i}`}>
            <Row label="raw_event_id" value={a.provenance?.raw_event_id} />
            <Row label="trust" value={a.provenance?.trust_state} />
            <Row label="authenticated endpoint"
                 value={a.provenance?.authenticated_endpoint} />
            <Row label="canonical_event_id (incident)"
                 value={a.provenance?.canonical_event_id} />
            <Row label="canonical_event_id (evidence plane)"
                 value={a.provenance?.canonical_event_id_in_evidence_plane} />
            <Row label="resolved via"
                 value={a.provenance?.process_identity_resolved_via} />
            <Row label="process_iid" value={a.provenance?.process_iid} />
            <Row label="parent_iid" value={a.provenance?.parent_iid} />
            <Row label="canonical kind"
                 value={a.provenance?.canonical_kind} />
            <Row label="derivations"
                 value={(a.provenance?.derivation_outcomes || []).join(" → ")} />
          </div>
          <div style={{ marginTop: 12, fontSize: 8.5, fontWeight: 800,
                        letterSpacing: ".5px", textTransform: "uppercase",
                        color: "var(--cyan)" }}>
            What is known, and what is not
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap",
                        marginTop: 6 }}
               data-testid={`story-evidence-states-${i}`}>
            {Object.entries(a.evidence_states || {}).map(([k, v]) => (
              <Tag key={k} color={STATE_COLOR[v]}
                   testid={`story-state-${k}-${i}`}>
                {k.replace(/_/g, " ")}: {v}
              </Tag>
            ))}
          </div>
          {a.epistemic_state && (
            <div style={{ marginTop: 8, fontSize: 9.5, color: "var(--faint)",
                          lineHeight: 1.6, maxWidth: 900 }}
                 data-testid={`story-epistemic-${i}`}>
              Evidence plane declares · not observed:{" "}
              {(a.epistemic_state.not_observed || []).join(", ") || "—"} ·
              not supported:{" "}
              {(a.epistemic_state.not_supported || []).join(", ") || "—"}.{" "}
              {a.epistemic_state.note}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Response({ r }) {
  const ok = r.proof?.success_claimed;
  return (
    <div data-testid={`story-response-${r.command_id}`}
         style={{ padding: "8px 4px", borderBottom: "1px solid #141C24" }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center",
                    flexWrap: "wrap" }}>
        {ok ? <ShieldCheck size={12} color="#5FD4A0" />
            : <AlertTriangle size={12} color="#FFB454" />}
        <span className="mono" style={{ fontSize: 10.5,
                                        color: "var(--text)" }}>
          {r.action}
        </span>
        <Tag color={ok ? "#5FD4A0" : "#FFB454"}
             testid={`story-response-proof-${r.command_id}`}>
          {r.proof?.proof}
        </Tag>
        <span className="mono" style={{ fontSize: 9.5,
                                        color: "var(--text-dim)" }}>
          {r.requested_by} · {(r.requested_at || "").slice(11, 19)}
          {r.target?.pid ? ` · pid ${r.target.pid}` : ""}
        </span>
      </div>
      <div style={{ marginTop: 5, marginLeft: 22, fontSize: 9.5,
                    color: "var(--faint)", lineHeight: 1.6,
                    maxWidth: 940 }}>
        {(r.history || []).map((h) => h.state).join(" → ")}
        {r.verification?.finding && (
          <div style={{ marginTop: 4, color: "var(--text-dim)" }}
               data-testid={`story-response-finding-${r.command_id}`}>
            Verification · {r.verification.method}: {r.verification.finding}
          </div>
        )}
        {!r.verification && (
          <div style={{ marginTop: 4 }}>
            ⊘ no post-action evidence — nothing about the effect is proven
          </div>
        )}
        <div style={{ marginTop: 4, color: "#8C7A5A" }}
             data-testid={`story-response-link-${r.command_id}`}>
          Link · {r.link_basis} ({r.link_strength})
        </div>
      </div>
    </div>
  );
}

const Section = ({ title, sub, children, testid }) => (
  <section style={{ marginTop: 22 }} data-testid={testid}>
    <div style={{ fontSize: 9, fontWeight: 800, letterSpacing: ".7px",
                  textTransform: "uppercase", color: "var(--cyan)",
                  borderBottom: "1px solid #17202A", paddingBottom: 5 }}>
      {title}
    </div>
    {sub && (
      <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6,
                    lineHeight: 1.6, maxWidth: 940 }}>{sub}</div>
    )}
    <div style={{ marginTop: 8 }}>{children}</div>
  </section>
);

export default function EdrCampaignStoryPage() {
  const ctx = useIncidentContext();
  const [params] = useSearchParams();
  const incidentId = params.get("incident_id") || ctx.incident_id;
  const [state, setState] = useState({ loading: false, err: null, s: null });

  useEffect(() => {
    if (!incidentId) return;
    setState({ loading: true, err: null, s: null });
    api.get("/edr/campaign-story", { params: { incident_id: incidentId } })
      .then(({ data }) => setState({ loading: false, err: null, s: data }))
      .catch((e) => setState({
        loading: false, s: null,
        err: e?.response?.data?.detail?.reason || e?.message || String(e) }));
  }, [incidentId]);

  const s = state.s;
  return (
    <NivXForgeConsole activeTab="campaign-story">
      <h1 className="page-h1" data-testid="story-heading">Campaign Story</h1>
      <div className="page-sub">
        One intrusion, told once, from the authoritative records — endpoint →
        process activity → detection → evidence → verdict → incident →
        response → verified response. A projection, not a second source of
        truth: nothing here is inferred from the existence of something
        else.
      </div>

      {!incidentId && (
        <div className="x-empty" data-testid="story-noctx">
          Campaign Story is scoped to an incident. Open it from an
          incident, or add <b>?incident_id=…</b>
        </div>
      )}
      {state.loading && (
        <div className="x-empty" data-testid="story-loading">
          <Loader2 size={13} className="spin"
                   style={{ verticalAlign: "middle", marginRight: 6 }} />
          Reading the authoritative records …
        </div>
      )}
      {state.err && (
        <div className="x-empty" style={{ color: "#ff9494" }}
             data-testid="story-error">{String(state.err)}</div>
      )}

      {s && (
        <>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap",
                        marginTop: 14 }} data-testid="story-header">
            <Row label="Incident"
                 value={`${s.incident.incident_number} · ${s.incident.state}`
                        + ` · ${s.incident.priority}`}
                 testid="story-incident" />
            <Row label="Verdict"
                 value={`${s.incident.campaign.max_label} `
                        + `${s.incident.campaign.max_score}`}
                 testid="story-verdict" />
            <Row label="Endpoint"
                 value={`${s.endpoint.hostname || ""} · `
                        + `${s.incident.campaign.endpoint_id}`}
                 testid="story-endpoint" />
            <Row label="Behaviours consolidated"
                 value={`${s.incident.campaign.detection_count} in a `
                        + `${s.incident.campaign.window_minutes}-min window`}
                 testid="story-detection-count" />
            <Row label="Rules that fired"
                 value={(s.incident.campaign.rule_ids || []).join(", ")}
                 testid="story-rules" />
          </div>

          <Section title="What happened" testid="story-narrative"
                   sub="Written only from fields that exist in the records.">
            <ol style={{ margin: 0, paddingLeft: 18, fontSize: 11,
                         lineHeight: 1.85, color: "var(--text-dim)" }}>
              {(s.narrative || []).map((l, i) => (
                <li key={i} data-testid={`story-narrative-${i}`}>{l}</li>
              ))}
            </ol>
          </Section>

          <Section title={`Process activity · ${s.activities.length} observed`}
                   testid="story-activities"
                   sub="Each behaviour expands to its full provenance chain: raw event → canonical evidence → process identity → rule → detection outcome.">
            {s.activities.map((a, i) => (
              <Activity key={i} a={a} i={i} />
            ))}
          </Section>

          <Section title="Why it was judged this way"
                   testid="story-reasoning"
                   sub="The existing IUE / ICE / VEEE record — no second verdict engine.">
            <div style={{ display: "flex", gap: 18, flexWrap: "wrap" }}>
              <Row label="IUE" value={s.reasoning.iue_id}
                   testid="story-iue" />
              <Row label="ICE correlation" value={s.reasoning.ice_state}
                   testid="story-ice" />
              <Row label="VEEE label"
                   value={`${s.reasoning.veee?.label || ""} `
                          + `${s.reasoning.veee?.score ?? ""}`}
                   testid="story-veee" />
              <Row label="Engine" value={s.reasoning.engines?.detection} />
              <Row label="Reason" value={s.reasoning.veee?.reason} />
            </div>
            <div style={{ marginTop: 10, display: "flex", gap: 8,
                          flexWrap: "wrap" }}
                 data-testid="story-veee-contributors">
              {(s.reasoning.veee?.contributors || []).map((c, i) => (
                <Tag key={i} color="#7FB3FF">
                  {c.source} +{c.weight} · {c.detail}
                </Tag>
              ))}
            </div>
          </Section>

          <Section title={`Response and independent verification · `
                          + `${s.responses.length}`}
                   testid="story-responses"
                   sub="The same authoritative response records the Response Verification console renders. A request is not an outcome, and a sensor's own report is not proof.">
            {s.responses.length === 0 ? (
              <div className="x-empty" data-testid="story-no-response">
                ◇ NO RESPONSE ACTION on this endpoint inside the campaign
                window. That is an absence of action, not an absence of
                risk.
              </div>
            ) : s.responses.map((r) => (
              <Response key={r.command_id} r={r} />
            ))}
          </Section>

          <Section title={`Evidence gaps · ${s.gaps.length}`}
                   testid="story-gaps"
                   sub="What this story cannot tell you, and why. A gap is a limit of collection, never evidence that nothing happened.">
              {s.gaps.map((g, i) => (
                <div key={i} data-testid={`story-gap-${i}`}
                     style={{ display: "flex", gap: 10, padding: "4px 0",
                              alignItems: "baseline", flexWrap: "wrap" }}>
                  <Tag color={STATE_COLOR[g.state]}>{g.state}</Tag>
                  <span className="mono" style={{ fontSize: 10,
                                                  color: "var(--text)" }}>
                    {g.gap}
                  </span>
                  <span style={{ fontSize: 10, color: "var(--faint)",
                                 maxWidth: 820, lineHeight: 1.6 }}>
                    {g.reason}
                  </span>
                </div>
              ))}
          </Section>

          <Section title="Pivots" testid="story-pivots">
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap",
                          fontSize: 10.5 }}>
              <Link to={s.pivots.process_tree} data-testid="story-pivot-tree"
                    style={{ color: "var(--cyan)" }}>
                <GitBranch size={11} style={{ verticalAlign: -1,
                                              marginRight: 4 }} />
                Process Tree
              </Link>
              <Link to={`/edr/trajectory?device=`
                        + `${s.incident.campaign.endpoint_id}`}
                    data-testid="story-pivot-trajectory"
                    style={{ color: "var(--cyan)" }}>
                <Radar size={11} style={{ verticalAlign: -1,
                                          marginRight: 4 }} />
                Device Trajectory
              </Link>
              <Link to={`/edr/detections?endpoint_id=`
                        + `${s.incident.campaign.endpoint_id}`}
                    data-testid="story-pivot-detections"
                    style={{ color: "var(--cyan)" }}>
                <ShieldAlert size={11} style={{ verticalAlign: -1,
                                                marginRight: 4 }} />
                Detections
              </Link>
              <Link to={s.pivots.incident} data-testid="story-pivot-incident"
                    style={{ color: "var(--cyan)" }}>Incident</Link>
              <Link to={s.pivots.response_verification}
                    data-testid="story-pivot-response"
                    style={{ color: "var(--cyan)" }}>
                <ShieldCheck size={11} style={{ verticalAlign: -1,
                                                marginRight: 4 }} />
                Response Verification
              </Link>
            </div>
            <div style={{ marginTop: 10, fontSize: 9.5,
                          color: "var(--faint)", maxWidth: 940,
                          lineHeight: 1.6 }}
                 data-testid="story-sources">
              Sources: {(s.sources || []).join(" · ")} — read by{" "}
              {s.engine_id}. {s.honesty_note}
            </div>
          </Section>
        </>
      )}
    </NivXForgeConsole>
  );
}
