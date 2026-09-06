/**
 * EndpointDetailsDrawer · the persistent right-side endpoint context panel.
 *
 * Opened by `Show details` on the endpoint header and kept open while the
 * analyst works the Device Trajectory. It is context, NOT an investigation
 * surface and NOT an action menu.
 *
 * Honest state: every row states what is actually known. A field with no
 * telemetry behind it renders `◇ NO EVIDENCE`; a field that would require
 * a capability this platform has not registered renders
 * `⊘ CAPABILITY UNAVAILABLE` with the reason. Nothing is inferred to fill
 * a gap and nothing is simulated.
 */
import React, { useState } from "react";
import { ChevronDown, ChevronRight, X } from "lucide-react";

function Field({ k, v, title }) {
  return (
    <div style={{ marginBottom: 7 }} title={title}>
      <div style={{ color: "var(--faint)", fontSize: 9, fontWeight: 800,
                    textTransform: "uppercase", letterSpacing: ".4px" }}>{k}</div>
      <div className="mono" style={{ color: "var(--text-dim)", fontSize: 10.5,
                                     marginTop: 2, wordBreak: "break-all" }}>{v}</div>
    </div>
  );
}

const Nope = ({ label, ep = "no_evidence" }) => (
  <span className="nx-ep" data-ep={ep} data-known="true"
        style={{ whiteSpace: "normal", wordBreak: "break-word",
                 lineHeight: 1.5, display: "inline-block", maxWidth: "100%" }}>
    {label}
  </span>
);

function Section({ id, title, badge, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ borderTop: "1px solid #212B36", paddingTop: 9, marginTop: 9 }}>
      <button className="btn ghost"
              onClick={() => setOpen((o) => !o)}
              aria-expanded={open}
              style={{ width: "100%", justifyContent: "space-between",
                       padding: "2px 0", marginBottom: open ? 8 : 0 }}
              data-testid={`endpoint-drawer-section-${id}`}>
        <span className="section-title" style={{ margin: 0 }}>{title}</span>
        <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {badge}
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </span>
      </button>
      {open ? children : null}
    </div>
  );
}

export const EndpointDetailsDrawer = ({
  hostname, deviceRef, identity, authoritative,
  observedUsers = [], observedProviders = [], onClose,
}) => {
  const health = identity?.health || null;
  const life = health?.agent_lifecycle;
  const tele = health?.telemetry_health;
  const vis = health?.visibility;
  const NO_AGENT = life?.state === "NO_AGENT";
  return (
  <aside className="panel"
         style={{ padding: 11, alignSelf: "start", position: "sticky", top: 8,
                  maxHeight: "calc(100vh - 90px)", overflowY: "auto" }}
         aria-label={`Endpoint details for ${hostname || deviceRef}`}
         data-testid="endpoint-details-drawer">
    <div style={{ display: "flex", alignItems: "flex-start", gap: 8,
                  marginBottom: 4 }}>
      <div className="mono" style={{ fontSize: 12, fontWeight: 800,
                                     color: "var(--text)", wordBreak: "break-all",
                                     flex: 1, lineHeight: 1.4 }}
           data-testid="endpoint-drawer-title">
        {hostname || deviceRef}
      </div>
      <button className="btn ghost" onClick={onClose} aria-label="Hide details"
              style={{ padding: "2px 5px" }}
              data-testid="endpoint-drawer-close">
        <X size={12} />
      </button>
    </div>

    <Section id="identity" title="Endpoint Identity">
      <Field k="Hostname"
             v={identity?.hostname
                 ? <>{identity.hostname}{" "}
                     <span className="nx-ep" data-ep="unknown" data-known="false"
                           title="The device identity is authoritative; this hostname STRING is carried on the observation record and is not independently attested.">
                       OBSERVATION-DERIVED
                     </span></>
                 : <Nope label="◇ NO HOSTNAME OBSERVED" />} />
      <Field k="Device IID (authoritative)"
             v={identity?.device_iid || <Nope label="◇ NO IID BOUND" />} />
      <Field k="Identity confidence"
             v={<span className="nx-ep"
                      data-ep={authoritative ? "evidence_present" : "unknown"}
                      data-known="true">
                  {authoritative ? "◆ AUTHORITATIVE" : "◇ INFERRED"}
                </span>} />
      <Field k="Observations" v={`${identity?.observation_count ?? 0} persisted`} />
      <Field k="First observed" v={identity?.observed_first_seen || "◇"} />
      <Field k="Last observed" v={identity?.observed_last_seen || "◇"} />
      <Field k="Users observed"
             v={observedUsers.length ? observedUsers.join(", ")
                                     : <Nope label="◇ NONE RECORDED" />} />
      <Field k="Telemetry providers"
             v={observedProviders.length ? observedProviders.join(", ")
                                         : <Nope label="◇ NONE RECORDED" />} />
    </Section>

    <Section id="health" title="Health"
             badge={tele ? (
               <span className="nx-ep"
                     data-ep={tele.state === "ONLINE" ? "evidence_present"
                                                       : "unknown"}
                     data-known="true" style={{ fontSize: 8.5 }}>
                 {tele.state}
               </span>) : null}>
      {/* Two INDEPENDENT dimensions. Never collapsed into one status:
          a CONNECTED agent can be NO_TELEMETRY, and that is precisely
          the case a single field would hide. */}
      <Field k="Agent link (lifecycle)"
             v={life
                 ? <>{life.state}
                     <div style={{ color: "var(--faint)", fontSize: 9.5,
                                   marginTop: 2 }}>{life.reason}</div></>
                 : <Nope label="? NOT RESOLVED" ep="unknown" />}
             title="Operational state of the agent link." />
      <Field k="Telemetry health (evidence)"
             v={tele
                 ? <>{tele.state}
                     <div style={{ color: "var(--faint)", fontSize: 9.5,
                                   marginTop: 2 }}>{tele.reason}</div></>
                 : <Nope label="? NOT RESOLVED" ep="unknown" />}
             title="What we actually know about this endpoint's evidence." />
      <Field k="Evidence sufficiency"
             v={tele?.evidence_sufficiency || "?"} />
      <Field k="Parser failures / dropped"
             v={`${tele?.parser_failures ?? 0} / ${tele?.dropped_events ?? 0}`} />
      {vis ? (
        <div className="nx-ep"
             data-ep={vis.state === "FULL" ? "evidence_present"
                                            : "capability_unavailable"}
             data-known="true"
             style={{ display: "block", whiteSpace: "normal",
                      wordBreak: "break-word", lineHeight: 1.5,
                      marginTop: 4 }}
             data-testid="endpoint-drawer-visibility">
          VISIBILITY {vis.state}
        </div>
      ) : null}
      {vis?.statement ? (
        <div style={{ fontSize: 9.5, color: "var(--faint)", lineHeight: 1.6,
                      marginTop: 5 }}>
          {vis.statement}
        </div>
      ) : null}
      {tele?.note ? (
        <div style={{ fontSize: 9.5, color: "#E8B931", lineHeight: 1.6,
                      marginTop: 5 }}
             data-testid="endpoint-drawer-health-note">
          {tele.note}
        </div>
      ) : null}
    </Section>

    <Section id="sensor" title="Sensor &amp; Platform"
             badge={<span className="nx-ep" data-ep="capability_unavailable"
                          data-known="true" style={{ fontSize: 8.5 }}>
                      {NO_AGENT ? "⊘ NO AGENT" : life?.state || "⊘"}
                    </span>}>
      <Field k="Operating system"
             v={<Nope label="◇ NOT REPORTED — NO SENSOR ENROLMENT" />} />
      <Field k="Connector version"
             v={<Nope label="⊘ NO CONNECTOR ENROLLED" ep="capability_unavailable" />} />
      <Field k="Install date"
             v={<Nope label="⊘ NO CONNECTOR ENROLLED" ep="capability_unavailable" />} />
      <Field k="Internal / external IP"
             v={<Nope label="◇ NOT OBSERVED IN THIS SUBSTRATE" />} />
      <Field k="Policy / group"
             v={<Nope label="⊘ NO POLICY PLANE BOUND" ep="capability_unavailable" />} />
      <Field k="Host firewall"
             v={<Nope label="⊘ NO POLICY PLANE BOUND" ep="capability_unavailable" />} />
      <Field k="Connector health"
             v={life
                 ? <>{life.state}
                     <div style={{ color: "var(--faint)", fontSize: 9.5,
                                   marginTop: 2 }}>{life.reason}</div></>
                 : <Nope label="⊘ NO HEARTBEAT — TELEMETRY IS HISTORIC ONLY"
                          ep="capability_unavailable" />} />
      <Field k="Live query"
             v={<Nope label="⊘ NO LIVE-QUERY DRIVER REGISTERED"
                      ep="capability_unavailable" />} />
      <div style={{ fontSize: 9.5, color: "var(--faint)", lineHeight: 1.6 }}>
        These fields require an enrolled endpoint sensor. Until then they are
        declared unavailable rather than estimated.
      </div>
    </Section>

    <Section id="isolation" title="Isolation">
      <div className="nx-ep" data-ep="capability_unavailable" data-known="true"
           style={{ display: "block", whiteSpace: "normal",
                    wordBreak: "break-word", lineHeight: 1.5 }}
           data-testid="endpoint-drawer-isolation-state">
        ⊘ ISOLATION STATE UNKNOWN — RESPONSE DRIVER NOT REGISTERED
      </div>
      <div style={{ fontSize: 9.5, color: "var(--faint)", lineHeight: 1.6,
                    marginTop: 5 }}>
        Not reported as isolated and not reported as connected. With no
        response driver bound, the state is genuinely unknown — it is not
        defaulted to &ldquo;Not isolated&rdquo;.
      </div>
    </Section>

    <Section id="antivirus" title="Antivirus" defaultOpen={false}>
      <Field k="Engine" v={<Nope label="⊘ NO AV PLANE BOUND"
                                  ep="capability_unavailable" />} />
      <Field k="Definitions version"
             v={<Nope label="⊘ NO AV PLANE BOUND" ep="capability_unavailable" />} />
    </Section>

    <Section id="vulnerabilities" title="Vulnerabilities" defaultOpen={false}>
      <Nope label="⊘ NO EXPOSURE DATA BOUND TO THIS ENDPOINT ENTITY"
            ep="capability_unavailable" />
      <div style={{ fontSize: 9.5, color: "var(--faint)", marginTop: 5,
                    lineHeight: 1.6 }}>
        Absence of exposure data is not evidence that the endpoint has no
        vulnerabilities.
      </div>
    </Section>
  </aside>
  );
};

export default EndpointDetailsDrawer;
