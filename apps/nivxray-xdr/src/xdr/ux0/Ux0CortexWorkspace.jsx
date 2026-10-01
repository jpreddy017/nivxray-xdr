/**
 * E2E-UX0 · Wave 1 · `/xdr/_ux0-preview/workspace`
 *
 * High-fidelity structural reimplementation of the owner-supplied Cortex XDR
 * split-view Incident Workspace.
 *
 * Reference ownership (catalogue rows 1–3):
 *   Cortex XDR = SHELL / LAYOUT authority.
 *   Cortex XDR is NOT the NivXRay capability authority — all ten NivXRay
 *   investigation tabs survive (Overview · Attack Story · Timeline · Evidence ·
 *   Entities · Detections · MITRE · Response · Activity · Report), five more
 *   than the reference shows.
 *
 * Data honesty: fields NivXRay cannot compute authoritatively keep their
 * structural position and render `NOT AVAILABLE` / `NOT EVALUATED` rather than
 * a fabricated number. Additive route; production is untouched.
 */
import React, { useState } from "react";
import {
  Monitor, User, ChevronDown, Star, MoreVertical, Clock, Shield,
  AlertTriangle, Activity as ActivityIcon, PlayCircle, CheckCircle2,
  UserCheck, Search,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { NxFlyout, NxEmpty } from "@/xdr/nx";
import { QUEUE, TACTICS, LIFECYCLE, WS_TABS, ALERT_SEV, SOURCES } from "./cortexFixtures";
import "./ux0.css";
import "./ux0-cortex.css";

export default function Ux0CortexWorkspace() {
  const [selId, setSelId] = useState(QUEUE[2].id);
  const [tab, setTab] = useState("overview");
  const [fly, setFly] = useState(null);
  const inc = QUEUE.find((q) => q.id === selId);

  return (
    <XdrShell flush>
      <div data-testid="cx-workspace-page">
        <div className="cx-top">
          <h1>Incidents</h1>
          <span className="cx-top__count" data-testid="cx-result-count">
            Found {QUEUE.length} results
          </span>
          <div className="cx-top__right">
            <span className="cx-na" data-testid="cx-design-state">DESIGN-STATE PREVIEW</span>
            <span>Alerts Table</span>
            <MoreVertical size={14} />
          </div>
        </div>

        <div className="cx">
          <aside className="cx-queue" data-testid="cx-queue">
            <div className="cx-queue__bar">
              <Search size={12} />
              <label>Sort:</label>
              <select data-testid="cx-queue-sort" defaultValue="updated">
                <option value="updated">Last Updated</option>
                <option value="score">Score</option>
                <option value="severity">Severity</option>
              </select>
            </div>
            {QUEUE.map((q) => (
              <button key={q.id} type="button"
                      className={`cx-row${q.id === selId ? " is-sel" : ""}`}
                      onClick={() => setSelId(q.id)}
                      data-testid={`cx-queue-row-${q.id}`}>
                <div className="cx-row__upd">{q.updated}</div>
                <div className="cx-row__l1">
                  <span className="cx-row__sev" data-s={q.severity}>
                    {q.severity[0].toUpperCase()}
                  </span>
                  <span className="cx-row__score">
                    Score {q.score == null
                      ? <em>NOT AVAILABLE</em>
                      : q.score}
                  </span>
                  <span className="cx-row__who">
                    <UserCheck size={11} />{q.assignee || "Unassigned"}
                  </span>
                  <span className={`cx-row__state${q.state === "New" ? " is-new" : ""}`}>
                    {q.state}
                  </span>
                </div>
                <div className="cx-row__title">
                  <b>{q.id}</b> {q.title}
                </div>
                <div className="cx-row__ctx">
                  <span><Monitor size={11} />{q.host}</span>
                  {q.user && <span><User size={11} />{q.user}</span>}
                </div>
              </button>
            ))}
          </aside>

          <section className="cx-detail" data-testid="cx-detail">
            <div className="cx-hdr" data-testid="cx-incident-header">
              <button className="cx-pill cx-pill--sev" data-s={inc.severity}
                       data-testid="cx-hdr-severity">
                {inc.severity[0].toUpperCase() + inc.severity.slice(1)}
                <ChevronDown size={12} />
              </button>
              <Star size={14} color="var(--nx-muted)" />
              <span className="cx-hdr__id">{inc.id}</span>
              <span className="cx-div" />
              <span className="cx-hdr__name">Add incident name</span>
              <div className="cx-hdr__sp">
                <span className="cx-pill cx-pill--quiet" title="NivXRay does not compute an incident score">
                  Score <span className="cx-na" style={{ marginLeft: 6 }}>NOT AVAILABLE</span>
                </span>
                <span className="cx-div" />
                <button className="cx-pill" data-testid="cx-hdr-assignee">
                  <UserCheck size={12} />{inc.assignee || "Unassigned"}<ChevronDown size={12} />
                </button>
                <button className="cx-pill" data-testid="cx-hdr-status">
                  {inc.state}<ChevronDown size={12} />
                </button>
                <MoreVertical size={15} />
              </div>
            </div>

            <p className="cx-sentence" data-testid="cx-incident-sentence">
              {inc.sentence}
            </p>

            <div className="cx-stats" data-testid="cx-stat-clusters">
              <div className="cx-stat">
                <span className="cx-stat__ring"><i>{inc.alerts}</i></span>
                <div>
                  <div className="cx-stat__k">Alerts</div>
                  <div className="cx-stat__srcs">
                    Sources:
                    {SOURCES.map((s) => <span key={s.k}>{s.k}</span>)}
                  </div>
                </div>
              </div>
              <div className="cx-stat">
                <span className="cx-stat__icon"><Monitor size={19} /></span>
                <div>
                  <div className="cx-stat__v">{inc.hosts}</div>
                  <div className="cx-stat__k">Host{inc.hosts === 1 ? "" : "s"}</div>
                </div>
              </div>
              <div className="cx-stat">
                <span className="cx-stat__icon"><User size={19} /></span>
                <div>
                  <div className="cx-stat__v">{inc.users}</div>
                  <div className="cx-stat__k">User{inc.users === 1 ? "" : "s"}</div>
                </div>
              </div>
              <div className="cx-openfor" data-testid="cx-open-for">
                <Clock size={14} color="var(--nx-muted)" />
                <div>
                  <b>Open for {inc.openDays} days</b>{" "}
                  <em>Created on {inc.created}</em>
                </div>
              </div>
            </div>

            <div className="cx-tabs" role="tablist" data-testid="cx-tabs">
              {WS_TABS.map((t) => (
                <button key={t.key} role="tab" aria-selected={t.key === tab}
                        className={`cx-tab${t.key === tab ? " is-active" : ""}`}
                        onClick={() => setTab(t.key)}
                        data-testid={`cx-tab-${t.key}`}>
                  {t.label}
                  {t.count != null && <span className="cx-tab__n">{t.count}</span>}
                </button>
              ))}
            </div>

            {tab === "overview"
              ? <Overview inc={inc} onEntity={setFly} />
              : <TabStub tab={WS_TABS.find((t) => t.key === tab)} />}
          </section>
        </div>

        <NxFlyout open={!!fly} title={fly?.name || ""} eyebrow={fly?.kind}
                  width={560} onClose={() => setFly(null)}
                  fullPageHref="/xdr/entity" testid="cx-flyout">
          {fly && (
            <NxEmpty
              title="Entity 360 is Wave 2 of this programme."
              hint={`The pivot interaction is implemented: queue → incident → entity flyout → full page. The ${fly.kind} detail panes are catalogued against the Microsoft Defender XDR reference (catalogue row 6) and are not implemented in Wave 1.`}
              data-testid="cx-flyout-wave2" />
          )}
        </NxFlyout>
      </div>
    </XdrShell>
  );
}

function Overview({ inc, onEntity }) {
  return (
    <>
      <div className="cx-attck__lead">
        Incidents by <b>MITRE</b> | <b>ATT&CK</b>
        <span style={{ fontStyle: "italic", color: "var(--nx-muted)" }}>
          {TACTICS.filter((t) => t.n > 0).length} Tactics and {inc.techniques} Techniques
        </span>
        <span className="cx-hdr__sp">
          <span className="cx-na" title="NivXRay only renders techniques that can cite an artifact">
            EVIDENCE-BACKED ONLY
          </span>
        </span>
      </div>
      <div className="cx-attck" data-testid="cx-attck-strip">
        {TACTICS.map((t) => (
          <button key={t.key} type="button"
                  className={`cx-tac${t.n > 0 ? " is-hit" : ""}`}
                  data-testid={`cx-tactic-${t.key}`}
                  title={t.n > 0
                    ? `${t.n} evidence-backed technique(s) — click to filter detections`
                    : "No technique in this tactic could cite an artifact"}>
            <div className="cx-tac__n">{t.n}</div>
            <div className="cx-tac__l">{t.label}</div>
          </button>
        ))}
      </div>

      <div className="cx-sect">
        <div className="cx-sect__h">
          Timeline
          <button className="cx-sect__more" data-testid="cx-timeline-more">Show More</button>
        </div>
        <div className="cx-rail" data-testid="cx-lifecycle-rail">
          {LIFECYCLE.map((n, i) => (
            <React.Fragment key={n.key}>
              {i > 0 && <span className="cx-rail__line" />}
              <span className={`cx-rail__n${n.at ? " is-hit" : ""}`}
                    data-testid={`cx-lifecycle-${n.key}`}>
                <span className="cx-rail__dot">
                  {n.key === "created" ? <AlertTriangle size={13} />
                    : n.key === "alert" ? <ActivityIcon size={13} />
                    : n.key === "assigned" ? <UserCheck size={13} />
                    : n.key === "investigation" ? <Search size={13} />
                    : n.key === "response" ? <PlayCircle size={13} />
                    : <CheckCircle2 size={13} />}
                </span>
                <span className="cx-rail__t">
                  {n.label}
                  <em>{n.at || "NOT OBSERVED"}</em>
                </span>
              </span>
            </React.Fragment>
          ))}
        </div>
      </div>

      <div className="cx-grid" data-testid="cx-overview-grid">
        <div className="cx-panel" data-testid="cx-panel-detections">
          <div className="cx-panel__h">
            Detections
            <button className="cx-sect__more">Show More</button>
          </div>
          <div className="cx-total">Total<b>{inc.alerts}</b></div>
          <div className="cx-panel__b">
            <div className="cx-legend">
              {ALERT_SEV.map((s) => (
                <div key={s.k} className="cx-legend__r" data-s={s.k}>
                  {s.label}<b>{s.n}</b>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="cx-panel" data-testid="cx-panel-sources">
          <div className="cx-panel__h">
            Sources
            <button className="cx-sect__more">Show More</button>
          </div>
          <div className="cx-total">Total<b>{SOURCES.length}</b></div>
          <div className="cx-panel__b">
            <div className="cx-src">
              {SOURCES.map((s) => (
                <div key={s.k}>
                  <div className="cx-src__i">{s.k}</div>
                  <div className="cx-src__n">{s.n}</div>
                </div>
              ))}
            </div>
            <div className="cx-empty" style={{ paddingBottom: 0 }}>
              <span className="cx-na">3 OF 5 CONTRIBUTING</span>
            </div>
          </div>
        </div>

        <div className="cx-panel" data-testid="cx-panel-hosts">
          <div className="cx-panel__h">
            Hosts
            <button className="cx-sect__more">Show More</button>
          </div>
          <div className="cx-total">Total<b>{inc.hosts}</b></div>
          <div className="cx-panel__b">
            <div className="cx-ent" onClick={() => onEntity({ name: inc.host, kind: "endpoint" })}
                 data-testid="cx-entity-host">
              <Monitor size={14} color="var(--nx-muted)" />
              <span className="cx-ent__n">{inc.host}</span>
              <span className="cx-ent__k">primary</span>
            </div>
          </div>
        </div>

        <div className="cx-panel" data-testid="cx-panel-users">
          <div className="cx-panel__h">
            Users
            <button className="cx-sect__more">Show More</button>
          </div>
          <div className="cx-total">Total<b>{inc.users}</b></div>
          <div className="cx-panel__b">
            {inc.userList.map((u) => (
              <div key={u} className="cx-ent" data-testid={`cx-entity-user-${u}`}
                   onClick={() => onEntity({ name: u, kind: "identity" })}>
                <User size={14} color="var(--nx-muted)" />
                <span className="cx-ent__n">{u}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="cx-note" style={{ marginTop: 12 }}>
        <b>Wave 1</b>
        <span>
          Cortex XDR is the shell/layout authority for this surface, not the
          NivXRay capability authority. The tab strip above carries all ten
          NivXRay investigation capabilities — five more than the reference
          screen shows — and every field NivXRay cannot compute authoritatively
          renders <span className="cx-na">NOT AVAILABLE</span> or{" "}
          <span className="cx-na">NOT OBSERVED</span> in its reference position
          instead of a fabricated value.
        </span>
      </div>
    </>
  );
}

function TabStub({ tab }) {
  return (
    <div style={{ padding: "18px 14px" }} data-testid={`cx-tabstub-${tab.key}`}>
      <NxEmpty
        title={`${tab.label} is scheduled for Wave ${tab.wave} of this programme.`}
        hint={`Primary reference: ${tab.ref}. The reference and the NivXRay capability/data mapping are locked in memory/E2E_UX0_REFERENCE_CATALOGUE.md; implementation has not started, so this surface is deliberately empty rather than mocked.`}
        data-testid={`cx-empty-${tab.key}`} />
    </div>
  );
}
