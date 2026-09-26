/**
 * E2E-UX0 · `/xdr/_ux0-preview` — visual acceptance environment.
 *
 * ADDITIVE AND NON-DESTRUCTIVE. No production route is altered, no production
 * page is replaced, nothing is written to any database. Every panel except
 * Command Intelligence renders explicitly badged DESIGN-STATE fixtures;
 * Command Intelligence calls the real `POST /api/analyze/command`.
 *
 * Demonstrates blueprint §3: shell → persistent incident header (expanded and
 * condensed) → tab set → Overview → Attack Story → Timeline → Evidence →
 * Entities → Response → Activity → Command Intelligence → layered flyout →
 * the three empty/unavailable states → light and dark.
 */
import React, { useEffect, useState } from "react";

import XdrShell from "@/xdr/XdrShell";
import { NxFlyout, NxEmpty, NxProvenanceChip, NxVerdict } from "@/xdr/nx";
import Ux0IncidentHeader from "./Ux0IncidentHeader";
import Ux0Overview from "./Ux0Overview";
import Ux0AttackStory from "./Ux0AttackStory";
import { Ux0Evidence, Ux0Entities, Ux0Activity } from "./Ux0Tables";
import Ux0CommandIntel from "./Ux0CommandIntel";
import { Panel, TechnicalDetails } from "./Ux0Parts";
import {
  INCIDENT, METRICS, STAGES, CLAIMS, EVIDENCE, ENTITIES, ACTIVITY,
} from "./ux0Fixtures";
import "./ux0.css";

const TABS = [
  { key: "overview",  label: "Overview" },
  { key: "story",     label: "Attack Story", count: CLAIMS.length },
  { key: "timeline",  label: "Timeline" },
  { key: "evidence",  label: "Evidence", count: EVIDENCE.length },
  { key: "entities",  label: "Entities", count: ENTITIES.length },
  { key: "response",  label: "Response" },
  { key: "activity",  label: "Activity", count: ACTIVITY.length },
];

export default function Ux0PreviewPage() {
  const [tab, setTab] = useState("overview");
  const [condensed, setCondensed] = useState(false);
  const [stack, setStack] = useState([]);          // layered flyouts

  useEffect(() => {
    const onScroll = () => setCondensed(window.scrollY > 120);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const push = (fly) => setStack((s) => [...s, fly]);
  const pop = () => setStack((s) => s.slice(0, -1));
  const top = stack[stack.length - 1];

  return (
    <XdrShell>
      <div className="ux0" data-testid="ux0-preview-page">
        <div className="ux0-banner" data-testid="ux0-design-state-banner">
          <b>UX0 preview</b>
          <span>
            Visual acceptance environment for <code>E2E_UX0_BLUEPRINT.md</code>.
            Every panel except <strong>Command Intelligence</strong> renders
            design-state fixtures — not production data, never persisted.
            Command Intelligence calls the real
            <code> POST /api/analyze/command</code>. This route replaces nothing.
          </span>
        </div>

        <Ux0IncidentHeader incident={INCIDENT} condensed={condensed}
                           tabs={TABS} active={tab} onTab={setTab} />

        {tab === "overview" && (
          <Ux0Overview incident={INCIDENT} metrics={METRICS} stages={STAGES}
                       onDrawer={(kind) => push({ kind, title: DRAWER[kind].title,
                                                   eyebrow: DRAWER[kind].eyebrow })} />
        )}

        {tab === "story" && (
          <Ux0AttackStory stages={STAGES} claims={CLAIMS}
                          onProof={(p) => push({
                            kind: p.kind, title: p.label,
                            eyebrow: `${p.kind} · proof`,
                          })} />
        )}

        {tab === "timeline" && (
          <div style={{ marginTop: 18 }}>
            <Panel title="Timeline" testid="ux0-timeline-panel">
              <NxEmpty
                title="No evidence has been attached to this incident yet."
                hint="The timeline populates from correlated detection events. This incident has 4 detections but no event-level projection in the design-state fixture."
                data-testid="ux0-empty-nodata" />
            </Panel>
          </div>
        )}

        {tab === "evidence" && (
          <Ux0Evidence rows={EVIDENCE}
                       onRow={(r) => push({
                         kind: r.kind, title: r.entity,
                         eyebrow: `${r.type} · evidence`, row: r,
                       })} />
        )}

        {tab === "entities" && (
          <Ux0Entities rows={ENTITIES}
                       onRow={(r) => push({
                         kind: "entity", title: r.name,
                         eyebrow: `${r.type} · entity 360`, row: r,
                       })} />
        )}

        {tab === "response" && (
          <div style={{ marginTop: 18 }}>
            <Panel title="Response" testid="ux0-response-panel">
              <NxEmpty
                title="You are not authorized for response actions."
                hint="Your effective permissions do not include incident.respond. Authorization basis: effective permission set from /api/xdr/rbac/me/effective. This is an authorization decision, not a missing feature."
                data-testid="ux0-empty-unauthorized" />
            </Panel>
          </div>
        )}

        {tab === "activity" && <Ux0Activity rows={ACTIVITY} />}

        <div style={{ marginTop: 26 }}>
          <div className="ux0-banner">
            <b>Composition</b>
            <span>
              Command Intelligence is not a tab — it is a composition rendered
              inside a flyout from any command artifact, and on its own page for
              ad-hoc analysis. The layout below is byte-identical in both
              containers.
            </span>
          </div>
          <Ux0CommandIntel />
        </div>

        <NxFlyout
          open={!!top} title={top?.title || ""} eyebrow={top?.eyebrow}
          width={top?.kind === "command" ? 760 : 560}
          onClose={() => setStack([])}
          onBack={stack.length > 1 ? pop : undefined}
          backLabel={stack.length > 1
            ? stack[stack.length - 2].title.slice(0, 28) : undefined}
          fullPageHref={top?.kind === "entity" ? "/xdr/entity" : undefined}
          testid="ux0-flyout">
          {top && <FlyoutBody fly={top} onPush={push} />}
        </NxFlyout>
      </div>
    </XdrShell>
  );
}

const DRAWER = {
  assets:      { title: "Assets (3)",       eyebrow: "impact · drawer" },
  observables: { title: "Observables (17)", eyebrow: "impact · drawer" },
  indicators:  { title: "Indicators (6)",   eyebrow: "impact · drawer" },
  detection:   { title: "Detection detail", eyebrow: "detection · drawer" },
};

function FlyoutBody({ fly, onPush }) {
  if (fly.kind === "command") {
    return <Ux0CommandIntel compact />;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <Panel title="Summary" testid="ux0-fly-summary">
        <div className="ux0-chiprow">
          <NxVerdict value={fly.row?.verdict || "unknown"} />
          <NxProvenanceChip provenance={fly.row?.provenance || "observed"} />
        </div>
        <p className="ux0-prose" style={{ marginTop: 10 }}>
          {fly.row?.entity || fly.title} was first seen at{" "}
          {fly.row?.seen || "09:22:14Z"} from {fly.row?.source || "Sysmon"} and is
          part of the execution stage of this incident.
        </p>
      </Panel>
      <Panel title="Relations" testid="ux0-fly-relations">
        <div className="ux0-chiprow">
          <button type="button" className="ux0-proof"
                  onClick={() => onPush({ kind: "command",
                                          title: "Command artifact",
                                          eyebrow: "command · intelligence" })}
                  data-testid="ux0-fly-open-command">
            command artifact ▸
          </button>
          <button type="button" className="ux0-proof"
                  onClick={() => onPush({ kind: "entity", title: "FIN-WS-014",
                                          eyebrow: "endpoint · entity 360",
                                          row: ENTITIES[0] })}
                  data-testid="ux0-fly-open-entity">
            FIN-WS-014 ▸
          </button>
        </div>
      </Panel>
      <Panel title="Why it was flagged" testid="ux0-fly-why">
        <div className="ux0-kv">
          <span className="ux0-kv__k">Rule</span>
          <span className="ux0-kv__v">Obfuscated PowerShell — runtime string assembly</span>
          <span className="ux0-kv__k">Matched</span>
          <span className="ux0-kv__v">
            <code>process.command_line contains '-ExecutionPolicy bypass'</code>
          </span>
        </div>
      </Panel>
      <TechnicalDetails json={fly.row || { note: "design-state fixture" }}
                        testid="ux0-fly-tech" />
    </div>
  );
}
