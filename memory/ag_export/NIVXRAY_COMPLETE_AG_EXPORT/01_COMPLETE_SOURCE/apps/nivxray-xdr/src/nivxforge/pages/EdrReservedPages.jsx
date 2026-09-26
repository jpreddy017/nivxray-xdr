/**
 * Honest empty-state pages for the not-yet-implemented tabs inside
 * the NivXForge EDR Console.  Every page renders inside the same
 * console shell (so the analyst never falls off the console),
 * preserves the incident context banner, and clearly states its
 * reserved status.  No fake data.
 */
import React from "react";
import { Lock } from "lucide-react";
import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";

function ReservedPage({ tabKey, heading, body }) {
  return (
    <NivXForgeConsole activeTab={tabKey}>
      <h1 className="page-h1">{heading}</h1>
      <div className="x-reserved" data-testid={`edr-page-${tabKey}`}>
        <div className="lock"><Lock size={11} /> Reserved · later slice</div>
        <div className="title">{heading}</div>
        <div className="body">{body}</div>
      </div>
    </NivXForgeConsole>
  );
}

export const EdrFilesPage = () => (
  <ReservedPage
    tabKey="files"
    heading="Files"
    body="File-system evidence observed by the endpoint agent: writes, drops, signers, hashes.  Deep-links each file into IOC Intelligence + Malware Intelligence.  Arrives in a later slice."
  />
);
export const EdrNetworkPage = () => (
  <ReservedPage
    tabKey="network"
    heading="Network"
    body="Endpoint-observed connections + DNS, with process attribution and pivots into NDR.  Arrives in a later slice."
  />
);
export const EdrHuntingPage = () => (
  <ReservedPage
    tabKey="hunting"
    heading="Threat Hunting"
    body="Free-form endpoint telemetry search — process, file, hash, IP, domain, URL, user, command line, event type, time — with full provenance on every result.  Arrives in a later slice."
  />
);
export const EdrForensicsPage = () => (
  <ReservedPage
    tabKey="forensics"
    heading="Forensics"
    body="Forensic snapshot + targeted live query on the endpoint.  Every collection carries an evidence id and audit trail.  Arrives in a later slice."
  />
);
export const EdrLiveQueryPage = () => (
  <ReservedPage
    tabKey="live-query"
    heading="Live Query"
    body="Targeted live query with approval workflow.  No one-click execution.  Arrives in a later slice."
  />
);
export const EdrResponsePage = () => (
  <ReservedPage
    tabKey="response"
    heading="Response"
    body="Endpoint response actions — Isolate, Kill Process, Quarantine File, Collect Artifact, Forensic Snapshot.  Every action must clear Approval → Execution → Verification → Audit.  Arrives in a later slice."
  />
);
