/**
 * NivXForge EDR Overview page · `/edr`
 *
 * When arrived from an Incident, shows the endpoint context first
 * (device / user / time / customer) so the analyst never loses their
 * operational anchor.
 *
 * P0-W.F-2 · CONSOLE TRUTH.  Surface availability is NOT a literal in
 * this file any more.  Every card reads the AUTHORITATIVE capability
 * registry (`GET /api/edr/wave0/capabilities`) and renders that grade
 * verbatim, with the registry's own `honest_note` as the reason.  A
 * capability the registry grades implemented can no longer be presented
 * as "Reserved · later slice", and a capability it grades
 * NOT_IMPLEMENTED can never be presented as operational.
 */
import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Radar, ShieldAlert, GitBranch, FileText, Wifi, ArrowRight } from "lucide-react";

import NivXForgeConsole, { useIncidentContext } from "@/nivxforge/NivXForgeConsole";
import { getEdrCapabilities } from "@/nivxforge/edrApi";
import { TelemetryFreshnessBanner }
  from "@/nivxforge/components/TelemetryFreshness";

// Card → the capability row that authoritatively grades it. The route is
// the CANONICAL EDR route (the legacy `/edr/trajectory` resolver is no
// longer advertised as the primary Device Trajectory destination).
const SURFACES = [
  { key: "trajectory",   label: "Device Trajectory", to: "/edr/device-trajectory",
    icon: Radar,       capability: "experience.device_trajectory_ui",
    hint: "Temporal canvas for endpoint activity — the primary EDR investigation surface." },
  { key: "detections",   label: "Detections",        to: "/edr/detections",
    icon: ShieldAlert, capability: "experience.detections_ui",
    hint: "Authoritative endpoint detections projected from the XDR detection fabric." },
  { key: "process-tree", label: "Process Tree",      to: "/edr/process-tree",
    icon: GitBranch,   capability: "experience.process_tree_ui",
    hint: "Parent → child ancestry from canonical process identities." },
  { key: "files",        label: "Files",             to: "/edr/files",
    icon: FileText,    capability: "experience.file_trajectory_ui",
    // The capability is real, but the surface that delivers it today is
    // the XDR-hosted Fleet File Trajectory. The EDR route is still a
    // reserved stub, so this product must not offer to open it.
    stubInThisProduct: "the file-trajectory capability is graded implemented, but it is "
                     + "currently delivered by the XDR-hosted Fleet File Trajectory — "
                     + "the NivXForge route is not wired to it yet (F-3 class)",
    hint: "File-system evidence: writes, drops, signers, hashes." },
  { key: "network",      label: "Network",           to: "/edr/network",
    icon: Wifi,        capability: "experience.network_ui",
    hint: "Endpoint-observed network connections + DNS." },
];

// The registry's vocabulary → what the console may claim. Only a state
// the registry has actually graded against runtime evidence is allowed
// to read as operational.
const GRADE = {
  END_TO_END_VALIDATED:     { label: "Available",   open: true,  tone: "mint" },
  REAL_ENDPOINT_VALIDATED:  { label: "Available",   open: true,  tone: "mint" },
  GOLDEN_CORPUS_VALIDATED:  { label: "Available",   open: true,  tone: "mint" },
  BACKEND_IMPLEMENTED:      { label: "Implemented · not runtime verified", open: true, tone: "amber" },
  UI_IMPLEMENTED:           { label: "Implemented · not runtime verified", open: true, tone: "amber" },
  CONTRACT_DEFINED:         { label: "Not implemented", open: false, tone: "faint" },
  NOT_IMPLEMENTED:          { label: "Not implemented", open: false, tone: "faint" },
};

export default function EdrOverviewPage() {
  const ctx = useIncidentContext();
  const [caps, setCaps] = useState(null);
  const [capErr, setCapErr] = useState(null);

  useEffect(() => {
    let cancelled = false;
    getEdrCapabilities()
      .then((d) => {
        if (cancelled) return;
        const byId = {};
        for (const r of d?.capabilities || []) byId[r.capability_id] = r;
        setCaps(byId);
      })
      .catch((e) => !cancelled
        && setCapErr(e?.response?.data?.detail || e.message || "unreachable"));
    return () => { cancelled = true; };
  }, []);

  return (
    <NivXForgeConsole activeTab="overview">
      <h1 className="page-h1" data-testid="edr-overview-heading">Endpoint Overview</h1>
      <div className="page-sub">
        {ctx.incident_id
          ? "Opened from an operational incident — endpoint context is pinned at the top of every page in this console."
          : "Endpoint state, recent detections, and pivots into the operational surfaces of NivXRay EDR."}
      </div>

      {/* P0-3 · the product states whether it is receiving anything at
          all, BEFORE it shows any endpoint surface. An empty surface on a
          blind pipeline is a visibility gap, not an all-clear. */}
      <TelemetryFreshnessBanner endpoint={ctx.device || null} />

      <div className="stat-grid" data-testid="edr-overview-stats">
        <Stat label="Device"       value={ctx.device || "Not provided"}  tone={ctx.device ? "cyan" : "faint"} />
        <Stat label="Customer"     value={ctx.tenant || "Not provided"}  tone={ctx.tenant ? "cyan" : "faint"} />
        <Stat label="User"         value={ctx.user   || "Not provided"}  tone={ctx.user   ? "cyan" : "faint"} />
        <Stat label="Agent Status" value="Not assessed on this surface"                       tone="faint" />
        {/* Isolation is never asserted without evidence: absence of a
            proven containment record is not proof that a host is free. */}
        <Stat label="Isolation"    value="Not assessed on this surface"                       tone="faint" />
        <Stat label="Risk"         value={ctx.incident_id ? "See Incident" : "—"}             tone="faint" />
      </div>

      <div className="section-title" style={{ marginBottom: 8 }}>Console Surfaces</div>
      <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 10 }}
           data-testid="edr-overview-capability-basis">
        {capErr
          ? `CAPABILITY REGISTRY UNREACHABLE (${capErr}) — no surface is claimed available.`
          : caps
            ? "Graded by the authoritative EDR capability registry · GET /api/edr/wave0/capabilities"
            : "Reading the authoritative capability registry…"}
      </div>
      <div style={{
        display: "grid",
        gap: 10,
        gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
      }} data-testid="edr-overview-surface-cards">
        {SURFACES.map((s) => (
          <SurfaceCard key={s.key} s={s} row={caps?.[s.capability]}
                       loading={!caps && !capErr} carry={ctx} />
        ))}
      </div>
    </NivXForgeConsole>
  );
}

function Stat({ label, value, tone = "cyan" }) {
  return (
    <div className={`stat-card ${tone}`}>
      <div className="lbl">{label}</div>
      <div className="val">{value}</div>
    </div>
  );
}

function SurfaceCard({ s, row, loading, carry }) {
  const Icon = s.icon;
  const state = row?.declared_state;
  const grade = GRADE[state] || null;
  // Until the registry has answered, nothing is claimed either way.
  // A capability the registry grades implemented is still NOT openable
  // from this product if this product's route does not deliver it yet:
  // grading a capability real never licenses claiming a stub works.
  const open = !loading && !!grade?.open && !s.stubInThisProduct;
  const reason = (!open && s.stubInThisProduct && grade?.open)
    ? s.stubInThisProduct
    : row?.honest_note;
  const stateLabel = loading
    ? "Reading registry…"
    : (s.stubInThisProduct && grade?.open)
      ? "Implemented · not wired in this product"
      : grade ? grade.label
              : state ? state
                      : "No capability row — nothing claimed";

  const carryQs = React.useMemo(() => {
    const p = new URLSearchParams();
    if (carry.incident_id) p.set("incident_id", carry.incident_id);
    if (carry.device)      p.set("device", carry.device);
    if (carry.tenant)      p.set("tenant", carry.tenant);
    if (carry.user)        p.set("user", carry.user);
    return p.toString();
  }, [carry.incident_id, carry.device, carry.tenant, carry.user]);

  const to = carryQs ? `${s.to}?${carryQs}` : s.to;
  const tone = loading ? "faint" : (grade?.tone || "faint");

  return (
    <div className="panel" style={{ padding: 14, opacity: open ? 1 : 0.7 }}
         data-testid={`edr-overview-card-${s.key}`}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <Icon size={14} style={{ color: `var(--${tone === "mint" ? "mint" : tone === "amber" ? "amber" : "faint"})` }} />
        <span style={{
          fontSize: 10.5, letterSpacing: ".3px",
          textTransform: "uppercase", fontWeight: 800,
          color: `var(--${tone === "mint" ? "mint" : tone === "amber" ? "amber" : "faint"})`,
        }} data-testid={`edr-overview-state-${s.key}`}>
          {stateLabel}
        </span>
      </div>
      <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text)" }}>{s.label}</div>
      <div style={{ marginTop: 4, fontSize: 11, color: "var(--muted)", lineHeight: 1.55 }}>
        {s.hint}
      </div>
      {!open && reason && (
        <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)", lineHeight: 1.5 }}
             data-testid={`edr-overview-reason-${s.key}`}>
          {reason}
        </div>
      )}
      {open ? (
        <Link
          to={to}
          className="btn mint"
          style={{ marginTop: 10, alignSelf: "flex-start", textDecoration: "none" }}
          data-testid={`edr-overview-open-${s.key}`}
        >
          Open <ArrowRight size={11} />
        </Link>
      ) : (
        <button className="btn" disabled style={{ marginTop: 10 }}
                data-testid={`edr-overview-closed-${s.key}`}>
          {loading ? "…" : "Not available"}
        </button>
      )}
      <div style={{ marginTop: 8, fontSize: 9.5, color: "var(--faint)", fontFamily: "monospace" }}>
        {s.capability}
      </div>
    </div>
  );
}
