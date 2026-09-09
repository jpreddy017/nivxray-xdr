/**
 * Pivot · NivXRay XDR observable pivot menu.
 *
 * TARGET: Cisco XDR's Pivot menu, structure-for-structure. Verified from
 * docs.xdr.security.cisco.com/Content/pivot-menu.htm (2026-06):
 *
 *   ┌ Verdict-time toggle ──────────────────────────────┐
 *   │  [ Incident time ] [ Current ]                    │  ← Cisco
 *   │  colour-coded verdict badges by disposition       │
 *   ├ Observable actions ───────────────────────────────┤
 *   │  Investigate observable                           │
 *   │  Add observable to investigation                  │
 *   │  Create judgment                                  │
 *   │  Copy value                                       │
 *   │  Copy defanged value                              │
 *   │  Add to new case / Add to active case             │
 *   ├ Pivot to integrated product ──────────────────────┤
 *   │  <product> → <action>                             │
 *   ├ Automation ───────────────────────────────────────┤
 *   │  run response workflow                            │
 *   └───────────────────────────────────────────────────┘
 *
 * NivXRay XDR differences, all deliberate:
 *   • Products pivoted to are OUR surfaces, reached with `navigate()` — the
 *     shell stays mounted, nothing opens another frontend (PR-XDR-0).
 *   • A capability we do not have is rendered DISABLED with the reason.
 *     Cisco shows fewer rows when an integration is absent; we show the row
 *     and say why, because a silently missing row is indistinguishable from
 *     a capability we never built.
 *   • `Copy value` / `Copy defanged value` are fully implemented — Cisco's
 *     defang rule lives in `ciscoSemantics.defang()`.
 */
import React, { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronDown, Radar, Terminal, Globe, Grid3x3, Search, FileText,
         Ban, Copy, ShieldOff, FolderPlus, Zap, Gavel } from "lucide-react";
import { disposition, verdictOf, defang } from "@/xdr/lib/ciscoSemantics";
import { defangOnCopy } from "@/xdr/lib/ribbonSettings";

// Why a capability has no NivXRay XDR destination yet. Shown verbatim.
const NO_DESTINATION = {
  intel: "NivXRay XDR Intelligence is not wired to its backing service in "
       + "this build. No in-product indicator surface exists to pivot to.",
  command: "NivXRay XDR Command Intelligence is not wired to the decode "
         + "fabric in this build.",
  malware: "NivXRay XDR Malware Intelligence is not wired to artifact "
         + "analysis in this build.",
  iue: "NivXRay XDR has no case-scoped collector/IUE surface. The Evidence "
     + "Explorer cannot carry this case reference.",
  casebook: "The casebook is not implemented in NivXRay XDR. There is no "
          + "case store to add this observable to.",
  judgment: "Private judgments are not implemented. Verdicts are owned by "
          + "the backend investigation services and are not authored here.",
  workflow: "Running a response workflow from a pivot is not wired. Use "
          + "Automate ▸ Playbooks, where approval and dispatch are enforced.",
};

const off = (key, label, icon, reason) =>
  ({ key, label, icon, unavailable: true, reason });

// ── product-pivot section · our real destinations, per observable kind ──
const PRODUCT_PIVOTS = {
  host: (v) => [
    { key: "trajectory", label: "Device Trajectory", icon: Radar,
      to: `/xdr/endpoints/${encodeURIComponent(v)}/trajectory`,
      hint: "Native NivXRay XDR trajectory canvas" },
    { key: "entity", label: "Endpoint Entity 360", icon: Search,
      to: `/xdr/endpoints/${encodeURIComponent(v)}`,
      hint: "Endpoint master-detail workspace" },
  ],
  device: (v, ctx) => PRODUCT_PIVOTS.host(v, ctx),
  process: () => [off("cmd", "Command Intelligence", Terminal,
                       NO_DESTINATION.command)],
  file:    () => [off("vt", "Malware Intelligence", Search,
                       NO_DESTINATION.malware)],
  hash:    () => [off("hash", "Hash Intelligence", Search, NO_DESTINATION.intel)],
  ip:      () => [off("ip", "IP Intelligence", Globe, NO_DESTINATION.intel)],
  domain:  () => [off("domain", "Domain Intelligence", Globe, NO_DESTINATION.intel)],
  url:     () => [off("url", "URL Intelligence", Globe, NO_DESTINATION.intel)],
  rule: (v) => [
    { key: "mitre", label: "MITRE ATT&CK Heatmap", icon: Grid3x3,
      to: `/xdr/intelligence/mitre?q=${encodeURIComponent(v)}`,
      hint: "Native ATT&CK heatmap, filtered to this reference" },
  ],
  engine: (v, ctx) => {
    const inc  = ctx?.incident_id ? encodeURIComponent(ctx.incident_id) : null;
    const rule = ctx?.rule_id     ? encodeURIComponent(ctx.rule_id)     : null;
    const low  = String(v || "").toLowerCase();
    if (low.includes("verdict engine")) {
      if (!inc) return [off("verdict", "Open Verdict & Technical", Radar,
        "No incident reference on this record, so there is no case to open "
        + "the verdict against.")];
      return [
        { key: "verdict", label: "Verdict & Technical", icon: Radar,
          to: `/xdr/incidents/${inc}?tab=technical${rule ? `&rule=${rule}` : ""}`,
          hint: "Stage-2 verdict on the incident record" },
        { key: "analyst", label: "Investigation Workspace", icon: Search,
          to: `/xdr/investigations/${inc}`,
          hint: "Causal investigation workspace" },
      ];
    }
    if (low.includes("collector") || low.includes("iue"))
      return [off("iue", "IUE Lane C", Terminal, NO_DESTINATION.iue)];
    if (["magic-byte", "magic", "zip-content", "heuristic"].includes(low))
      return [off("artifact", "Artifact Intelligence", FileText,
                   NO_DESTINATION.malware)];
    return [];
  },
  user: () => [],
};

// Kinds Cisco treats as observables (copy / investigate / judgment apply).
const OBSERVABLE_KINDS = new Set(
  ["hash", "ip", "domain", "url", "file", "process", "host", "device"]);

export default function Pivot({ kind, value, ctx, size = "sm", testid }) {
  const [open, setOpen]       = useState(false);
  const [scope, setScope]     = useState("incident");   // Cisco: time | current
  const [copied, setCopied]   = useState(null);
  const ref = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!open) return;
    const onDoc = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  if (!value) {
    return (
      <span className="mono" style={{ color: "var(--faint)", fontSize: 10.5 }}
            data-testid={testid || `pivot-${kind}-empty`}>
        NOT AVAILABLE
      </span>
    );
  }

  const base       = testid || `pivot-${kind}`;
  const products   = (PRODUCT_PIVOTS[kind] || (() => []))(value, ctx || {});
  const observable = OBSERVABLE_KINDS.has(kind);
  // Cisco: with Defang on Copy enabled, "Copy defanged value" is removed and
  // "Copy value" copies the defanged form.
  const defangCopy = defangOnCopy();

  // Cisco shows the verdict at INCIDENT TIME vs CURRENT. We only hold what the
  // record carries: `ctx.judgments` (incident time). There is no current-verdict
  // service, so CURRENT is honest about that rather than echoing incident time.
  const judgments = Array.isArray(ctx?.judgments) ? ctx.judgments : [];
  const verdict   = scope === "incident" ? verdictOf(judgments) : null;
  const scopeNote = scope === "current"
    ? "No current-verdict service is wired in NivXRay XDR. Re-enrichment on "
      + "demand arrives with Intelligence."
    : (judgments.length === 0
        ? "No judgments were recorded against this observable at incident time."
        : null);

  const copy = async (text, key) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1400);
    } catch { setCopied("failed"); }
  };

  // ── observable actions, in Cisco's order ──
  const actions = observable ? [
    ctx?.incident_id
      ? { key: "investigate", label: "Investigate observable", icon: Search,
          to: `/xdr/search?q=${encodeURIComponent(value)}`,
          hint: "Federated entity search across NivXRay XDR" }
      : { key: "investigate", label: "Investigate observable", icon: Search,
          to: `/xdr/search?q=${encodeURIComponent(value)}`,
          hint: "Federated entity search across NivXRay XDR" },
    off("add-to-investigation", "Add observable to investigation", FolderPlus,
        "Investigations are built from incident evidence, not assembled from "
        + "loose observables, in this build."),
    off("judgment", "Create judgment", Gavel, NO_DESTINATION.judgment),
    { key: "copy", label: copied === "copy" ? "Copied" : "Copy value",
      icon: Copy,
      onSelect: () => copy(defangCopy ? defang(value) : value, "copy"),
      hint: defangCopy
        ? `Defang on copy is ON · copies as ${defang(value)}`
        : "Copy the observable value to the clipboard" },
    ...(defangCopy ? [] : [{
      key: "copy-defanged",
      label: copied === "copy-defanged" ? "Copied" : "Copy defanged value",
      icon: ShieldOff, onSelect: () => copy(defang(value), "copy-defanged"),
      hint: `Copies as ${defang(value)} so the value cannot be clicked` }]),
    off("new-case", "Add to new case", FolderPlus, NO_DESTINATION.casebook),
    off("active-case", "Add to active case", FolderPlus, NO_DESTINATION.casebook),
  ] : [];

  const automation = observable
    ? [off("workflow", "Run response workflow", Zap, NO_DESTINATION.workflow)]
    : [];

  const hasMenu = actions.length + products.length > 0;
  if (!hasMenu) {
    return (
      <span className="mono" style={{ color: "var(--text-dim)", fontSize: 11 }}
            data-testid={`${base}-plain`}>{value}</span>
    );
  }

  const btnStyle = size === "xs"
    ? { padding: "2px 6px", fontSize: 10 }
    : { padding: "3px 8px", fontSize: 11 };

  const Row = ({ t, section }) => {
    const Icon = t.icon || Search;
    const rowTestId = `${base}-item-${t.key}`;
    if (t.unavailable) {
      return (
        <div role="menuitem" aria-disabled="true" data-testid={rowTestId}
             data-state="PIVOT_DESTINATION_NOT_AVAILABLE"
             data-pivot-section={section} title={t.reason}
             style={{ display: "flex", flexDirection: "column", gap: 3,
                       padding: "6px 8px", opacity: 0.55,
                       cursor: "not-allowed" }}>
          <span style={{ display: "inline-flex", alignItems: "center",
                          gap: 6, fontSize: 11.5 }}>
            <Ban size={11} />
            <span style={{ flex: 1, textAlign: "left" }}>{t.label}</span>
            <span className="mono" style={{ fontSize: 9 }}>NOT AVAILABLE</span>
          </span>
          <span className="mono" style={{ fontSize: 9.5, lineHeight: 1.5,
                                           color: "var(--faint)" }}>
            {t.reason}
          </span>
        </div>
      );
    }
    return (
      <button role="menuitem" type="button" className="btn ghost"
              data-testid={rowTestId} data-pivot-to={t.to || undefined}
              data-pivot-section={section} title={t.hint}
              style={{ width: "100%", justifyContent: "flex-start",
                        padding: "6px 8px", borderRadius: 4,
                        borderColor: "transparent" }}
              onClick={() => {
                if (t.onSelect) { t.onSelect(); return; }
                setOpen(false);
                navigate(t.to);
              }}>
        <Icon size={12} />
        <span style={{ flex: 1, textAlign: "left" }}>{t.label}</span>
      </button>
    );
  };

  const SectionLabel = ({ children }) => (
    <div style={{ padding: "6px 8px 2px", fontSize: 9.5, letterSpacing: ".4px",
                   color: "var(--faint)", textTransform: "uppercase",
                   fontWeight: 800 }}>{children}</div>
  );

  return (
    <span ref={ref} style={{ position: "relative", display: "inline-flex" }}>
      <button type="button" className="btn" style={btnStyle}
              onClick={() => setOpen((v) => !v)}
              data-testid={`${base}-trigger`}
              title={`Pivot from ${kind}: ${value}`}>
        <span className="mono" style={{ color: "var(--text)" }}>{value}</span>
        <ChevronDown size={10} />
      </button>
      {open && (
        <div className="panel" role="menu" data-testid={`${base}-menu`}
             style={{ position: "absolute", top: "100%", left: 0, marginTop: 4,
                       minWidth: 300, maxWidth: 380, zIndex: 40, padding: 4,
                       maxHeight: 520, overflowY: "auto" }}>

          {/* Cisco · verdict-time toggle + colour-coded verdict badge */}
          {observable && (
            <div data-testid={`${base}-verdict-scope`}
                 style={{ padding: "6px 8px", borderBottom:
                            "1px solid var(--line)" }}>
              <div style={{ display: "flex", gap: 4, marginBottom: 6 }}>
                {[["incident", ctx?.investigation_id
                                 ? "Investigation time" : "Incident time"],
                  ["current", "Current"]].map(([k, label]) => (
                  <button key={k} type="button" className="btn"
                          data-testid={`${base}-verdict-${k}`}
                          data-active={scope === k ? "true" : "false"}
                          onClick={() => setScope(k)}
                          style={{ padding: "2px 8px", fontSize: 10,
                                    opacity: scope === k ? 1 : 0.55 }}>
                    {label}
                  </button>
                ))}
              </div>
              {verdict ? (
                <span className="mono" data-testid={`${base}-verdict-badge`}
                      data-disposition={verdict.meta.key}
                      style={{ fontSize: 10, fontWeight: 800,
                                color: `var(${verdict.meta.cssVar}, var(--text))` }}>
                  {verdict.meta.label.toUpperCase()}
                  {verdict.module ? ` · ${verdict.module}` : ""}
                </span>
              ) : (
                <span className="mono" data-testid={`${base}-verdict-absent`}
                      data-state="NO_VERDICT"
                      style={{ fontSize: 9.5, color: "var(--faint)",
                                lineHeight: 1.5 }}>
                  {scopeNote}
                </span>
              )}
            </div>
          )}

          <SectionLabel>Pivot · {kind}</SectionLabel>
          {actions.map((t) => (
            <Row key={t.key} t={t} section="observable" />
          ))}

          {products.length > 0 && (
            <>
              <SectionLabel>NivXRay XDR surfaces</SectionLabel>
              {products.map((t) => (
                <Row key={t.key} t={t} section="product" />
              ))}
            </>
          )}

          {automation.length > 0 && (
            <>
              <SectionLabel>Automation</SectionLabel>
              {automation.map((t) => (
                <Row key={t.key} t={t} section="automation" />
              ))}
            </>
          )}
        </div>
      )}
    </span>
  );
}
