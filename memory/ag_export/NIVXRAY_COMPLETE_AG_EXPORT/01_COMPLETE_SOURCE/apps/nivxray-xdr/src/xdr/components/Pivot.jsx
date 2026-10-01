/**
 * Pivot · Slice 1 — Contextual pivot menu for XDR entities.
 *
 * Rules (owner-locked):
 *   • Every pivot target is an EXISTING NivXRay capability or an
 *     in-XDR route.  We never fabricate targets.
 *   • External targets open in a new browser tab (never duplicated
 *     inside this bundle).
 *   • Entities without a value show `NOT AVAILABLE` — no fake IDs.
 */
import React, { useEffect, useRef, useState } from "react";
import { ChevronDown, ExternalLink, Radar, Terminal, Globe, Grid3x3, Search, FileText } from "lucide-react";

// Pivot targets per entity kind.  Keep the list surgical — one row per
// existing capability the analyst can actually reach.
const PIVOTS = {
  host: (v, ctx) => [
    { key: "trajectory", label: "Device Trajectory (XDR)",
      icon: Radar, to: `/xdr/endpoints/${encodeURIComponent(v)}/trajectory`,
      external: false, hint: "Native XDR trajectory canvas" },
    { key: "base-trajectory", label: "Device Trajectory (Base)",
      icon: ExternalLink, to: `/edr/trajectory?device=${encodeURIComponent(v)}${ctx?.incident_id ? `&incident_id=${encodeURIComponent(ctx.incident_id)}` : ""}`,
      external: true, hint: "Existing base-app trajectory (new tab)" },
  ],
  device: (v, ctx) => PIVOTS.host(v, ctx),
  process: (v, ctx) => [
    { key: "cmd", label: "Command Intelligence",
      icon: Terminal, to: `/analyze${ctx?.incident_id ? `?incident_id=${encodeURIComponent(ctx.incident_id)}` : ""}`,
      external: true, hint: "Analyze command line (new tab)" },
  ],
  file: (v) => [
    { key: "vt", label: "Malware Intelligence",
      icon: Search, to: `/documents?q=${encodeURIComponent(v)}`,
      external: true, hint: "File intel lookup (new tab)" },
  ],
  hash: (v) => [
    { key: "hash", label: "Hash Intelligence",
      icon: Search, to: `/threat-intel?q=${encodeURIComponent(v)}`,
      external: true, hint: "Hash reputation (new tab)" },
  ],
  ip: (v) => [
    { key: "ip", label: "IP Intelligence",
      icon: Globe, to: `/threat-intel?q=${encodeURIComponent(v)}&type=ip`,
      external: true, hint: "IP reputation (new tab)" },
  ],
  domain: (v) => [
    { key: "domain", label: "Domain Intelligence",
      icon: Globe, to: `/threat-intel?q=${encodeURIComponent(v)}&type=domain`,
      external: true, hint: "Domain reputation (new tab)" },
  ],
  url: (v) => [
    { key: "url", label: "URL Intelligence",
      icon: Globe, to: `/threat-intel?q=${encodeURIComponent(v)}&type=url`,
      external: true, hint: "URL reputation (new tab)" },
  ],
  rule: (v) => [
    { key: "mitre", label: "MITRE ATT&CK Heatmap",
      icon: Grid3x3, to: `/heatmap`,
      external: true, hint: "MITRE technique map (new tab)" },
  ],
  // Slice 3 · Detection Sourcing — pivot on a detection's source engine.
  // `ctx` may carry {incident_id, rule_id} so the engine viewer can
  // ground into the same case + rule.
  engine: (v, ctx) => {
    const enc  = ctx?.incident_id ? encodeURIComponent(ctx.incident_id) : null;
    const rule = ctx?.rule_id     ? encodeURIComponent(ctx.rule_id)     : null;
    const low  = String(v || "").toLowerCase();
    // Deterministic mapping: which authoritative surface owns each
    // known source-engine identifier?  Anything unknown → NO MATCHING
    // EVIDENCE handled at the caller.
    const targets = [];
    if (low.includes("verdict engine")) {
      targets.push({
        key: "verdict", label: "Open Stage-2 Verdict Engine",
        icon: Radar,
        to: enc
          ? `/edr/trajectory?incident_id=${enc}${rule ? `&rule=${rule}` : ""}`
          : `/edr/trajectory`,
        external: true, hint: "Existing Verdict Engine viewer (new tab)",
      });
      if (enc) targets.push({
        key: "analyst", label: "Open Analyst Workspace",
        icon: ExternalLink, to: `/analyst?case=${enc}&tab=verdict`,
        external: true, hint: "Rehydrated in the Analyst Workspace (new tab)",
      });
    } else if (low.includes("collector") || low.includes("iue")) {
      targets.push({
        key: "iue", label: "Open IUE Lane C",
        icon: Terminal,
        to: enc ? `/analyst?case=${enc}&tab=iue` : `/analyst`,
        external: true, hint: "IUE collector lane (new tab)",
      });
    } else if (low === "magic-byte" || low === "magic"
                  || low === "zip-content" || low === "heuristic") {
      targets.push({
        key: "artifact", label: "Open Artifact Intelligence",
        icon: FileText, to: `/documents${enc ? `?case=${enc}` : ""}`,
        external: true, hint: "Artifact intelligence source (new tab)",
      });
    }
    return targets;
  },
  user: () => [],
};

export default function Pivot({ kind, value, ctx, size = "sm", testid }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

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

  const targets = (PIVOTS[kind] || (() => []))(value, ctx || {});
  const btnStyle = size === "xs"
    ? { padding: "2px 6px", fontSize: 10 }
    : { padding: "3px 8px", fontSize: 11 };

  const trigger = (
    <button
      type="button"
      className="btn"
      style={btnStyle}
      onClick={() => setOpen((v) => !v)}
      data-testid={testid || `pivot-${kind}-trigger`}
      title={`Pivot from ${kind}: ${value}`}
    >
      <span className="mono" style={{ color: "var(--text)" }}>{value}</span>
      <ChevronDown size={10} />
    </button>
  );

  if (targets.length === 0) {
    return (
      <span className="mono" style={{ color: "var(--text-dim)", fontSize: 11 }}
            data-testid={testid || `pivot-${kind}-plain`}>
        {value}
      </span>
    );
  }

  return (
    <span ref={ref} style={{ position: "relative", display: "inline-flex" }}>
      {trigger}
      {open && (
        <div
          className="panel"
          role="menu"
          data-testid={testid ? `${testid}-menu` : `pivot-${kind}-menu`}
          style={{
            position: "absolute", top: "100%", left: 0, marginTop: 4,
            minWidth: 240, zIndex: 40, padding: 4,
            boxShadow: "0 10px 28px rgba(0,0,0,.55)",
          }}
        >
          <div style={{
            padding: "6px 8px", fontSize: 9.5, letterSpacing: ".4px",
            color: "var(--faint)", textTransform: "uppercase", fontWeight: 800,
          }}>
            Pivot · {kind}
          </div>
          {targets.map((t) => {
            const Icon = t.icon || ExternalLink;
            const click = () => {
              setOpen(false);
              if (t.external) window.open(t.to, "_blank", "noopener,noreferrer");
              else window.location.assign(t.to);
            };
            return (
              <button
                key={t.key}
                role="menuitem"
                type="button"
                className="btn ghost"
                style={{
                  width: "100%", justifyContent: "flex-start",
                  padding: "6px 8px", borderRadius: 4, borderColor: "transparent",
                }}
                onClick={click}
                data-testid={`${testid || `pivot-${kind}`}-item-${t.key}`}
                title={t.hint}
              >
                <Icon size={12} />
                <span style={{ flex: 1, textAlign: "left" }}>{t.label}</span>
                {t.external && <ExternalLink size={10} style={{ color: "var(--faint)" }} />}
              </button>
            );
          })}
        </div>
      )}
    </span>
  );
}
