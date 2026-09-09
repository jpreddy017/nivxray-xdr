/**
 * TrajectoryFiltersModal · the Cisco Secure Endpoint filter matrix,
 * mapped honestly onto the NivXForge substrate.
 *
 * Every criterion in the vendor matrix is listed, so an analyst who
 * knows AMP finds what they expect.  A criterion whose backing signal
 * does not exist in `v2_shadow_observations` is rendered DISABLED with
 * the reason — it is never offered as a live filter that silently
 * matches nothing.
 */
import React from "react";
import { X } from "lucide-react";

/** predicate === null → no backing signal in this substrate. */
export const FILTER_GROUPS = [
  {
    key: "activity", title: "Activity events",
    items: [
      { key: "create",   label: "Create (file write)", kinds: ["file_create", "file_write"] },
      { key: "delete",   label: "Delete",              kinds: ["file_delete"] },
      { key: "execute",  label: "Execute (process launch)", kinds: ["process_create"] },
      { key: "network",  label: "Network connection",  kinds: ["network_connect", "network_listen"] },
      { key: "registry", label: "Registry value set",  kinds: ["registry_value_set"] },
      { key: "service",  label: "Service install",     kinds: ["service_install"] },
      { key: "memory",   label: "Memory allocation",   kinds: ["memory_alloc"] },
      { key: "kernel",   label: "Kernel / behavioural telemetry", kinds: ["kernel_event"] },
      { key: "cloud",    label: "Cloud IAM action",    kinds: ["cloud_iam_action"] },
      { key: "copy",     label: "Copy (duplication)",  kinds: null,
        reason: "no copy/duplication event kind is emitted" },
      { key: "move",     label: "Move / rename",       kinds: null,
        reason: "no move/rename event kind is emitted" },
      { key: "open",     label: "Open (handle read)",  kinds: null,
        reason: "no handle-open telemetry is collected" },
      { key: "exec_blocked", label: "Execute blocked", kinds: null,
        reason: "no prevention engine is registered" },
      { key: "exploit",  label: "Exploit prevention",  kinds: null,
        reason: "no exploit-prevention engine is registered" },
      { key: "restore",  label: "Restore from quarantine", kinds: null,
        reason: "no quarantine vault exists" },
    ],
  },
  {
    key: "lifecycle", title: "System & lifecycle",
    items: [
      { key: "compromise", label: "Compromise (detection)", tier: 2 },
      { key: "attributed", label: "Technique attributed",   tier: 1 },
      { key: "reboot",     label: "Reboot",             kinds: null,
        reason: "no power/lifecycle telemetry" },
      { key: "scan",       label: "Scan",               kinds: null,
        reason: "no scan engine is registered" },
      { key: "defs",       label: "Definitions update", kinds: null,
        reason: "no connector definitions plane" },
      { key: "policy",     label: "Policy update",      kinds: null,
        reason: "no policy plane is bound" },
      { key: "connector",  label: "Connector update",   kinds: null,
        reason: "no connector is enrolled" },
      { key: "isolation",  label: "Isolation status changed", kinds: null,
        reason: "response driver not registered" },
    ],
  },
  {
    key: "disposition", title: "Disposition",
    items: [
      { key: "unknown",   label: "Unknown", disposition: "unknown" },
      { key: "benign",    label: "Benign",  kinds: null,
        reason: "the substrate carries no disposition field" },
      { key: "malicious", label: "Malicious", kinds: null,
        reason: "the substrate carries no disposition field" },
    ],
  },
  {
    key: "modifiers", title: "Modifiers",
    items: [
      { key: "command_line", label: "Command line present", field: "command_line" },
      { key: "sha256",       label: "File SHA-256 present", field: "file_sha256" },
      { key: "no_flag",      label: "No flag (benign telemetry)", tier: 0 },
      { key: "audit",        label: "Audit only",           kinds: null,
        reason: "no audit-mode policy exists" },
    ],
  },
];

export const AVAILABLE_KEYS = new Set(
  FILTER_GROUPS.flatMap((g) => g.items
    .filter((i) => i.kinds !== null)
    .map((i) => `${g.key}:${i.key}`)),
);

export default function TrajectoryFiltersModal({ active, onToggle, onClear, onClose }) {
  const enabledCount = active.size;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 65,
                  background: "rgba(4,6,10,0.66)", display: "flex",
                  alignItems: "flex-start", justifyContent: "center",
                  paddingTop: 70 }}
         onClick={onClose}
         data-testid="edr-filters-overlay">
      <section onClick={(e) => e.stopPropagation()}
               className="panel"
               style={{ width: 1000, maxWidth: "95vw", maxHeight: "78vh",
                        overflow: "auto", padding: 14, background: "#11161D" }}
               data-testid="edr-filters-modal">
        <div style={{ display: "flex", alignItems: "center", gap: 10,
                      marginBottom: 10 }}>
          <div className="section-title" style={{ flex: 1, margin: 0 }}>
            Filters · {enabledCount || "none"} active
          </div>
          <button className="btn" style={{ padding: "3px 8px", fontSize: 10 }}
                  onClick={onClear} data-testid="edr-filters-clear">Clear all</button>
          <button className="btn" style={{ padding: "2px 6px" }} onClick={onClose}
                  data-testid="edr-filters-close"><X size={11} /></button>
        </div>

        <div style={{ display: "grid",
                      gridTemplateColumns: "repeat(auto-fit,minmax(228px,1fr))",
                      gap: 12 }}>
          {FILTER_GROUPS.map((g) => (
            <div key={g.key} style={{ border: "1px solid #212B36", borderRadius: 4,
                                      padding: 10, background: "#0B0F14" }}>
              <div style={{ color: "var(--faint)", fontSize: 9, fontWeight: 800,
                            textTransform: "uppercase", letterSpacing: ".4px",
                            marginBottom: 7 }}>{g.title}</div>
              {g.items.map((i) => {
                const id = `${g.key}:${i.key}`;
                const usable = i.kinds !== null;
                const on = active.has(id);
                return (
                  <label key={id}
                         title={usable ? undefined : `⊘ ${i.reason}`}
                         style={{ display: "flex", gap: 6, alignItems: "flex-start",
                                  marginBottom: 5, fontSize: 10.5,
                                  color: usable ? "#C7D0DB" : "#5D6875",
                                  cursor: usable ? "pointer" : "not-allowed" }}>
                    <input type="checkbox" checked={on} disabled={!usable}
                           onChange={() => onToggle(id)}
                           style={{ marginTop: 2 }}
                           data-testid={`edr-filter-${g.key}-${i.key}`} />
                    <span>
                      {usable ? i.label : `⊘ ${i.label}`}
                      {!usable && (
                        <div className="mono" style={{ fontSize: 8.6,
                                                       color: "#4B5563" }}>
                          {i.reason}
                        </div>
                      )}
                    </span>
                  </label>
                );
              })}
            </div>
          ))}
        </div>

        <div style={{ marginTop: 10, fontSize: 9.8, color: "var(--faint)",
                      lineHeight: 1.7 }}>
          Disabled criteria exist in the Cisco matrix but have no backing
          signal in <span className="mono">v2_shadow_observations</span>. They
          are shown so the taxonomy is complete and disabled so they cannot
          silently filter to nothing.
        </div>
      </section>
    </div>
  );
}

/** Apply the active criteria to the observation set. */
export function applyFilters(events, active) {
  if (!active || active.size === 0) return events;
  const kindSets = [];
  let tierSet = null;
  const fields = [];
  for (const g of FILTER_GROUPS) {
    for (const i of g.items) {
      const id = `${g.key}:${i.key}`;
      if (!active.has(id) || i.kinds === null) continue;
      if (i.kinds) kindSets.push(...i.kinds);
      if (i.tier !== undefined) { tierSet = tierSet || new Set(); tierSet.add(i.tier); }
      if (i.field) fields.push(i.field);
      if (i.disposition) { /* every row is unknown — matches all */ }
    }
  }
  return events.filter((e) => {
    if (kindSets.length && !kindSets.includes(e.observation_kind)) return false;
    if (fields.length && !fields.every((f) => e[f])) return false;
    if (tierSet) {
      const t = (e.mitre || []).length || (e.labels || []).length ? 1 : 0;
      const tier = (e.kind === "detection" || e.severity === "critical"
                    || e.severity === "high") ? 2 : t;
      if (!tierSet.has(tier)) return false;
    }
    return true;
  });
}
