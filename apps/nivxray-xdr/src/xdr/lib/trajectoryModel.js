/**
 * trajectoryModel · pure projection helpers for the Device Trajectory
 * lifeline canvas, compromise band and events ledger.
 *
 * Honest-State contract enforced here, once, for every consumer:
 *   • Nothing is derived that is not present in the observation record.
 *   • Process→process lineage is reported ONLY when a declared
 *     `parent_iid` resolves to a `process_iid` that was itself observed.
 *     Today that count is 0, so no lineage edge is produced and callers
 *     render `[ROOT / PARENT NOT OBSERVED]`.
 *   • actor→target connectors ARE evidence: both endpoints come from the
 *     same single observation document.
 */

export const IOC_RED       = "#FF3838";
export const TELEMETRY_CYAN = "#00D2D3";
export const IOC_BAND_FILL = "rgba(243, 156, 18, 0.12)";
export const IOC_BAND_EDGE = "rgba(243, 156, 18, 0.55)";

const PROCESS_KINDS = new Set(["process_create"]);

/** Glyph vocabulary — one per observed `observation_kind`. */
export const GLYPHS = {
  process_create:     { sym: "▶", tag: "EXEC", color: "#8FA6C8", label: "Execution" },
  file_create:        { sym: "◼", tag: "FILE", color: "#7FD1AE", label: "File create" },
  file_write:         { sym: "◼", tag: "FILE", color: "#7FD1AE", label: "File write" },
  file_delete:        { sym: "◻", tag: "FILE", color: "#C9A227", label: "File delete" },
  registry_value_set: { sym: "◆", tag: "REG",  color: "#B08CE0", label: "Registry set" },
  network_connect:    { sym: "●", tag: "NET",  color: TELEMETRY_CYAN, label: "Network connect" },
  network_listen:     { sym: "◐", tag: "NET",  color: TELEMETRY_CYAN, label: "Network listen" },
  service_install:    { sym: "⬢", tag: "SVC",  color: "#E0A75E", label: "Service install" },
  memory_alloc:       { sym: "▤", tag: "MEM",  color: "#9BB0C9", label: "Memory alloc" },
  kernel_event:       { sym: "▣", tag: "KRN",  color: "#9BB0C9", label: "Kernel event" },
  cloud_iam_action:   { sym: "☁", tag: "IAM",  color: "#9BB0C9", label: "Cloud IAM" },
  detection:          { sym: "✖", tag: "IOC",  color: IOC_RED, label: "Detection" },
};

export function glyphFor(evt) {
  if (evt.kind === "detection") return GLYPHS.detection;
  return GLYPHS[evt.observation_kind] || {
    sym: "○", tag: "OBS", color: "#78808f", label: evt.observation_kind || "observation",
  };
}

/** Literal artifact tag from the observed path — never guessed.
 *  `.exe` yields `[EXE]`, not `[PE]`: PE-ness would be a claim about
 *  file contents we have not parsed. */
export function typeTag(pathOrName) {
  const s = String(pathOrName || "");
  const leaf = s.split(/[\\/]/).pop() || "";
  if (/^[a-f0-9]{64}$/i.test(leaf)) return "[SHA-256]";
  if (!leaf.includes(".")) return "[NO EXT]";
  const ext = leaf.split(".").pop();
  if (!ext || ext.length > 8) return "[NO EXT]";
  return `[${ext.toUpperCase()}]`;
}

export const TIER_BENIGN     = 0;   // telemetry with no adverse signal recorded
export const TIER_ATTRIBUTED = 1;   // technique / label carried on the record
export const TIER_MALICIOUS  = 2;   // an actual detection or high severity

export const TIER_COLOR = {
  0: TELEMETRY_CYAN,
  1: "#F39C12",
  2: IOC_RED,
};

/**
 * Severity tier — persisted signals only, and it drives z-ordering so a
 * malicious marker is never buried under benign telemetry.
 */
export function severityTier(evt) {
  if (!evt) return TIER_BENIGN;
  if (evt.kind === "detection") return TIER_MALICIOUS;
  if (evt.severity === "critical" || evt.severity === "high") return TIER_MALICIOUS;
  if ((evt.mitre || []).length > 0 || (evt.labels || []).length > 0) return TIER_ATTRIBUTED;
  return TIER_BENIGN;
}

/** IOC flag — any recorded adverse attribution. */
export function isIoc(evt) {
  return severityTier(evt) >= TIER_ATTRIBUTED;
}

export function tsOf(evt) {
  const t = new Date(evt?.timestamp).getTime();
  return Number.isFinite(t) ? t : null;
}

/**
 * Collapse observations that are the SAME persisted event replayed under
 * multiple case references (`event.iid` is stable, `case_id` is not).
 * The duplication is real, so it is reported, not hidden.
 */
export function dedupeObservations(events) {
  const out = [];
  const index = new Map();
  for (const e of events || []) {
    const key = e.evidence_ref?.event_iid || e.id;
    const seen = index.get(key);
    if (!seen) {
      const row = {
        ...e,
        id: key,
        event_iid: e.evidence_ref?.event_iid || null,
        case_refs: e.incident_id ? [e.incident_id] : [],
        mitre: [...(e.mitre || [])],
        labels: [...(e.labels || [])],
        occurrences: 1,
      };
      index.set(key, row);
      out.push(row);
      continue;
    }
    seen.occurrences += 1;
    if (e.incident_id && !seen.case_refs.includes(e.incident_id)) {
      seen.case_refs.push(e.incident_id);
    }
    // Merging must never DISCARD evidence: an attribution asserted on any
    // persisted copy of this `event.iid` is a real assertion, so mitre /
    // labels are unioned and the strongest severity is kept.
    for (const m of e.mitre || []) {
      if (!(seen.mitre || []).includes(m)) seen.mitre = [...(seen.mitre || []), m];
    }
    for (const l of e.labels || []) {
      if (!(seen.labels || []).includes(l)) seen.labels = [...(seen.labels || []), l];
    }
    const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    if ((rank[e.severity] ?? 0) > (rank[seen.severity] ?? 0)) seen.severity = e.severity;
    if (!seen.command_line && e.command_line) seen.command_line = e.command_line;
    if (!seen.sha256 && e.sha256) seen.sha256 = e.sha256;
  }
  return out;
}

/** Actor of an observation — the process that performed it. */
export function actorOf(evt) {
  return evt.process || evt.title || null;
}

/** Target of an observation, as recorded. */
export function targetOf(evt) {
  if (PROCESS_KINDS.has(evt.observation_kind)) {
    return evt.path || evt.process || evt.title || null;
  }
  return evt.file || null;
}

/**
 * Build the canvas swimlanes.
 *
 * Group A — PROCESSES: one lifeline per observed process name.
 * Group B — ARTIFACTS & NETWORK: one lifeline per recorded target
 *           string (file path, registry key, remote endpoint).
 *
 * Every event is anchored on its actor row; non-process events are ALSO
 * anchored on their target row and the two anchors are joined by an
 * orthogonal connector, because both endpoints live in the same
 * observation document.
 */
export function buildSwimlanes(events) {
  const procRows = new Map();
  const artRows = new Map();

  const touch = (map, key, group, labelSource) => {
    let row = map.get(key);
    if (!row) {
      row = {
        key: `${group}:${key}`,
        group,
        label: key,
        tag: typeTag(labelSource || key),
        events: [],
        iocCount: 0,
        maliciousCount: 0,
        attributedCount: 0,
        first: null,
        last: null,
        processIids: [],
        parentClaims: [],
      };
      map.set(key, row);
    }
    return row;
  };

  const anchors = [];        // { evt, actorRowKey, targetRowKey }
  for (const e of events || []) {
    const t = tsOf(e);
    if (t === null) continue;
    const actorName = actorOf(e);
    if (!actorName) continue;
    const actorRow = touch(procRows, actorName, "process", e.path || actorName);
    actorRow.events.push(e);
    const tier = severityTier(e);
    if (tier >= TIER_ATTRIBUTED) actorRow.iocCount += 1;
    if (tier === TIER_MALICIOUS) actorRow.maliciousCount += 1;
    else if (tier === TIER_ATTRIBUTED) actorRow.attributedCount += 1;
    if (e.process_iid && !actorRow.processIids.includes(e.process_iid)) {
      actorRow.processIids.push(e.process_iid);
    }
    if (e.parent_iid && !actorRow.parentClaims.some((p) => p.iid === e.parent_iid)) {
      actorRow.parentClaims.push({ iid: e.parent_iid, name: e.parent_name || null });
    }
    if (actorRow.first === null || t < actorRow.first) actorRow.first = t;
    if (actorRow.last === null || t > actorRow.last) actorRow.last = t;

    let targetRowKey = null;
    const tgt = targetOf(e);
    if (!PROCESS_KINDS.has(e.observation_kind) && tgt) {
      const artRow = touch(artRows, tgt, "artifact", tgt);
      artRow.events.push(e);
      if (tier >= TIER_ATTRIBUTED) artRow.iocCount += 1;
      if (tier === TIER_MALICIOUS) artRow.maliciousCount += 1;
      else if (tier === TIER_ATTRIBUTED) artRow.attributedCount += 1;
      if (artRow.first === null || t < artRow.first) artRow.first = t;
      if (artRow.last === null || t > artRow.last) artRow.last = t;
      targetRowKey = artRow.key;
    }
    anchors.push({ evt: e, t, actorRowKey: actorRow.key, targetRowKey });
  }

  const sortRows = (m) => Array.from(m.values())
    .sort((a, b) => (a.first ?? 0) - (b.first ?? 0));

  return {
    processRows:  sortRows(procRows),
    artifactRows: sortRows(artRows),
    anchors,
  };
}

/**
 * Lineage resolvability report.  `resolved` edges are the only ones a
 * caller may draw.
 */
export function lineageStats(events) {
  const observed = new Set();
  for (const e of events || []) if (e.process_iid) observed.add(e.process_iid);
  const declared = [];
  const resolved = [];
  const unresolved = new Map();
  for (const e of events || []) {
    if (!e.parent_iid) continue;
    declared.push(e);
    if (observed.has(e.parent_iid)) {
      resolved.push({ child: e.process_iid, parent: e.parent_iid, evt: e });
    } else if (!unresolved.has(e.parent_iid)) {
      unresolved.set(e.parent_iid, e.parent_name || null);
    }
  }
  return {
    observedProcessIids: observed.size,
    declaredCount: declared.length,
    resolved,
    unresolvedParents: Array.from(unresolved, ([iid, name]) => ({ iid, name })),
  };
}

/**
 * Compromise spans — contiguous clusters of IOC-bearing observations.
 * Driven by the observations' own timestamps; never a guessed window.
 */
export function compromiseSpans(events, gapMs = 120000) {
  const ioc = (events || []).filter(isIoc)
    .map((e) => ({ e, t: tsOf(e) }))
    .filter((r) => r.t !== null)
    .sort((a, b) => a.t - b.t);
  const spans = [];
  for (const { e, t } of ioc) {
    const last = spans[spans.length - 1];
    if (last && t - last.end <= gapMs) {
      last.end = Math.max(last.end, t);
      last.events.push(e);
      for (const m of e.mitre || []) last.mitre.add(m);
      for (const c of e.case_refs || []) last.caseRefs.add(c);
    } else {
      spans.push({
        start: t, end: t, events: [e],
        mitre: new Set(e.mitre || []),
        caseRefs: new Set(e.case_refs || []),
      });
    }
  }
  return spans.map((s, i) => ({
    id: `span-${i}`,
    start: s.start,
    end: s.end,
    events: s.events,
    mitre: Array.from(s.mitre),
    caseRefs: Array.from(s.caseRefs),
  }));
}

/** Case references seen on this device, with resolvability unknown until
 *  the caller checks the incident plane. */
export function caseReferences(events) {
  const m = new Map();
  for (const e of events || []) {
    for (const c of (e.case_refs || (e.incident_id ? [e.incident_id] : []))) {
      if (!m.has(c)) m.set(c, { case_id: c, events: 0, ioc: 0, first: null, last: null });
      const row = m.get(c);
      row.events += 1;
      if (isIoc(e)) row.ioc += 1;
      const t = tsOf(e);
      if (t !== null) {
        if (row.first === null || t < row.first) row.first = t;
        if (row.last === null || t > row.last) row.last = t;
      }
    }
  }
  return Array.from(m.values()).sort((a, b) => (b.ioc - a.ioc) || (b.events - a.events));
}

export function fmtUtc(ms, withMs = false) {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "◇";
  const iso = new Date(ms).toISOString();
  return withMs ? iso.replace("T", " ").replace("Z", "Z") : iso.replace("T", " ").slice(0, 19) + "Z";
}

export function shortHash(h) {
  if (!h) return null;
  return h.length > 20 ? `${h.slice(0, 8)}…${h.slice(-8)}` : h;
}
