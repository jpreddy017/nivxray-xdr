/**
 * processAncestry · P1.2 · deterministic in-memory DAG projection.
 *
 * Projects process observations into a lineage graph.  No new store,
 * no synthetic graph, no fabricated ancestor.
 *
 * SUBSTRATE REALITY (verified 2026-09-05 against all 7 devices /
 * 114 process observations):
 *   • `raw.pid` and `raw.ppid` DO NOT EXIST anywhere in
 *     v2_shadow_observations — 0 documents carry either field.
 *   • Lineage is expressed ONLY as `process.parent_iid → process.iid`.
 *   • ZERO parent_iids currently resolve to an observed process, on
 *     every device.  So today every process is an orphan root.
 *
 * Consequences, stated rather than hidden:
 *   • The DIRECT_IID branch is implemented and is the authoritative
 *     path; it will light up the moment lineage-complete telemetry
 *     lands.
 *   • The PPID temporal-match and PID-reuse (UNCERTAIN_RELATIONSHIP)
 *     branches are implemented to contract but are UNREACHABLE with
 *     this substrate, because no PID/PPID is captured.  They are not
 *     simulated.
 *   • `parent_name` (e.g. "explorer.exe") IS persisted — but on the
 *     CHILD's record.  It is the child's claim about its parent, not an
 *     independent observation of that parent.  It is therefore surfaced
 *     as INFERRED_FROM_CHILD and never promoted into an observed node.
 */

export const EP = {
  PRESENT:   "EVIDENCE_PRESENT",
  ROOT_NOBS: "ROOT_PARENT_NOT_OBSERVED",
  UNCERTAIN: "UNCERTAIN_RELATIONSHIP",
};

const REL = {
  DIRECT:    "DIRECT_IID",
  PPID:      "MATCHED_PPID",
  COLLISION: "UNCERTAIN_PID_COLLISION",
};

function nodeFrom(e) {
  return {
    id:              e.process_iid,
    label:           e.process || "◇ PROCESS NAME NOT CAPTURED",
    // No PID/PPID exists in this substrate — never invent one.
    pid:             Number.isFinite(e.pid) ? e.pid : null,
    ppid:            Number.isFinite(e.ppid) ? e.ppid : null,
    timestamp:       e.timestamp,
    user:            e.user || null,
    commandLine:     e.command_line || null,
    executablePath:  e.path || null,
    sha256:          e.sha256 || null,
    sourceCase:      e.incident_id || null,
    observationIid:  e.evidence_ref?.event_iid || null,
    deviceIid:       e.device_iid || null,
    mitre:           e.mitre || [],
    parentIid:       e.parent_iid || null,
    /** Claimed by the child record, not independently observed. */
    claimedParentName: e.parent_name || null,
    epistemicState:  EP.PRESENT,
    isSyntheticRoot: false,
    evidenceRef:     e.evidence_ref || null,
    eventId:         e.id,
  };
}

export function buildProcessAncestryDAG(events) {
  const procEvents = (events || []).filter(
    (e) => e.observation_kind === "process_create" && e.process_iid);

  const nodes = new Map();
  const edges = [];
  const iidMap = new Map();
  const pidMap = new Map();

  // ── Pass 1 · entity registration ────────────────────────────────
  // The same process is persisted once per case copy in the golden
  // corpus, so collapse on process_iid and keep the case list.
  for (const e of procEvents) {
    const existing = nodes.get(e.process_iid);
    if (existing) {
      if (e.incident_id && !existing.sourceCases.includes(e.incident_id)) {
        existing.sourceCases.push(e.incident_id);
      }
      continue;
    }
    const n = nodeFrom(e);
    n.sourceCases = e.incident_id ? [e.incident_id] : [];
    nodes.set(n.id, n);
    iidMap.set(n.id, n);
    if (n.pid !== null) {
      if (!pidMap.has(n.pid)) pidMap.set(n.pid, []);
      pidMap.get(n.pid).push(n);
    }
  }

  for (const list of pidMap.values()) {
    list.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  }

  // ── Pass 2 · deterministic edge linking ─────────────────────────
  for (const child of Array.from(nodes.values())) {
    if (child.isSyntheticRoot) continue;
    const childTime = new Date(child.timestamp).getTime();

    // 2A · authoritative: parent_iid resolves to an observed process.
    if (child.parentIid && iidMap.has(child.parentIid)) {
      edges.push({
        id: `edge_${child.parentIid}->${child.id}`,
        source: child.parentIid, target: child.id,
        relationType: REL.DIRECT, isDotted: false,
      });
      continue;
    }

    // 2B · fallback: PPID → an observed PID at or before child time.
    //      Unreachable today (no PID/PPID captured); kept to contract.
    if (child.ppid !== null && pidMap.has(child.ppid)) {
      const cands = pidMap.get(child.ppid).filter(
        (c) => new Date(c.timestamp).getTime() <= childTime && c.id !== child.id);
      if (cands.length === 1) {
        edges.push({
          id: `edge_${cands[0].id}->${child.id}`,
          source: cands[0].id, target: child.id,
          relationType: REL.PPID, isDotted: false,
        });
        continue;
      }
      if (cands.length > 1) {
        const nearest = cands[cands.length - 1];
        child.epistemicState = EP.UNCERTAIN;
        edges.push({
          id: `edge_${nearest.id}->${child.id}`,
          source: nearest.id, target: child.id,
          relationType: REL.COLLISION, isDotted: true,
        });
        continue;
      }
    }

    // 2C · zero-fabrication anchor.  Keyed on whatever identity the
    //      child actually recorded — parent_iid here, PPID if a future
    //      substrate captures one.  Never on a guessed binary name.
    const key = child.parentIid || (child.ppid !== null ? `ppid_${child.ppid}` : null);
    if (!key) continue;
    const rootId = `unobserved_parent_${key}`;
    if (!nodes.has(rootId)) {
      nodes.set(rootId, {
        id: rootId,
        label: child.ppid !== null && !child.parentIid
          ? `[ROOT / PARENT NOT OBSERVED (PPID: ${child.ppid})]`
          : `[ROOT / PARENT NOT OBSERVED · ${child.parentIid}]`,
        pid: child.ppid ?? null,
        ppid: null,
        timestamp: child.timestamp,
        user: null,
        commandLine: null,
        executablePath: null,
        sha256: null,
        sourceCase: null,
        sourceCases: [],
        observationIid: null,
        deviceIid: child.deviceIid,
        mitre: [],
        parentIid: null,
        /** Surfaced as a claim, never as an observed node label. */
        claimedParentName: child.claimedParentName || null,
        epistemicState: EP.ROOT_NOBS,
        isSyntheticRoot: true,
        evidenceRef: null,
        eventId: null,
      });
    }
    edges.push({
      id: `edge_${rootId}->${child.id}`,
      source: rootId, target: child.id,
      relationType: REL.PPID, isDotted: true,
    });
  }

  return { nodes: Array.from(nodes.values()), edges };
}

/** Layered top-down layout. Depth = distance from a root. */
export function layoutDAG({ nodes, edges }) {
  const childrenOf = new Map();
  const parentOf = new Map();
  for (const e of edges) {
    if (!childrenOf.has(e.source)) childrenOf.set(e.source, []);
    childrenOf.get(e.source).push(e.target);
    parentOf.set(e.target, e.source);
  }
  const roots = nodes.filter((n) => !parentOf.has(n.id)).map((n) => n.id);
  const depth = new Map();
  const order = [];
  const seen = new Set();

  const walk = (id, d) => {
    if (seen.has(id)) return;
    seen.add(id);
    depth.set(id, d);
    order.push(id);
    for (const c of (childrenOf.get(id) || [])) walk(c, d + 1);
  };
  roots.forEach((r) => walk(r, 0));
  // Any node in a cycle or orphaned by a missing source still renders.
  nodes.forEach((n) => walk(n.id, depth.get(n.id) ?? 0));

  const byId = new Map(nodes.map((n) => [n.id, n]));
  return {
    order: order.map((id) => byId.get(id)).filter(Boolean),
    depth,
    childrenOf,
    parentOf,
    rootCount: roots.length,
  };
}
