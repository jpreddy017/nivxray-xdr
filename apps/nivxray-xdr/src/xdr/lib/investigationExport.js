/**
 * Investigation Export · P1.9
 *
 * Client-side only.  No server state, no object storage, no export-event
 * collection, no new endpoints — an export is built from data already on
 * the page and handed straight to the browser.
 *
 * The export is an EVIDENCE MANIFEST, not a narrative:
 *   1. the export contract and mode,
 *   2. the exact scope predicate that produced the rows,
 *   3. count reconciliation (unique evidence events vs raw observations),
 *   4. the evidence rows under a fixed field allowlist,
 *   5. the honest-state limitations, verbatim, so the epistemic tokens
 *      survive outside the UI,
 *   6. a self-contained SHA-256 over the canonical payload.
 *
 * Mode: SOC / INTERNAL FORENSIC EXPORT.  Forensic fields (usernames,
 * hostnames, paths, IPs, command lines) are PRESERVED — deterministic
 * external sanitisation is a separate future capability.  Secrets are
 * never preserved: high-confidence credential material inside a command
 * line is replaced with a labelled marker and counted in the manifest.
 */

export const EXPORT_MODE = "SOC / INTERNAL FORENSIC EXPORT";
export const EXPORT_CONTRACT_VERSION = "nivxray.investigation-export/1.0";

/** Fields deliberately defined by the export contract. Nothing else leaves. */
export const EVENT_FIELDS = [
  "event_iid", "timestamp", "device_iid", "hostname", "observation_kind",
  "process", "process_iid", "parent_iid", "parent_name", "image_path",
  "target", "file_sha256", "user", "command_line", "provider", "event_id",
  "rule_label", "adapter", "mitre", "labels", "case_refs", "raw_copies",
  "matched_on", "observation_record_digest",
];

export const EXCLUDED_BY_CONTRACT = [
  "passwords, secrets, API keys, access/session tokens, cookies",
  "private keys and certificate private material",
  "authorization headers and authentication material",
  "credentials embedded in command lines or URLs (replaced with a marker)",
  "internal application/session identifiers not required for correlation",
  "raw database documents, _id values and internal implementation metadata",
  "tenant-internal security configuration",
  "any data outside the stated scope predicate",
  "internal debugging traces and engine internals",
];

export const HONEST_STATE_LIMITATIONS = [
  "DISPOSITION: not carried by v2_shadow_observations. Nothing is inferred from severity.",
  "PROCESS LINEAGE: parent_iid references do not resolve to observed process_iid values; no lineage edge is asserted (? PARENT NOT OBSERVED).",
  "PID / PPID: not captured in this substrate.",
  "FILE CONTENT IDENTITY: artefacts.file[].sha256 is unpopulated; file identity is UNVERIFIED. Name/path correlation is CONTENT-BLIND.",
  "OBSERVATION RECORD DIGEST: digests the ingested observation record (== input_sha256). It is an evidence-integrity digest, NOT a file hash.",
  "ORIGIN: the earliest record is the EARLIEST OBSERVED HOST only. Initial access and patient zero are NOT established.",
  "ATTACK WINDOW: the observed window is not the attack window. True start and end are UNKNOWN; telemetry may begin after compromise.",
  "CROSS-HOST CAUSALITY: not established. The same name/path on several endpoints is a COHORT, never a lateral-movement edge.",
  "OBJECTIVE: not established. No objective is derived from a family name or a technique tag.",
  "ATT&CK: techniques are assertions carried by the ingest adapter, not re-derived at export time.",
  "CASE REFERENCES: case_ids carried by the substrate that have no persisted incident record are marked NOT PERSISTED.",
  "RESPONSE: no response driver is registered; no containment action was available or taken.",
  "ATTACK TRAVERSAL / LIFECYCLE: not implemented. No traversal, blast radius or lifecycle claim appears in this export.",
  "TENANT: v2_shadow_observations carries no tenant_id. This is validation / golden-corpus substrate visibility only.",
];

/** High-confidence credential patterns only — forensic text is otherwise kept. */
const SECRET_PATTERNS = [
  /(-{1,2}(?:password|passwd|pwd|secret|apikey|api[-_]?key|token)\s*[:=]?\s*)("[^"]*"|'[^']*'|\S+)/gi,
  /((?:password|passwd|pwd|secret|api[-_]?key|access[-_]?token|bearer)\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)/gi,
  /(:\/\/[^\s/:@]+:)([^\s@]+)(@)/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

export function scrubSecrets(text) {
  if (!text) return { value: text ?? null, redactions: 0 };
  let out = String(text);
  let n = 0;
  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, (m, a, b, c) => {
      n += 1;
      if (a === undefined) return "[REDACTED:PRIVATE_KEY]";
      return `${a}[REDACTED:SECRET]${c || ""}`;
    });
  }
  return { value: out, redactions: n };
}

/** Project one observation onto the contract's field allowlist. */
function projectEvent(e, redactionCounter) {
  const cmd = scrubSecrets(e.command_line);
  redactionCounter.count += cmd.redactions;
  return {
    event_iid:   e.event_iid || e.evidence_ref?.event_iid || e.id || null,
    timestamp:   e.timestamp || null,
    device_iid:  e.device_iid || e.device || null,
    hostname:    e.hostname || null,
    observation_kind: e.observation_kind || e.kind || null,
    process:     e.process || null,
    process_iid: e.process_iid || null,
    parent_iid:  e.parent_iid || null,
    parent_name: e.parent_name || null,
    image_path:  e.path || e.process_image || null,
    target:      e.file || e.target || (e.file_paths || [])[0] || null,
    file_sha256: e.file_sha256 || null,
    user:        e.user || null,
    command_line: cmd.value,
    provider:    e.provider || null,
    event_id:    e.event_id ?? null,
    rule_label:  e.rule_label || null,
    adapter:     e.adapter || null,
    mitre:       e.mitre || [],
    labels:      e.labels || [],
    case_refs:   e.case_refs || (e.incident_id ? [e.incident_id] : []),
    raw_copies:  e.occurrences ?? null,
    matched_on:  e.matched_on || null,
    observation_record_digest: e.input_digest || null,
  };
}

async function sha256Hex(text) {
  if (!window.crypto?.subtle) return null;
  const d = await window.crypto.subtle.digest("SHA-256",
                                              new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d))
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Stable key order so the digest is reproducible. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

/**
 * Build the export package.
 *
 * @param {object} a
 * @param {string} a.surface        "device_trajectory" | "fleet_file_trajectory"
 * @param {object} a.scope          the exact predicate that produced the rows
 * @param {Array}  a.events         the rows already on screen
 * @param {object} a.counts         { unique_events, raw_observations, ... }
 * @param {Array}  a.endpoints      optional per-endpoint rollup
 * @param {Array}  a.notes          optional surface-specific caveats
 * @param {string} a.exportedBy
 */
export async function buildExport({ surface, scope, events, counts,
                                    endpoints = null, notes = [], exportedBy }) {
  const redactionCounter = { count: 0 };
  const rows = (events || []).map((e) => projectEvent(e, redactionCounter));
  const payload = {
    surface,
    exported_at: new Date().toISOString(),
    exported_by: exportedBy || null,
    substrate: "v2_shadow_observations",
    mode: EXPORT_MODE,
    scope,
    counts: {
      ...counts,
      exported_rows: rows.length,
      reconciliation: `${rows.length} exported rows == unique evidence events in scope`
        + (counts?.raw_observations != null
            ? ` · ${counts.raw_observations} raw observations (provenance copies) are reported, not exported as separate rows`
            : ""),
    },
    secret_redactions: redactionCounter.count,
    surface_notes: notes,
    endpoints,
    events: rows,
    limitations: HONEST_STATE_LIMITATIONS,
    excluded_by_contract: EXCLUDED_BY_CONTRACT,
    field_allowlist: EVENT_FIELDS,
  };
  const digest = await sha256Hex(canonical(payload));
  return {
    contract: EXPORT_CONTRACT_VERSION,
    integrity: {
      algorithm: "SHA-256",
      canonicalisation: "sorted-key JSON of the payload object",
      payload_sha256: digest,
      note: digest
        ? "Recompute over the canonical payload to verify this export was not altered."
        : "⊘ DIGEST UNAVAILABLE — SubtleCrypto requires a secure context.",
    },
    payload,
  };
}

/* ── serialisers ─────────────────────────────────────────────────── */

export function toJson(pkg) {
  return JSON.stringify(pkg, null, 2);
}

const mdEsc = (v) => String(v ?? "◇").replace(/\|/g, "\\|");

export function toMarkdown(pkg) {
  const p = pkg.payload;
  const L = [];
  L.push(`# NivXRay Investigation Export — ${p.surface.replace(/_/g, " ")}`);
  L.push("");
  L.push(`**Mode:** ${p.mode}  `);
  L.push(`**Contract:** ${pkg.contract}  `);
  L.push(`**Exported at:** ${p.exported_at}  `);
  L.push(`**Exported by:** ${p.exported_by || "◇ unknown"}  `);
  L.push(`**Substrate:** ${p.substrate}  `);
  L.push(`**Payload SHA-256:** \`${pkg.integrity.payload_sha256 || "⊘ unavailable"}\`  `);
  L.push("");
  L.push("## Scope predicate");
  L.push("");
  for (const [k, v] of Object.entries(p.scope || {})) {
    L.push(`- **${k}**: \`${Array.isArray(v) ? v.join(", ") || "—" : String(v ?? "—")}\``);
  }
  L.push("");
  L.push("## Count reconciliation");
  L.push("");
  for (const [k, v] of Object.entries(p.counts || {})) {
    L.push(`- **${k}**: ${Array.isArray(v) ? v.join(", ") : String(v)}`);
  }
  if (p.secret_redactions > 0) {
    L.push(`- **secret_redactions**: ${p.secret_redactions} credential fragment(s) replaced with \`[REDACTED:SECRET]\``);
  }
  L.push("");
  if (p.surface_notes?.length) {
    L.push("## Surface notes");
    L.push("");
    for (const n of p.surface_notes) L.push(`- ${n}`);
    L.push("");
  }
  if (p.endpoints?.length) {
    L.push("## Endpoints in scope");
    L.push("");
    L.push("| Endpoint | device_iid | Unique events | Raw obs. | First seen | Last seen |");
    L.push("|---|---|---|---|---|---|");
    for (const r of p.endpoints) {
      L.push(`| ${mdEsc(r.hostname)} | ${mdEsc(r.device_iid)} | ${r.unique_events ?? "◇"} `
        + `| ${r.raw_observations ?? "◇"} | ${mdEsc(r.first_seen)} | ${mdEsc(r.last_seen)} |`);
    }
    L.push("");
  }
  L.push("## Evidence");
  L.push("");
  L.push("| Timestamp (UTC) | Endpoint | Kind | Actor | Target | ATT&CK | Disposition | event_iid |");
  L.push("|---|---|---|---|---|---|---|---|");
  for (const e of p.events) {
    L.push(`| ${mdEsc(e.timestamp)} | ${mdEsc(e.hostname || e.device_iid)} `
      + `| ${mdEsc(e.observation_kind)} | ${mdEsc(e.process)} | ${mdEsc(e.target)} `
      + `| ${(e.mitre || []).join(", ") || "◇"} | ? UNKNOWN | \`${mdEsc(e.event_iid)}\` |`);
  }
  L.push("");
  L.push("### Per-event detail");
  L.push("");
  for (const e of p.events) {
    L.push(`#### \`${e.event_iid}\` · ${e.timestamp}`);
    L.push("");
    for (const f of EVENT_FIELDS) {
      const v = e[f];
      const shown = Array.isArray(v) ? (v.join(", ") || "◇ none") : (v ?? "◇ not observed");
      L.push(`- **${f}**: ${typeof shown === "string" ? shown : String(shown)}`);
    }
    L.push("");
  }
  L.push("## What this export does NOT establish");
  L.push("");
  for (const l of p.limitations) L.push(`- ${l}`);
  L.push("");
  L.push("## Excluded by the export contract");
  L.push("");
  for (const l of p.excluded_by_contract) L.push(`- ${l}`);
  L.push("");
  return L.join("\n");
}

const csvCell = (v) => {
  const s = Array.isArray(v) ? v.join(" ") : (v ?? "");
  return /[",\n]/.test(String(s)) ? `"${String(s).replace(/"/g, '""')}"` : String(s);
};

export function toCsv(pkg) {
  const p = pkg.payload;
  const head = [
    `# ${pkg.contract} · ${p.mode}`,
    `# exported_at=${p.exported_at} exported_by=${p.exported_by || ""}`,
    `# scope=${canonical(p.scope).replace(/\n/g, " ")}`,
    `# payload_sha256=${pkg.integrity.payload_sha256 || "unavailable"}`,
    `# unique_evidence_events=${p.counts.exported_rows} raw_observations=${p.counts.raw_observations ?? ""}`,
    "# disposition is UNKNOWN for every row: the substrate carries no disposition field",
  ];
  const rows = [EVENT_FIELDS.join(",")];
  for (const e of p.events) rows.push(EVENT_FIELDS.map((f) => csvCell(e[f])).join(","));
  return `${head.join("\n")}\n${rows.join("\n")}\n`;
}

export function download(filename, text, mime) {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

export function slug(s) {
  return String(s || "export").replace(/[^a-zA-Z0-9._-]+/g, "-").slice(0, 60);
}
