/**
 * NxEntityIcon · the NivXRay-native icon family.
 *
 * OWNER DIRECTIVE: NivXRay's own concepts must NOT wear another vendor's
 * proprietary artwork. Cortex XDR's causality vocabulary and Microsoft
 * Defender XDR's graph node categories are used as SEMANTIC benchmarks —
 * i.e. which entity classes must be visually distinguishable, and how
 * clearly — and this family reproduces that clarity with our own glyphs.
 *
 * One glyph per concept, one tone per class, used everywhere that concept
 * appears (tables, flyouts, graphs, timelines), so an analyst learns the
 * vocabulary once.
 */
import React from "react";
import {
  Activity, AlertTriangle, Archive, Binary, Boxes, Braces, Clock,
  Cpu, Crosshair, Database, FileText, Fingerprint, Folder, Globe, HardDrive,
  KeyRound, Laptop, Lock, Mail, Network, Radar, Router, Search, Server,
  Shield, ShieldOff, Siren, Terminal, User, Users, Workflow,
} from "lucide-react";
import "./nx-vendor.css";

/** concept → { glyph, tone token, analyst label }. */
export const ENTITY_ICONS = {
  // ── security objects ──────────────────────────────────────────
  incident:      { I: Siren,        tone: "var(--nx-critical)", label: "Incident" },
  detection:     { I: Radar,        tone: "var(--nx-high)",     label: "Detection" },
  alert:         { I: AlertTriangle, tone: "var(--nx-high)",    label: "Alert" },
  investigation: { I: Search,       tone: "var(--nx-purple)",   label: "Investigation" },
  hunt:          { I: Crosshair,    tone: "var(--nx-purple)",   label: "Hunt" },
  finding:       { I: Fingerprint,  tone: "var(--nx-medium)",   label: "Finding" },
  evidence:      { I: Archive,      tone: "var(--nx-teal)",     label: "Evidence" },
  timeline:      { I: Clock,        tone: "var(--nx-low)",      label: "Timeline" },
  playbook:      { I: Workflow,     tone: "var(--nx-purple)",   label: "Playbook" },

  // ── entities (Defender-class graph categories, our artwork) ───
  device:        { I: Laptop,       tone: "var(--nx-low)",      label: "Device" },
  server:        { I: Server,       tone: "var(--nx-low)",      label: "Server" },
  collector:     { I: Router,       tone: "var(--nx-low)",      label: "Collector" },
  user:          { I: User,         tone: "var(--nx-purple)",   label: "User" },
  group:         { I: Users,        tone: "var(--nx-purple)",   label: "Group" },
  identity:      { I: KeyRound,     tone: "var(--nx-purple)",   label: "Identity" },
  process:       { I: Cpu,          tone: "var(--nx-medium)",   label: "Process" },
  command:       { I: Terminal,     tone: "var(--nx-medium)",   label: "Command line" },
  file:          { I: FileText,     tone: "var(--nx-text-dim)", label: "File" },
  folder:        { I: Folder,       tone: "var(--nx-text-dim)", label: "Folder" },
  hash:          { I: Binary,       tone: "var(--nx-text-dim)", label: "Hash" },
  ip:            { I: Network,      tone: "var(--nx-teal)",     label: "IP address" },
  domain:        { I: Globe,        tone: "var(--nx-teal)",     label: "Domain" },
  mail:          { I: Mail,         tone: "var(--nx-teal)",     label: "Mailbox" },
  registry:      { I: Braces,       tone: "var(--nx-text-dim)", label: "Registry" },
  data:          { I: Database,     tone: "var(--nx-text-dim)", label: "Data store" },
  volume:        { I: HardDrive,    tone: "var(--nx-text-dim)", label: "Volume" },
  telemetry:     { I: Activity,     tone: "var(--nx-low)",      label: "Telemetry" },
  datasource:    { I: Boxes,        tone: "var(--nx-low)",      label: "Data source" },

  // ── response verbs ────────────────────────────────────────────
  response:      { I: Shield,       tone: "var(--nx-benign)",   label: "Response" },
  isolate:       { I: ShieldOff,    tone: "var(--nx-critical)", label: "Isolate" },
  quarantine:    { I: Lock,         tone: "var(--nx-critical)", label: "Quarantine" },
  verify:        { I: Radar,        tone: "var(--nx-benign)",   label: "Verify" },
};

export default function NxEntityIcon({ kind, size = 14, boxed = false,
                                       label = false, testid }) {
  const key = String(kind || "").toLowerCase();
  const e = ENTITY_ICONS[key];
  if (!e) return null;
  const { I, tone } = e;
  const glyph = (
    <span className={`nx-ei${boxed ? " nx-ei--boxed" : ""}`}
          style={{ "--nx-ei-tone": tone }} aria-hidden="true"
          data-nx-entity={key}
          data-testid={testid || `nx-entity-icon-${key}`}>
      <I size={size} />
    </span>
  );
  if (!label) return glyph;
  return (
    <span className="nx-ei-wrap">
      {glyph}
      <span className="nx-ei-label">{e.label}</span>
    </span>
  );
}
