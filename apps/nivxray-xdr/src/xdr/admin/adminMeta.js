/**
 * Admin section taxonomy · Slice 10 (owner-locked).
 *
 * 14 native XDR admin surfaces, each with:
 *   • real route (/xdr/admin/:key)
 *   • authoritative API to consume (or `null` → NOT CONNECTED)
 *   • row shape describing what the native XDR renderer expects
 *   • honest fallback state when the API returns nothing
 *
 * Guardrail: never deep-link to base NivXRay `/admin` UI.  Every
 * surface reads authoritative APIs and renders natively in XDR.
 */
import {
  LayoutGrid, Plug, HardDrive, Cpu, Wifi, Sliders, Activity as ActivityIcon,
  Filter, Shuffle, Zap, ArrowRightLeft, Users, Webhook, HeartPulse,
  Boxes, FolderTree, Radar, PlusCircle, ShieldCheck, KeyRound, Package,
} from "lucide-react";

export const ADMIN_SECTIONS = [
  {
    key: "overview", label: "Overview", icon: LayoutGrid,
    subtitle: "Aggregate admin KPIs · deterministic counts from authoritative surfaces.",
    api: "/admin/stats", kind: "kv",
  },
  {
    key: "audit-log", label: "Audit Log", icon: ShieldCheck,
    subtitle: "Append-only tamper-evident audit trail · HMAC-signed chain · tenant-scoped · every enterprise write must emit here.",
    api: null, kind: "audit_log", connected: true,
  },
  {
    key: "secrets", label: "Secrets Store", icon: KeyRound,
    subtitle: "Server-side encrypted secrets · per-tenant DEK · masked reads · explicit reveal · every mutation audit-logged.",
    api: null, kind: "secrets", connected: true,
  },
  {
    key: "content-pack-lolbas", label: "Content Pack · LOLBAS", icon: Package,
    subtitle: "Phase A · 100% upstream synchronization · 10-stage pipeline (discover→download→parse→validate→normalize→index→primitives→ATT&CK→regression→complete) · deterministic evidence generation · every mutation audit-logged.",
    api: null, kind: "content_pack_lolbas", connected: true,
  },
  {
    key: "capability-hub", label: "Capability Hub", icon: PlusCircle,
    subtitle: "Plug-and-play extension registry · Install → Configure → Test → Enable · every capability is a validated manifest, never uploaded code.",
    api: null, kind: "capability_hub", connected: true,
  },
  {
    key: "detection-content", label: "Detection Content", icon: Radar,
    subtitle: "Rules · Pattern Rules · LOLBAS · ATT&CK coverage · every entry contributes evidence to the deterministic Verdict engine.",
    api: null, kind: "detection_content", connected: true,
  },
  {
    key: "engines", label: "Engines", icon: Boxes,
    subtitle: "Inventory of every NivXRay engine XDR consumes · adopt-before-invent registry + architecture diagram.",
    api: null, kind: "engines", connected: true,
  },
  {
    key: "corpus", label: "Investigation Corpus", icon: FolderTree,
    subtitle: "Eight-category scenario corpus · every scenario exercises evidence → correlation → verdict → severity → recommendation → playbook → report.",
    api: null, kind: "corpus", connected: true,
  },
  {
    key: "integrations", label: "Integrations", icon: Plug,
    subtitle: "Connect telemetry sources — every source flows through the same ingestion pipeline into canonical evidence.",
    api: "/admin/osint/services", kind: "integrations",
    empty: "No telemetry sources connected for this tenant.",
  },
  {
    key: "data-sources", label: "Data Sources", icon: HardDrive,
    subtitle: "Native NivXRay data-source control plane · RBAC-gated, audit-tracked, evidence-backed state.",
    api: null, kind: "data_sources_native", connected: true,
    empty: "No data sources configured for this tenant yet.",
    payloadKey: "data_sources",
  },
  {
    key: "collectors", label: "Collectors", icon: Cpu,
    subtitle: "Collector control plane · protocol registry (IMPLEMENTED / SCAFFOLD / BLOCKED) · CONNECTED only after real telemetry.",
    api: null, kind: "collectors_native", connected: true,
    empty: "No collectors provisioned for this tenant yet.",
    payloadKey: "collectors",
  },
  {
    key: "agents", label: "Agents", icon: Wifi,
    subtitle: "Deployed agent inventory · version · health.",
    api: null, connected: false,
    integration: "Agent management plane",
  },
  {
    key: "telemetry-studio", label: "Telemetry Studio", icon: Sliders,
    subtitle: "LLM-assisted decoding telemetry configuration.",
    api: "/admin/llm-telemetry", kind: "kv",
    empty: "No telemetry configuration recorded.",
  },
  {
    key: "telemetry-health", label: "Telemetry Health", icon: ActivityIcon,
    subtitle: "Per-source health · reported by every connector in the XDR Collector fleet.",
    api: "collector:/telemetry-health", kind: "table",
    columns: [
      { k: "source_type", label: "Source" },
      { k: "health",      label: "Health" },
      { k: "instances",   label: "Instances", mono: true },
      { k: "note",        label: "Note" },
    ],
    empty: "Collector runtime reported no health rows.",
    payloadKey: "rows",
  },
  {
    key: "parsers", label: "Parsers", icon: Filter,
    subtitle: "Raw event parsers per source type.",
    api: null, connected: false,
    integration: "Parser registry service",
  },
  {
    key: "normalization", label: "Normalization", icon: Shuffle,
    subtitle: "OCSF / ECS mapping and field normalisation.",
    api: null, connected: false,
    integration: "Normalisation pipeline",
  },
  {
    key: "detection-rules", label: "Detection Rules", icon: Zap,
    subtitle: "Rule inventory · Stage-2 verdict weights.",
    api: "/admin/models", kind: "table",
    columns: [
      { k: "provider", label: "Provider" },
      { k: "name",     label: "Model / Rule" },
      { k: "role",     label: "Role" },
      { k: "enabled",  label: "Enabled", render: (v) => v ? "YES" : "NO" },
    ],
    empty: "No detection models catalogued.",
  },
  {
    key: "response-policies", label: "Response Policies", icon: ArrowRightLeft,
    subtitle: "Per-tenant approval + auto-response policies.",
    api: null, connected: false,
    integration: "Response Policy engine (arrives with Slice 11)",
  },
  {
    key: "users-roles", label: "Users & Roles", icon: Users,
    subtitle: "Enterprise RBAC · users · custom + built-in roles (L1/L2/L3/SME/Manager/Admin/Auditor) · granular resource×action permissions · access simulator · every mutation audit-logged and server-enforced.",
    api: null, kind: "users_roles", connected: true,
  },
  {
    key: "api-keys", label: "API Keys", icon: KeyRound,
    subtitle: "Programmatic access tokens · hashed server-side (SHA-256) · plaintext revealed once at create/rotate · scoped by permission · expiration · rotate · revoke · every mutation audit-logged and RBAC-gated.",
    api: null, kind: "api_keys", connected: true,
  },
  {
    key: "api-webhooks", label: "Webhooks", icon: Webhook,
    subtitle: "Outbound webhooks · HMAC-SHA256 signed · secret via P0-2 Secrets Store · retry/backoff/DLQ · replay · delivery states PENDING/DELIVERING/DELIVERED/RETRYING/FAILED/DLQ (DELIVERED requires an actual 2xx response) · RBAC-gated · audit-logged.",
    api: null, kind: "webhooks", connected: true,
  },
  {
    key: "platform-health", label: "Platform Health", icon: HeartPulse,
    subtitle: "Backend liveness, DB, decoder registry.",
    api: "/health", kind: "kv",
    empty: "Backend health probe returned no fields.",
  },
];

export const ADMIN_BY_KEY = Object.fromEntries(
  ADMIN_SECTIONS.map((s) => [s.key, s]),
);
