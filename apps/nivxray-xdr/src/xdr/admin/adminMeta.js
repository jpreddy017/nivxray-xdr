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
} from "lucide-react";

export const ADMIN_SECTIONS = [
  {
    key: "overview", label: "Overview", icon: LayoutGrid,
    subtitle: "Aggregate admin KPIs · deterministic counts from authoritative surfaces.",
    api: "/admin/stats", kind: "kv",
  },
  {
    key: "integrations", label: "Integrations", icon: Plug,
    subtitle: "OSINT enrichment services and TAXII feeds.",
    api: "/admin/osint/services", kind: "table",
    columns: [
      { k: "name",       label: "Service" },
      { k: "type",       label: "Type" },
      { k: "enabled",    label: "Enabled", render: (v) => v ? "YES" : "NO" },
      { k: "endpoint",   label: "Endpoint", mono: true },
      { k: "last_check", label: "Last Check", mono: true },
    ],
    empty: "No OSINT integrations wired for this tenant.",
  },
  {
    key: "data-sources", label: "Data Sources", icon: HardDrive,
    subtitle: "Reference sample datasets and canonical corpora.",
    api: "/admin/samples/dashboard", kind: "kv",
    empty: "No sample data sources catalogued.",
  },
  {
    key: "collectors", label: "Collectors", icon: Cpu,
    subtitle: "Endpoint / network / cloud collectors.",
    api: null, connected: false,
    integration: "Collector fleet manager",
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
    subtitle: "Ingest health · latency · error rate.",
    api: "/health/deep", kind: "kv",
    empty: "Deep-health probe reported no measurements.",
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
    subtitle: "Console users, roles, tenant scope.",
    api: "/admin/users", kind: "table",
    columns: [
      { k: "email",    label: "Email",     mono: true },
      { k: "role",     label: "Role" },
      { k: "tenant",   label: "Tenant",    mono: true },
      { k: "active",   label: "Active",    render: (v) => v ? "YES" : "NO" },
      { k: "last_login", label: "Last Login", mono: true },
    ],
    empty: "No console users returned.",
  },
  {
    key: "api-webhooks", label: "API / Webhooks", icon: Webhook,
    subtitle: "Outbound webhooks and API keys.",
    api: null, connected: false,
    integration: "Webhook + API-key service",
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
