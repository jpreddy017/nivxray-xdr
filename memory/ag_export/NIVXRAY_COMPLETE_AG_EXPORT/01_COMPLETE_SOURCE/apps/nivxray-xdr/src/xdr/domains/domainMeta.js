/**
 * Domain taxonomy · Slice 7 (owner-locked).
 *
 * Every native XDR domain gets a stable key, a human label, and the
 * authoritative NivXRay backend surface that supplies its data.
 * A domain that has no authoritative surface renders `NOT CONNECTED`
 * honestly and links to Administration → Integrations — never a
 * fake populated screen.
 *
 * Quality bar (locked): more explainable than Defender's opaque
 * "1 alert" chip, more precise than Falcon's generic "no data".
 * Each state carries provenance.
 */
import { Cpu, Fingerprint, FileText, Wifi, Mail, Cloud } from "lucide-react";

export const DOMAIN_KEYS = ["endpoints","identity","files","network","email","cloud"];

export const DOMAIN_META = {
  endpoints: {
    key:      "endpoints",
    label:    "Endpoints",
    subtitle: "Forge EDR · process · file · registry · trajectory",
    icon:     Cpu,
    // Consumed by domain page + card summariser.  READ-ONLY.
    api:      "/edr/device-trajectory",
    connected: true,
  },
  identity: {
    key:      "identity",
    label:    "Identity",
    subtitle: "ITDR · authentication · privilege",
    icon:     Fingerprint,
    api:      null, // not wired — renders NOT CONNECTED honestly
    connected: false,
    integration: "Identity provider (Entra ID / Okta / AD)",
  },
  files: {
    key:      "files",
    label:    "Files",
    subtitle: "Artifact intelligence · IUE Lane C",
    icon:     FileText,
    api:      "/edr/detections",
    connected: true,
  },
  network: {
    key:      "network",
    label:    "Network",
    subtitle: "NDR · DNS · flow · beacon",
    icon:     Wifi,
    api:      null,
    connected: false,
    integration: "Network sensor (Zeek / NDR appliance)",
  },
  email: {
    key:      "email",
    label:    "Email",
    subtitle: "Message · sender · attachment · URL",
    icon:     Mail,
    api:      null,
    connected: false,
    integration: "Email security (M365 / Google Workspace)",
  },
  cloud: {
    key:      "cloud",
    label:    "Cloud",
    subtitle: "IaaS / SaaS control plane · CASB",
    icon:     Cloud,
    api:      null,
    connected: false,
    integration: "Cloud provider (AWS / Azure / GCP)",
  },
};

/**
 * `deriveDomainState(domain, ctx)` — pure, deterministic mapping.
 * ctx: { detectionCount, hasHost, hasIocs }.
 *
 *   RELATED       → real evidence count > 0
 *   SEARCHED      → connected but no hits in the incident window
 *   NOT CONNECTED → integration not wired for the tenant
 */
export function deriveDomainState(domain, ctx = {}) {
  const meta = DOMAIN_META[domain];
  if (!meta || !meta.connected) return "not_connected";
  const n = ctx.detectionCount || 0;
  if (n > 0) return "related";
  return "searched";
}
