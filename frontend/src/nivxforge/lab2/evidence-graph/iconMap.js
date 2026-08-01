import {
  FileText, Terminal, Globe, Link2, Hash, Crosshair, Wrench, Activity,
  AlertTriangle, Package, KeyRound, ShieldAlert, Database, Cpu, Mail,
  Network, ScrollText, HardDrive, Fingerprint, Layers, Zap, Search,
  Radio, Bug, FileCode
} from "lucide-react";

/**
 * Semantic icon per CIO node kind + IOC sub-type. Additions to this map are
 * the only place where new node visuals should live — every projection
 * consults iconFor(node) and receives a consistent glyph.
 */
export function iconFor(node) {
  const kind = (node?.kind || node?.data?.kind || "").toLowerCase();
  const sub = (node?.attrs?.ioc_kind || node?.data?.subKind || node?.subKind || "").toLowerCase();

  if (kind === "artifact" || kind === "seed" || kind === "input") return FileText;
  if (kind === "decoded_fragment" || kind === "decode_layer") return Terminal;
  if (kind === "command" || kind === "script") return ScrollText;
  if (kind === "ioc") {
    if (sub.includes("url") || sub.includes("domain")) return Globe;
    if (sub.includes("ip") || sub.includes("host")) return Network;
    if (sub.includes("email")) return Mail;
    if (sub.includes("md5") || sub.includes("sha") || sub.includes("hash")) return Hash;
    if (sub.includes("bitcoin") || sub.includes("wallet")) return KeyRound;
    return Link2;
  }
  if (kind === "mitre_technique" || kind === "mitre" || kind === "attack_technique") return Crosshair;
  if (kind === "lolbin" || kind === "lolbas") return Wrench;
  if (kind === "behaviour" || kind === "behavior") return Activity;
  if (kind === "verdict") return AlertTriangle;
  if (kind === "archive" || kind === "container") return Package;
  if (kind === "credential") return KeyRound;
  if (kind === "detection" || kind === "rule") return ShieldAlert;
  if (kind === "database") return Database;
  if (kind === "process") return Cpu;
  if (kind === "file") return HardDrive;
  if (kind === "fingerprint" || kind === "yara") return Fingerprint;
  if (kind === "family" || kind === "malware_family") return Bug;
  if (kind === "network") return Radio;
  if (kind === "shellcode") return Zap;
  if (kind === "layer") return Layers;
  if (kind === "search" || kind === "recon") return Search;
  if (kind === "code" || kind === "script_fragment") return FileCode;
  return Layers;
}

// Tone token derived from severity/weight/class so downstream node styles
// only need to read one field.
export function toneFor(node) {
  const cls = (node?.class || node?.data?.class || node?.attrs?.severity || "").toLowerCase();
  if (cls === "critical" || cls === "crit") return "critical";
  if (cls === "high") return "high";
  if (cls === "medium" || cls === "med") return "medium";
  if (cls === "low") return "low";
  if (cls === "mitigating") return "mitigating";
  return "context";
}
