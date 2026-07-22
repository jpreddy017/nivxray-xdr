/**
 * PreviewCommandHub — Feb 2026 design preview.
 *
 * Standalone evaluation page at `/preview/command-hub`. NOT wired into
 * production nav. All data is illustrative — the sole purpose of this
 * page is to let the user validate the SOC "Command Center" layout
 * (flow diagram + KPI row + trend / MITRE / feed / health cards)
 * before we decide whether to promote it as the canonical Dashboard.
 */
import { useState } from "react";
import {
  Search, Bell, Calendar, LayoutGrid, BarChart3, Shield, Target,
  BookOpen, Radar, Package, ScrollText, Puzzle, Cog, ChevronDown,
  Activity, ArrowUp, ArrowDown,
} from "lucide-react";

// ─── Design tokens ───────────────────────────────────────────────────
const T = {
  bg1:     "#040814",
  bg2:     "#080f22",
  surface: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.90))",
  border:  "rgba(148,163,184,0.14)",
  text:    "#e2e8f0",
  dim:     "rgba(203,213,225,0.72)",
  mute:    "rgba(148,163,184,0.55)",
  cyan:    "#22d3ee",
  green:   "#22c55e",
  amber:   "#f59e0b",
  red:     "#ef4444",
  violet:  "#8b5cf6",
  pink:    "#ec4899",
  font:    '"Chivo", ui-sans-serif, system-ui, sans-serif',
  mono:    'JetBrains Mono, ui-monospace, monospace',
};

const KPI = [
  { key: "total",  label: "Total Analyses",     value: 4782, delta: 12.4, up: true,  color: T.cyan,   spark: [12,15,14,18,22,25,28,26,30,29,32,34,33,36,38] },
  { key: "malic",  label: "Malicious Detected", value: 1248, delta: 18.7, up: true,  color: T.red,    spark: [22,25,28,26,30,29,32,34,33,36,38,40,39,42,44] },
  { key: "susp",   label: "Suspicious",         value:  892, delta:  8.3, up: false, color: T.amber,  spark: [30,28,32,29,26,28,25,27,24,26,23,25,22,24,21] },
  { key: "benign", label: "Benign",             value: 2642, delta: 91.2, up: true,  color: T.green,  spark: [14,16,15,18,17,19,21,20,22,24,23,25,26,24,27] },
  { key: "mitre",  label: "MITRE Techniques",   value:  145, delta: 15.2, up: true,  color: T.violet, spark: [80,82,85,88,90,92,95,98,102,108,115,122,128,138,145] },
];

const SOURCES = ["prod-winlogbeat","prod-kubernetes-prod","prod-cloudtrail","prod-o365audit","prod-kubernetes-dev"];
const REPOS   = ["SOC Prime Premium Rules","DEV Stage Rules","PRODUCTION Rules","Research · rule candidates","Custom Rules"];
const DESTS   = ["prod-cloudtrail-tagged","prod-windows-tagged","prod-office365-tagged","prod-kubernetes-dev","prod-kubernetes-prod","+3 more"];

// ═══════════════════════════════════════════════════════════════════
// Root
// ═══════════════════════════════════════════════════════════════════
export default function PreviewCommandHub() {
  const [tf, setTf] = useState("24H");
  return (
    <div data-testid="preview-command-hub" style={{
      minHeight: "100vh", display: "flex",
      background:
        "radial-gradient(circle at 12% 8%, rgba(34,211,238,0.06), transparent 55%),"
        + "radial-gradient(circle at 88% 20%, rgba(139,92,246,0.06), transparent 55%),"
        + `linear-gradient(180deg, ${T.bg1} 0%, ${T.bg2} 100%)`,
      backgroundAttachment: "fixed",
      color: T.text,
      fontFamily: T.font,
    }}>
      <LeftRail />
      <main style={{ flex: 1, padding: "20px 26px 32px", minWidth: 0 }}>
        <TopBar tf={tf} setTf={setTf} />
        <FlowDiagram />
        <KpiRow />
        <BottomCards />
      </main>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Left rail
// ═══════════════════════════════════════════════════════════════════
function LeftRail() {
  const items = [
    { label: "Command Center", icon: LayoutGrid,   active: true },
    { label: "Dashboard",      icon: BarChart3 },
    { label: "Detections",     icon: Shield },
    { label: "Threat Hunting", icon: Target },
    { label: "Playbooks",      icon: BookOpen },
    { label: "Intelligence",   icon: Radar },
    { label: "Assets",         icon: Package },
    { label: "Reports",        icon: ScrollText },
    { label: "Integrations",   icon: Puzzle },
    { label: "Settings",       icon: Cog },
  ];
  return (
    <aside style={{
      width: 230, flexShrink: 0,
      background: "linear-gradient(180deg, rgba(4,8,20,0.85), rgba(3,6,15,0.9))",
      borderRight: `1px solid ${T.border}`,
      padding: "20px 12px",
      display: "flex", flexDirection: "column",
      backdropFilter: "blur(18px) saturate(160%)",
    }}>
      {/* Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "0 4px 24px" }}>
        <div style={{
          position: "relative",
          width: 42, height: 42, borderRadius: 10,
          background: `linear-gradient(160deg, ${T.cyan}22, ${T.cyan}05)`,
          border: `1px solid ${T.cyan}55`,
          display: "grid", placeItems: "center",
          boxShadow: `0 0 20px ${T.cyan}33`,
        }}>
          <div style={{ fontFamily: T.font, fontWeight: 900, fontSize: 22, color: T.cyan, textShadow: `0 0 12px ${T.cyan}` }}>N</div>
          <span style={{ position: "absolute", bottom: 6, right: 6, width: 5, height: 5, borderRadius: "50%", background: "#f97316", boxShadow: "0 0 6px #f97316" }} />
        </div>
        <div>
          <div style={{ fontFamily: T.font, fontWeight: 900, fontSize: 16, letterSpacing: "0.14em" }}>NIVXRAY</div>
          <div style={{ fontFamily: T.mono, fontSize: 8, color: T.mute, letterSpacing: "0.20em" }}>DECODER / THREAT-LAB</div>
        </div>
      </div>

      <nav style={{ display: "flex", flexDirection: "column", gap: 2 }}>
        {items.map((it) => <RailItem key={it.label} {...it} />)}
      </nav>

      {/* Spacer */}
      <div style={{ flex: 1 }} />

      {/* User + status */}
      <div style={{
        padding: "10px 10px",
        display: "flex", alignItems: "center", gap: 10,
        background: "rgba(255,255,255,0.02)",
        border: `1px solid ${T.border}`, borderRadius: 8,
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8,
          background: `linear-gradient(160deg, ${T.violet}, #6d28d9)`,
          display: "grid", placeItems: "center",
          fontFamily: T.font, fontWeight: 800, fontSize: 12,
          boxShadow: `0 0 10px ${T.violet}55`,
        }}>NK</div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 700 }}>NivX Analyst</div>
          <div style={{ fontSize: 10, color: T.mute, fontFamily: T.mono }}>Administrator</div>
        </div>
        <ChevronDown size={14} color={T.mute} />
      </div>

      <div style={{
        marginTop: 10, padding: "10px 12px",
        display: "flex", alignItems: "center", gap: 8,
        borderRadius: 8, border: `1px solid ${T.border}`,
      }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: T.green, boxShadow: `0 0 6px ${T.green}` }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 11, fontWeight: 700 }}>System Status</div>
          <div style={{ fontFamily: T.mono, fontSize: 10, color: T.mute }}>All Systems Operational</div>
        </div>
      </div>
    </aside>
  );
}
function RailItem({ label, icon: Icon, active }) {
  return (
    <button style={{
      display: "flex", alignItems: "center", gap: 11,
      padding: "9px 11px", borderRadius: 8,
      background: active ? `linear-gradient(90deg, ${T.cyan}22, ${T.cyan}03)` : "transparent",
      border: `1px solid ${active ? T.cyan + "55" : "transparent"}`,
      color: active ? T.cyan : T.dim,
      cursor: "pointer",
      transition: "background 200ms, color 160ms, border-color 200ms",
      textAlign: "left",
      fontFamily: T.font, fontSize: 12, fontWeight: 600,
      letterSpacing: "0.02em",
    }}>
      <div style={{
        width: 26, height: 26, borderRadius: 6,
        display: "grid", placeItems: "center",
        background: active ? `${T.cyan}22` : "rgba(148,163,184,0.06)",
        border: `1px solid ${active ? T.cyan + "55" : "rgba(148,163,184,0.10)"}`,
        color: active ? T.cyan : T.dim,
      }}>
        <Icon size={13} strokeWidth={1.9} />
      </div>
      {label}
    </button>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Top bar
// ═══════════════════════════════════════════════════════════════════
function TopBar({ tf, setTf }) {
  return (
    <header style={{
      display: "flex", alignItems: "center", justifyContent: "space-between",
      gap: 16, marginBottom: 18,
    }}>
      <div>
        <h1 style={{
          margin: 0, fontFamily: T.font, fontWeight: 800, fontSize: 24,
          letterSpacing: "-0.01em",
        }}>Command Center</h1>
        <div style={{ fontFamily: T.mono, fontSize: 11, color: T.dim, marginTop: 3 }}>
          Real-time overview of your security operations
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 8,
          padding: "8px 12px", width: 320,
          borderRadius: 8, border: `1px solid ${T.border}`,
          background: "rgba(15,23,42,0.55)",
        }}>
          <Search size={13} color={T.mute} />
          <input placeholder="Search detections, IPs, hashes…" style={{
            background: "transparent", border: "none", outline: "none",
            color: T.text, fontFamily: T.mono, fontSize: 11, flex: 1,
          }} />
        </div>
        <IconBtn icon={Bell} badge={3} />
        <div style={{
          width: 36, height: 36, borderRadius: 999, display: "grid", placeItems: "center",
          fontFamily: T.font, fontWeight: 800, fontSize: 12,
          background: `linear-gradient(160deg, ${T.violet}, #6d28d9)`,
          boxShadow: `0 0 10px ${T.violet}55`,
        }}>NK</div>
      </div>
    </header>
  );
}
function IconBtn({ icon: Icon, badge }) {
  return (
    <button style={{
      position: "relative", width: 36, height: 36, borderRadius: 999,
      background: "rgba(15,23,42,0.55)", border: `1px solid ${T.border}`,
      color: T.dim, display: "grid", placeItems: "center", cursor: "pointer",
    }}>
      <Icon size={15} strokeWidth={1.9} />
      {badge != null && (
        <span style={{
          position: "absolute", top: -3, right: -3,
          minWidth: 16, height: 16, padding: "0 4px", borderRadius: 8,
          background: T.violet, color: "#fff", fontSize: 8, fontWeight: 800,
          display: "grid", placeItems: "center", boxShadow: `0 0 6px ${T.violet}`,
        }}>{badge}</span>
      )}
    </button>
  );
}

// ═══════════════════════════════════════════════════════════════════
// FLOW DIAGRAM — SOURCE → DETECTION → DESTINATIONS · RULES pipeline
// ═══════════════════════════════════════════════════════════════════
function FlowDiagram() {
  return (
    <div style={{
      marginBottom: 18,
      padding: "18px 22px",
      background: T.surface, border: `1px solid ${T.border}`,
      borderRadius: 14,
      backdropFilter: "blur(14px) saturate(150%)",
      boxShadow: "0 6px 24px rgba(2,6,23,0.35), inset 0 1px 0 rgba(255,255,255,0.04)",
      position: "relative", overflow: "hidden",
    }}>
      {/* Timeframe row */}
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 6 }}>
        <div style={{
          display: "inline-flex", padding: 4, gap: 2, borderRadius: 8,
          background: "rgba(15,23,42,0.55)", border: `1px solid ${T.border}`,
        }}>
          {["24H","7D","30D","90D"].map(v => (
            <button key={v} style={{
              padding: "6px 12px", borderRadius: 6,
              fontFamily: T.mono, fontSize: 10, letterSpacing: "0.14em", fontWeight: 700,
              background: v === "24H" ? `linear-gradient(160deg, ${T.cyan}22, ${T.cyan}03)` : "transparent",
              color: v === "24H" ? T.cyan : T.dim,
              border: `1px solid ${v === "24H" ? T.cyan + "55" : "transparent"}`,
              cursor: "pointer",
            }}>{v}</button>
          ))}
          <button style={{ padding: "6px 8px", borderRadius: 6, border: `1px solid ${T.border}`, background: "transparent", color: T.dim, cursor: "pointer" }}>
            <Calendar size={12} />
          </button>
        </div>
      </div>

      {/* Central SVG canvas */}
      <svg viewBox="0 0 1250 460" width="100%" height="460" style={{ display: "block" }}>
        {/* Legend anchors — we draw everything relative to these */}
        <defs>
          <linearGradient id="glowCyan" x1="0" x2="1">
            <stop offset="0%" stopColor={T.cyan} stopOpacity="0" />
            <stop offset="50%" stopColor={T.cyan} stopOpacity="1" />
            <stop offset="100%" stopColor={T.cyan} stopOpacity="0" />
          </linearGradient>
          <linearGradient id="glowViolet" x1="0" x2="1">
            <stop offset="0%" stopColor={T.violet} stopOpacity="0" />
            <stop offset="50%" stopColor={T.violet} stopOpacity="1" />
            <stop offset="100%" stopColor={T.violet} stopOpacity="0" />
          </linearGradient>
          <linearGradient id="glowGreen" x1="0" x2="1">
            <stop offset="0%" stopColor={T.green} stopOpacity="0" />
            <stop offset="50%" stopColor={T.green} stopOpacity="1" />
            <stop offset="100%" stopColor={T.green} stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* ── LEFT: SOURCE list ─────────────────────────────────── */}
        <text x="60" y="30" style={{ fontFamily: T.mono, fontSize: 11, fill: T.cyan, letterSpacing: "0.18em" }}>SOURCE</text>
        <text x="60" y="48" style={{ fontFamily: T.mono, fontSize: 9, fill: T.mute, letterSpacing: "0.14em" }}>Top 5 Sources</text>
        {SOURCES.map((s, i) => {
          const y = 78 + i * 24;
          return (
            <g key={s}>
              <circle cx="60" cy={y} r="4" fill={T.cyan} style={{ filter: `drop-shadow(0 0 4px ${T.cyan})` }} />
              <text x="72" y={y + 4} style={{ fontFamily: T.mono, fontSize: 11, fill: T.text }}>{s}</text>
              {/* connector to EVENTS/SEC box */}
              <path d={`M64,${y} C160,${y} 240,${175} 340,175`} fill="none" stroke={T.cyan} strokeWidth="0.7" opacity="0.55" />
            </g>
          );
        })}

        {/* ── EVENTS/SEC box ─────────────────────────────────────── */}
        <FlowBox x={340} y={140} w={130} h={72} color={T.cyan} title="EVENTS/SEC" value="54,778" />

        {/* connector EVENTS/SEC → DETECTION circle */}
        <path d="M475,176 L580,176" stroke={T.cyan} strokeWidth="1.4" opacity="0.85" />
        <circle cx="475" cy="176" r="3" fill={T.cyan} style={{ filter: `drop-shadow(0 0 6px ${T.cyan})` }} />

        {/* ── DETECTION PIPELINES big circle ─────────────────────── */}
        <BigCircle cx={640} cy={176} r={70} color={T.cyan} label={"DETECTION\nPIPELINES"} value="3:1" />

        {/* connector DETECTION → TAGGED */}
        <path d="M710,176 L780,176" stroke={T.violet} strokeWidth="1.6" opacity="0.85" />
        <path d="M710,176 L780,176" stroke="url(#glowViolet)" strokeWidth="3" opacity="0.4" />

        {/* ── TAGGED/SEC box ─────────────────────────────────────── */}
        <FlowBox x={780} y={140} w={130} h={72} color={T.violet} title="TAGGED/SEC" value="21" />

        {/* connector TAGGED → MITRE TIE */}
        <path d="M912,176 C960,176 990,240 990,300" stroke={T.violet} strokeWidth="1.2" opacity="0.75" fill="none" />

        {/* ── MITRE TIE circle ───────────────────────────────────── */}
        <MitreCircle cx={990} cy={330} r={54} />

        {/* ── RIGHT: DESTINATION topics with fan-out lines ───────── */}
        <text x="1055" y="30" style={{ fontFamily: T.mono, fontSize: 11, fill: T.violet, letterSpacing: "0.18em" }}>DESTINATION TOPICS</text>
        {DESTS.map((s, i) => {
          const y = 62 + i * 22;
          return (
            <g key={s}>
              <circle cx="1052" cy={y} r="3.5" fill={T.violet} style={{ filter: `drop-shadow(0 0 4px ${T.violet})` }} />
              <text x="1062" y={y + 4} style={{ fontFamily: T.mono, fontSize: 11, fill: T.text }}>{s}</text>
              {/* incoming line from TAGGED */}
              <path d={`M912,176 C980,176 1000,${y} 1050,${y}`} fill="none" stroke={T.violet} strokeWidth="0.5" opacity="0.5" />
            </g>
          );
        })}
        <text x="1055" y={62 + DESTS.length*22 + 30} style={{ fontFamily: T.mono, fontSize: 11, fill: T.green, letterSpacing: "0.18em" }}>DATA LAKE</text>
        {["AWS Security Lake"].map((s, i) => {
          const y = 62 + DESTS.length*22 + 30 + 18 + i*18;
          return <text key={s} x="1062" y={y} style={{ fontFamily: T.mono, fontSize: 11, fill: T.text }}>• {s}</text>;
        })}
        <text x="1055" y={310} style={{ fontFamily: T.mono, fontSize: 11, fill: T.green, letterSpacing: "0.18em" }}>SIEM</text>
        {["Splunk","QRadar","ArcSight","LogRhythm","Sentinel"].map((s, i) => {
          const y = 310 + 18 + i*18;
          return (
            <g key={s}>
              <circle cx="1052" cy={y-3} r="3" fill={T.green} />
              <text x="1062" y={y} style={{ fontFamily: T.mono, fontSize: 11, fill: T.text }}>{s}</text>
              <path d={`M1042,${330} C1046,${y} 1048,${y} 1050,${y-3}`} fill="none" stroke={T.green} strokeWidth="0.5" opacity="0.5" />
            </g>
          );
        })}
        <text x="1055" y={430} style={{ fontFamily: T.mono, fontSize: 11, fill: T.green, letterSpacing: "0.18em" }}>EDR</text>
        <circle cx="1052" cy={447} r="3" fill={T.green} />
        <text x="1062" y={450} style={{ fontFamily: T.mono, fontSize: 11, fill: T.text }}>Microsoft Defender</text>

        {/* ── BOTTOM ROW: REPOSITORIES → RULES → STAGING → DEPLOYED ── */}
        <text x="60" y="290" style={{ fontFamily: T.mono, fontSize: 11, fill: T.green, letterSpacing: "0.18em" }}>REPOSITORIES</text>
        <text x="60" y="308" style={{ fontFamily: T.mono, fontSize: 9, fill: T.mute, letterSpacing: "0.14em" }}>Top 5 Repositories</text>
        {REPOS.map((s, i) => {
          const y = 338 + i * 22;
          return (
            <g key={s}>
              <circle cx="60" cy={y} r="3.5" fill={T.green} style={{ filter: `drop-shadow(0 0 4px ${T.green})` }} />
              <text x="70" y={y + 4} style={{ fontFamily: T.mono, fontSize: 11, fill: T.text }}>{s}</text>
              <path d={`M64,${y} C160,${y} 220,${360} 340,360`} fill="none" stroke={T.green} strokeWidth="0.6" opacity="0.6" />
            </g>
          );
        })}
        <FlowBox x={340} y={310} w={130} h={54} color={T.green} title="# RULES" value="6,500" />
        <FlowBox x={340} y={390} w={130} h={54} color={T.green} title="# RULES" value="3,000" />

        {/* connect to STAGING circle */}
        <path d="M475,336 C540,336 570,380 580,380" stroke={T.green} strokeWidth="1.1" opacity="0.75" fill="none" />
        <path d="M475,414 C540,414 570,380 580,380" stroke={T.green} strokeWidth="1.1" opacity="0.75" fill="none" />
        <StagingCircle cx={640} cy={380} />

        {/* STAGING → RULES DEPLOYED */}
        <path d="M710,380 L780,380" stroke={T.green} strokeWidth="1.4" opacity="0.85" />
        <FlowBox x={780} y={350} w={130} h={62} color={T.green} title="RULES DEPLOYED" value="1,500" />

        {/* Deployed → LLM Firewall (bottom right connection) */}
        <path d="M912,380 C960,380 990,430 1040,455" stroke={T.green} strokeWidth="0.7" opacity="0.6" fill="none" />

        {/* Bottom-right LLM Firewall panel */}
        <text x="1055" y={465} style={{ fontFamily: T.mono, fontSize: 11, fill: T.green, letterSpacing: "0.18em" }}>LLM FIREWALL</text>
      </svg>
    </div>
  );
}

// SVG helpers ---------------------------------------------------------
function FlowBox({ x, y, w, h, color, title, value }) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="6" ry="6"
            fill="rgba(15,23,42,0.6)" stroke={color} strokeWidth="1.3"
            style={{ filter: `drop-shadow(0 0 8px ${color}44)` }} />
      <text x={x + w/2} y={y + 20} textAnchor="middle"
            style={{ fontFamily: T.mono, fontSize: 10, fill: color, letterSpacing: "0.16em" }}>{title}</text>
      <text x={x + w/2} y={y + 46} textAnchor="middle"
            style={{ fontFamily: T.font, fontWeight: 900, fontSize: 22, fill: T.text }}>{value}</text>
      {/* sparkline placeholder */}
      <path d={`M${x+12},${y+h-8} L${x+22},${y+h-14} L${x+32},${y+h-10} L${x+42},${y+h-16} L${x+52},${y+h-8} L${x+62},${y+h-14} L${x+72},${y+h-10} L${x+82},${y+h-18} L${x+92},${y+h-8} L${x+102},${y+h-14} L${x+112},${y+h-10}`}
            fill="none" stroke={color} strokeWidth="0.9" opacity="0.7" />
    </g>
  );
}
function BigCircle({ cx, cy, r, color, label, value }) {
  const lines = label.split("\n");
  return (
    <g>
      <circle cx={cx} cy={cy} r={r + 10} fill="none" stroke={color} strokeWidth="0.6" opacity="0.35" />
      <circle cx={cx} cy={cy} r={r + 4}  fill="none" stroke={color} strokeWidth="0.9" opacity="0.55" />
      <circle cx={cx} cy={cy} r={r} fill="rgba(15,23,42,0.55)" stroke={color} strokeWidth="1.6"
              style={{ filter: `drop-shadow(0 0 14px ${color}88)` }} />
      <text x={cx} y={cy - 8} textAnchor="middle" style={{ fontFamily: T.font, fontWeight: 900, fontSize: 26, fill: T.text }}>{value}</text>
      {lines.map((l, i) => (
        <text key={i} x={cx} y={cy + 14 + i * 14} textAnchor="middle" style={{ fontFamily: T.mono, fontSize: 10, fill: color, letterSpacing: "0.16em" }}>{l}</text>
      ))}
    </g>
  );
}
function MitreCircle({ cx, cy, r }) {
  return (
    <g>
      <circle cx={cx} cy={cy} r={r+8} fill="none" stroke={T.violet} strokeWidth="0.6" opacity="0.35" />
      <circle cx={cx} cy={cy} r={r} fill="rgba(15,23,42,0.55)" stroke={T.violet} strokeWidth="1.6"
              style={{ filter: `drop-shadow(0 0 12px ${T.violet}88)` }} />
      <text x={cx} y={cy - 4} textAnchor="middle" style={{ fontFamily: T.font, fontWeight: 900, fontSize: 14, fill: T.text, letterSpacing: "0.10em" }}>MITRE TIE</text>
      <text x={cx} y={cy + 14} textAnchor="middle" style={{ fontFamily: T.mono, fontSize: 10, fill: T.violet, letterSpacing: "0.16em" }}>ATTACK CHAIN</text>
    </g>
  );
}
function StagingCircle({ cx, cy }) {
  return (
    <g>
      <circle cx={cx} cy={cy} r={68} fill="none" stroke={T.green} strokeWidth="0.6" opacity="0.35" />
      <circle cx={cx} cy={cy} r={60} fill="rgba(15,23,42,0.55)" stroke={T.green} strokeWidth="1.6"
              style={{ filter: `drop-shadow(0 0 12px ${T.green}88)` }} />
      <text x={cx - 20} y={cy - 8} textAnchor="middle" style={{ fontFamily: T.font, fontWeight: 900, fontSize: 16, fill: T.text }}>1245</text>
      <text x={cx + 24} y={cy - 8} textAnchor="middle" style={{ fontFamily: T.font, fontWeight: 900, fontSize: 16, fill: T.text }}>25</text>
      <text x={cx} y={cy + 8} textAnchor="middle" style={{ fontFamily: T.mono, fontSize: 10, fill: T.green, letterSpacing: "0.16em" }}>STAGING</text>
      <text x={cx} y={cy + 22} textAnchor="middle" style={{ fontFamily: T.mono, fontSize: 9,  fill: T.mute, letterSpacing: "0.10em" }}>STATS</text>
    </g>
  );
}

// ═══════════════════════════════════════════════════════════════════
// KPI row
// ═══════════════════════════════════════════════════════════════════
function KpiRow() {
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(5, minmax(0, 1fr))",
      gap: 12, marginBottom: 18,
    }}>
      {KPI.map(k => <KpiCard key={k.key} k={k} />)}
    </div>
  );
}
function KpiCard({ k }) {
  return (
    <div style={{
      padding: "14px 16px", borderRadius: 10,
      background: T.surface, border: `1px solid ${T.border}`,
      backdropFilter: "blur(14px) saturate(150%)",
      boxShadow: "0 6px 24px rgba(2,6,23,0.35), inset 0 1px 0 rgba(255,255,255,0.04)",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontFamily: T.mono, fontSize: 9, letterSpacing: "0.18em", color: T.dim, textTransform: "uppercase" }}>
          {k.label}
        </div>
        <div style={{
          width: 26, height: 26, borderRadius: 999,
          background: `linear-gradient(160deg, ${k.color}22, ${k.color}05)`,
          border: `1px solid ${k.color}55`,
          display: "grid", placeItems: "center",
        }}>
          <svg width="12" height="12" viewBox="0 0 12 12"><circle cx="6" cy="6" r="4" fill="none" stroke={k.color} strokeWidth="1.4" /></svg>
        </div>
      </div>
      <div style={{ fontFamily: T.font, fontWeight: 900, fontSize: 30, marginTop: 8 }}>{k.value.toLocaleString()}</div>
      <div style={{ display: "inline-flex", alignItems: "center", gap: 4, marginTop: 2, color: k.up ? T.green : T.red, fontFamily: T.mono, fontSize: 10, fontWeight: 700 }}>
        {k.up ? <ArrowUp size={11} /> : <ArrowDown size={11} />}
        {k.delta}% <span style={{ color: T.mute, fontWeight: 400 }}>vs yesterday</span>
      </div>
      <Sparkline points={k.spark} color={k.color} />
    </div>
  );
}
function Sparkline({ points, color }) {
  const w = 200, h = 34;
  const min = Math.min(...points), max = Math.max(...points);
  const r = max - min || 1;
  const pts = points.map((p, i) => [ (i/(points.length-1))*w, h - ((p-min)/r)*h ]);
  const line = pts.map(([x,y], i) => `${i===0?"M":"L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ marginTop: 6, display: "block" }}>
      <path d={line} fill="none" stroke={color} strokeWidth="1.4" style={{ filter: `drop-shadow(0 0 3px ${color})` }} />
      {pts.map(([x,y], i) => <circle key={i} cx={x} cy={y} r="1.6" fill={color} />)}
    </svg>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Bottom cards row: Analysis Trend · MITRE donut · Live feed · Health
// ═══════════════════════════════════════════════════════════════════
function BottomCards() {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1.3fr 1fr 1fr 1fr", gap: 14 }}>
      <TrendCard />
      <MitreDonutCard />
      <LiveFeedCard />
      <SystemHealthCard />
    </div>
  );
}
function CardShell({ eyebrowIcon: Icon, title, subtitle, footer, children }) {
  return (
    <div style={{
      background: T.surface, border: `1px solid ${T.border}`,
      borderRadius: 10, padding: 14,
      backdropFilter: "blur(14px) saturate(150%)",
      boxShadow: "0 6px 24px rgba(2,6,23,0.35), inset 0 1px 0 rgba(255,255,255,0.04)",
      display: "flex", flexDirection: "column", minWidth: 0,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <div style={{
          width: 24, height: 24, borderRadius: 6,
          background: `linear-gradient(160deg, ${T.cyan}22, ${T.cyan}05)`,
          border: `1px solid ${T.cyan}55`,
          display: "grid", placeItems: "center", color: T.cyan,
        }}>
          {Icon && <Icon size={12} strokeWidth={1.9} />}
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontFamily: T.font, fontWeight: 800, fontSize: 12, letterSpacing: "0.06em" }}>{title}</div>
          {subtitle && <div style={{ fontFamily: T.mono, fontSize: 10, color: T.mute }}>{subtitle}</div>}
        </div>
      </div>
      <div style={{ flex: 1, minHeight: 0 }}>{children}</div>
      {footer && (
        <div style={{
          marginTop: 10, paddingTop: 10, borderTop: `1px solid ${T.border}`,
          fontFamily: T.mono, fontSize: 10, color: T.cyan, letterSpacing: "0.08em",
          textAlign: "center", cursor: "pointer",
        }}>{footer} →</div>
      )}
    </div>
  );
}
function TrendCard() {
  const N = 30;
  const T2 = Array.from({length: N}, (_,i) => ({
    p50:  240 + Math.sin(i/3)*40 + i*5,
    p95:  480 + Math.cos(i/4)*60 + i*6,
    mitre: 100 + Math.sin(i/5)*8 + i*1.4,
  }));
  const w = 360, h = 200, pl = 40, pr = 24, pt = 10, pb = 22;
  const iw = w - pl - pr, ih = h - pt - pb;
  const maxP95 = Math.max(...T2.map(d => d.p95)) * 1.1;
  const x = i => pl + (i/(N-1))*iw;
  const y = v => pt + ih - (v/maxP95)*ih;
  const line = (arr,f) => arr.map((d,i) => `${i===0?"M":"L"}${x(i).toFixed(1)},${f(d).toFixed(1)}`).join(" ");
  return (
    <CardShell eyebrowIcon={BarChart3} title="ANALYSIS TREND" subtitle="Real data from NivXRAY Corpus" footer="View full history">
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginBottom: 2 }}>
        {[{c:T.green,l:"p50 (ms)"},{c:T.violet,l:"p95 (ms)"},{c:T.cyan,l:"MITRE (count)"}].map(x => (
          <span key={x.l} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontFamily: T.mono, fontSize: 9, color: T.dim }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: x.c, boxShadow: `0 0 4px ${x.c}` }} />
            {x.l}
          </span>
        ))}
      </div>
      <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: "block" }}>
        {[0,0.25,0.5,0.75,1].map((f,i) => {
          const yy = pt + f*ih;
          return <line key={i} x1={pl} x2={w-pr} y1={yy} y2={yy} stroke="rgba(148,163,184,0.08)" strokeDasharray="3 4" />;
        })}
        {[0,0.5,1].map((f,i) => (
          <text key={i} x={pl-6} y={pt+f*ih+3} textAnchor="end" style={{ fontFamily: T.mono, fontSize: 9, fill: T.mute }}>
            {Math.round((1-f)*maxP95)}
          </text>
        ))}
        <path d={line(T2, d => y(d.p50))}    fill="none" stroke={T.green}  strokeWidth="1.4" style={{ filter: `drop-shadow(0 0 3px ${T.green})` }} />
        <path d={line(T2, d => y(d.p95))}    fill="none" stroke={T.violet} strokeWidth="1.4" style={{ filter: `drop-shadow(0 0 3px ${T.violet})` }} />
        <path d={line(T2, d => y(d.mitre*4))} fill="none" stroke={T.cyan}  strokeWidth="1.4" strokeDasharray="4 3" style={{ filter: `drop-shadow(0 0 3px ${T.cyan})` }} />
        {T2.map((d,i) => (
          <g key={i}>
            <circle cx={x(i)} cy={y(d.p50)} r="1.6" fill={T.green} />
            <circle cx={x(i)} cy={y(d.p95)} r="1.6" fill={T.violet} />
            <circle cx={x(i)} cy={y(d.mitre*4)} r="1.4" fill={T.cyan} />
          </g>
        ))}
      </svg>
    </CardShell>
  );
}
function MitreDonutCard() {
  const rows = [
    { label: "Initial Access",       v: 27, p: 18.6, c: T.cyan },
    { label: "Execution",            v: 31, p: 21.4, c: T.violet },
    { label: "Persistence",          v: 19, p: 13.1, c: T.amber },
    { label: "Privilege Escalation", v: 14, p:  9.7, c: T.green },
    { label: "Defense Evasion",      v: 22, p: 15.2, c: T.red },
    { label: "Credential Access",    v: 12, p:  8.3, c: T.pink },
    { label: "Discovery",            v: 20, p: 13.8, c: "#a3e635" },
  ];
  const tot = rows.reduce((s, r) => s + r.v, 0);
  const R = 60, RI = 42, CX = 80, CY = 84;
  let acc = 0;
  const arc = rows.map(r => {
    const s = acc/tot*Math.PI*2 - Math.PI/2;
    acc += r.v;
    const e = acc/tot*Math.PI*2 - Math.PI/2;
    return { ...r, s, e };
  });
  const path = (s,e) => {
    const large = e - s > Math.PI ? 1 : 0;
    const [x1,y1,x2,y2] = [CX+R*Math.cos(s), CY+R*Math.sin(s), CX+R*Math.cos(e), CY+R*Math.sin(e)];
    const [x3,y3,x4,y4] = [CX+RI*Math.cos(e), CY+RI*Math.sin(e), CX+RI*Math.cos(s), CY+RI*Math.sin(s)];
    return `M${x1},${y1} A${R},${R} 0 ${large},1 ${x2},${y2} L${x3},${y3} A${RI},${RI} 0 ${large},0 ${x4},${y4} Z`;
  };
  return (
    <CardShell eyebrowIcon={Target} title="MITRE ATT&CK COVERAGE" subtitle="Techniques observed (last 30 days)" footer="Explore MITRE Matrix">
      <div style={{ display: "flex", gap: 10 }}>
        <svg width="170" height="170" viewBox="0 0 170 170" style={{ flexShrink: 0 }}>
          {arc.map((a,i) => <path key={i} d={path(a.s, a.e)} fill={a.c} opacity="0.9" />)}
          <text x={CX} y={CY - 4} textAnchor="middle" style={{ fontFamily: T.font, fontWeight: 900, fontSize: 22, fill: T.text }}>{tot}</text>
          <text x={CX} y={CY + 12} textAnchor="middle" style={{ fontFamily: T.mono, fontSize: 8, fill: T.dim, letterSpacing: "0.14em" }}>TECHNIQUES</text>
        </svg>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 3, minWidth: 0 }}>
          {rows.map(r => (
            <div key={r.label} style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: T.mono, fontSize: 9 }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: r.c, flexShrink: 0 }} />
              <span style={{ flex: 1, color: T.dim, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{r.label}</span>
              <span style={{ color: T.text, fontWeight: 700 }}>{r.v}</span>
              <span style={{ color: T.mute }}>({r.p}%)</span>
            </div>
          ))}
        </div>
      </div>
    </CardShell>
  );
}
function LiveFeedCard() {
  const items = [
    { t: "10:24:31", title: "Malicious PowerShell Script", sub: "Obfuscated command detected", verdict: "Malicious", tone: T.red },
    { t: "10:24:12", title: "Suspicious Download",         sub: "Untrusted source activity",  verdict: "Suspicious",tone: T.amber },
    { t: "10:23:58", title: "Clean File Verified",         sub: "No threats detected",        verdict: "Benign",    tone: T.green },
    { t: "10:23:41", title: "C2 Communication",            sub: "Beaconing to known C2",       verdict: "Malicious",tone: T.red },
    { t: "10:23:19", title: "Registry Modification",       sub: "Auto-start persistence",     verdict: "Suspicious",tone: T.amber },
  ];
  return (
    <CardShell eyebrowIcon={Activity} title="LIVE ANALYSIS FEED" subtitle="Real-time activity stream" footer="View all activity">
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {items.map((e,i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 6px", borderRadius: 6, background: "rgba(255,255,255,0.02)", border: `1px solid ${T.border}` }}>
            <div style={{ width: 22, height: 22, borderRadius: 5, background: `linear-gradient(160deg, ${e.tone}22, ${e.tone}05)`, border: `1px solid ${e.tone}55`, display: "grid", placeItems: "center", color: e.tone, flexShrink: 0 }}>
              <Shield size={11} strokeWidth={1.9} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: T.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{e.title}</div>
              <div style={{ fontFamily: T.mono, fontSize: 9, color: T.mute }}>{e.sub}</div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontFamily: T.mono, fontSize: 9, color: T.mute }}>{e.t}</div>
              <span style={{ display: "inline-block", padding: "1px 6px", borderRadius: 8, fontFamily: T.mono, fontSize: 8, fontWeight: 700, background: `linear-gradient(160deg, ${e.tone}22, ${e.tone}05)`, color: e.tone, border: `1px solid ${e.tone}55` }}>{e.verdict}</span>
            </div>
          </div>
        ))}
      </div>
    </CardShell>
  );
}
function SystemHealthCard() {
  const services = ["API Services","Database","Cache","Storage","Queue","Workers","Analytics"];
  return (
    <CardShell eyebrowIcon={Shield} title="SYSTEM HEALTH" subtitle="All systems operational" footer="View system status">
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <svg width="140" height="140" viewBox="0 0 200 200" style={{ flexShrink: 0 }}>
          <circle cx="100" cy="100" r="80" fill="none" stroke={T.green} strokeWidth="1.4" style={{ filter: `drop-shadow(0 0 8px ${T.green}55)` }} />
          <circle cx="100" cy="100" r="80" fill={T.green} opacity="0.06" />
          {Array.from({length: 10}).map((_,i) => {
            const a = -Math.PI/2 + i * (Math.PI*2 / 10);
            const x = 100 + 80 * Math.cos(a), y = 100 + 80 * Math.sin(a);
            return <circle key={i} cx={x} cy={y} r="3" fill={T.green} style={{ filter: `drop-shadow(0 0 4px ${T.green})` }} />;
          })}
          <text x="100" y="94" textAnchor="middle" style={{ fontFamily: T.font, fontWeight: 900, fontSize: 28, fill: T.text }}>100%</text>
          <text x="100" y="114" textAnchor="middle" style={{ fontFamily: T.mono, fontSize: 8, fill: T.dim, letterSpacing: "0.16em" }}>HEALTH</text>
        </svg>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 4 }}>
          {services.map(s => (
            <div key={s} style={{ display: "flex", justifyContent: "space-between", fontFamily: T.mono, fontSize: 9 }}>
              <span style={{ color: T.dim, display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{ width: 5, height: 5, borderRadius: "50%", background: T.green, boxShadow: `0 0 4px ${T.green}` }} />
                {s}
              </span>
              <span style={{ color: T.green }}>Operational</span>
            </div>
          ))}
        </div>
      </div>
    </CardShell>
  );
}
