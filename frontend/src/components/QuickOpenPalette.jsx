/**
 * QuickOpenPalette — global Spotlight/Raycast-style command palette.
 *
 * Trigger: Cmd+K (macOS) / Ctrl+K (Windows/Linux). Also opens on "/"
 * pressed anywhere outside a text input.
 *
 * Sources — all REAL backend queries, no mocks:
 *   • Cases       ← GET /api/investigations         (last 50)
 *   • Samples     ← GET /api/admin/samples          (up to 200)
 *   • Training    ← GET /api/training-inbox         (up to 200)
 *   • Batch runs  ← GET /api/batch/history          (last 50)
 *   • Documents   ← GET /api/documents              (up to 200)
 *   • MITRE       ← static list from lucide/mitre TIDs common in the
 *                   corpus + techniques observed in the heatmap
 *
 * Behaviour:
 *   • Fuzzy substring match across name + type + id/hash
 *   • Recent selections persisted in localStorage under `nvx-qo-recent`
 *   • ↑ ↓ navigate · Enter open · Esc close
 *   • Grouped view when no query; flattened / ranked when typing
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search, X, ArrowRight, FileText, TestTube2, Target, Rss, ScrollText, Beaker,
  History as HistoryIcon, RefreshCw, Play, Command, Gauge, Rocket, KeyRound,
} from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/api";

const RECENT_KEY = "nvx-qo-recent";
const RECENT_MAX = 6;

// Sections
const SECTIONS = [
  { key: "cases",     label: "Cases",         icon: FileText,   route: (r) => `/analyst?iid=${encodeURIComponent(r.id)}` },
  { key: "samples",   label: "Samples",       icon: Beaker,     route: (r) => `/admin/samples#${encodeURIComponent(r.id)}` },
  { key: "mitre",     label: "MITRE",         icon: Target,     route: (r) => `/heatmap?t=${encodeURIComponent(r.id)}` },
  { key: "training",  label: "Training Notes",icon: Rss,        route: () => `/admin/training-inbox` },
  { key: "batch",     label: "Batch Runs",    icon: TestTube2,  route: (r) => `/batch-test?run=${encodeURIComponent(r.id)}` },
  { key: "documents", label: "Documents",     icon: ScrollText, route: (r) => `/documents#${encodeURIComponent(r.id)}` },
  { key: "action",    label: "Actions",       icon: Command,    route: (r) => r.href },
];

// Command aliases — trigger by typing `>` at the start of the palette.
// Each command performs a REAL action (API call or navigation) —
// no mocks. Actions run inside the palette callback so the modal
// closes only when the user picks the row.
function buildCommands({ navigate, closePalette }) {
  const call = async (fn, ok, err) => {
    try {
      await fn();
      toast.success(ok);
    } catch (e) {
      toast.error(err || String(e));
    }
  };
  return [
    {
      id: "cmd:refresh-corpus", icon: RefreshCw, kind: "action",
      label: ">refresh corpus",
      sub:   "Re-poll /api/rc5/golden/summary",
      exec:  () => call(
        () => api.get("/rc5/golden/summary?nocache=1"),
        "Corpus health refreshed",
        "Failed to refresh corpus",
      ),
    },
    {
      id: "cmd:run-benchmark", icon: Gauge, kind: "action",
      label: ">run benchmark",
      sub:   "Kick off the golden benchmark & open the Benchmark page",
      exec:  async () => {
        await call(
          () => api.post("/rc5/golden/run", {}),
          "Benchmark started",
          "Failed to start benchmark",
        );
        closePalette(); navigate("/benchmark");
      },
    },
    {
      id: "cmd:open-recent-case", icon: HistoryIcon, kind: "action",
      label: ">open recent case",
      sub:   "Jump to the latest investigation",
      exec:  async () => {
        try {
          const { data } = await api.get("/investigations?limit=1");
          const list = data?.investigations || data || [];
          const first = list[0];
          if (first?.id || first?._id) {
            closePalette();
            navigate(`/analyst?iid=${encodeURIComponent(first.id || first._id)}`);
          } else {
            toast.info("No recent cases yet");
          }
        } catch { toast.error("Could not fetch recent cases"); }
      },
    },
    {
      id: "cmd:open-training", icon: Rss, kind: "action",
      label: ">open training inbox",
      sub:   "Jump to /admin/training-inbox",
      exec:  () => { closePalette(); navigate("/admin/training-inbox"); },
    },
    {
      id: "cmd:open-heatmap", icon: Target, kind: "action",
      label: ">open mitre heatmap",
      sub:   "Jump to /heatmap",
      exec:  () => { closePalette(); navigate("/heatmap"); },
    },
    {
      id: "cmd:run-battery", icon: Play, kind: "action",
      label: ">run battery",
      sub:   "Kick off the multi-layer regression battery",
      exec:  () => call(
        () => api.post("/battery/rerun", {}),
        "Battery re-run started",
        "Failed to start battery",
      ),
    },
    {
      id: "cmd:change-password", icon: KeyRound, kind: "action",
      label: ">change password",
      sub:   "Open the change-password modal",
      exec:  () => {
        closePalette();
        // Dispatch a custom event the Header listens to.
        window.dispatchEvent(new CustomEvent("nvx-open-change-password"));
      },
    },
    {
      id: "cmd:workspace", icon: Rocket, kind: "action",
      label: ">go workspace",
      sub:   "Jump to the Analyst Workspace",
      exec:  () => { closePalette(); navigate("/"); },
    },
  ];
}

// ─── Small helpers ────────────────────────────────────────────────
// Score a candidate string against a needle.
// Higher = better match. 0 = no match.
//
// Ranking rules (Feb-2026, Cmd+K fuzzy boost):
//   • exact match on the full string      → 1000
//   • starts-with (prefix) match          → 700 + boost by needle length
//   • word-boundary prefix (any token)    → 500 + boost by needle length
//   • plain substring match               → 300 minus distance from start
//   • subsequence match (chars in order)  → 100 minus gap penalty
//   • otherwise                           → 0
// Ties are broken by shorter haystacks (more specific matches).
function scoreMatch(needle, hay) {
  if (!needle) return 1;
  const n = String(needle).toLowerCase();
  const h = String(hay || "").toLowerCase();
  if (!h) return 0;
  if (h === n) return 1000;
  if (h.startsWith(n)) return 700 + n.length * 4 - Math.max(0, h.length - n.length) * 0.1;
  // word-boundary prefix: any token starts with the needle
  const words = h.split(/[\s._\-/:]+/);
  for (const w of words) {
    if (w && w.startsWith(n)) return 500 + n.length * 3;
  }
  const sub = h.indexOf(n);
  if (sub >= 0) return 300 - sub;
  // Subsequence (all needle chars appear in order somewhere in the haystack).
  // Penalise big gaps between matches.
  let i = 0;
  let lastPos = -1;
  let gapPenalty = 0;
  for (const c of h) {
    if (c === n[i]) {
      if (lastPos >= 0) gapPenalty += Math.min(5, (h.indexOf(c, lastPos + 1) - lastPos - 1));
      lastPos = h.indexOf(c, lastPos + 1);
      i += 1;
      if (i === n.length) break;
    }
  }
  if (i === n.length) return Math.max(1, 100 - gapPenalty);
  return 0;
}

// Legacy boolean wrapper — retained for grouped view where we don't
// need a ranking, only a hit/no-hit decision. Callers may prefer
// scoreMatch(...) > 0 directly.
// eslint-disable-next-line no-unused-vars
function fuzzy(needle, hay) {
  return scoreMatch(needle, hay) > 0;
}

function loadRecent() {
  try {
    const v = JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
    return Array.isArray(v) ? v.slice(0, RECENT_MAX) : [];
  } catch { return []; }
}
function saveRecent(item) {
  try {
    const cur = loadRecent().filter((r) => r.__key !== item.__key);
    cur.unshift(item);
    localStorage.setItem(RECENT_KEY, JSON.stringify(cur.slice(0, RECENT_MAX)));
  } catch { /* ignore */ }
}

// Static MITRE seed (top corpus-observed techniques). Merged with any
// techniques the heatmap endpoint returns at load time.
const MITRE_SEED = [
  { id: "T1059", label: "Command and Scripting Interpreter" },
  { id: "T1059.001", label: "PowerShell" },
  { id: "T1059.003", label: "Windows Command Shell" },
  { id: "T1105", label: "Ingress Tool Transfer" },
  { id: "T1547", label: "Boot or Logon Autostart Execution" },
  { id: "T1204", label: "User Execution" },
  { id: "T1055", label: "Process Injection" },
  { id: "T1140", label: "Deobfuscate/Decode Files or Information" },
  { id: "T1027", label: "Obfuscated Files or Information" },
  { id: "T1620", label: "Reflective Code Loading" },
  { id: "T1218", label: "System Binary Proxy Execution" },
  { id: "T1112", label: "Modify Registry" },
  { id: "T1071", label: "Application Layer Protocol" },
  { id: "T1036", label: "Masquerading" },
];

// ═══════════════════════════════════════════════════════════════════
export default function QuickOpenPalette() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const [data, setData] = useState({
    cases: [], samples: [], mitre: MITRE_SEED, training: [], batch: [], documents: [],
  });
  const [recent, setRecent] = useState(() => loadRecent());
  const inputRef = useRef(null);
  const navigate = useNavigate();

  const commands = useMemo(
    () => buildCommands({ navigate, closePalette: () => setOpen(false) }),
    [navigate],
  );
  const isCommandMode = q.startsWith(">");

  // ── Global keyboard trigger ──────────────────────────────────────
  useEffect(() => {
    const onKey = (e) => {
      const meta = e.metaKey || e.ctrlKey;
      if (meta && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setOpen((o) => !o);
        return;
      }
      if (open && e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  // Focus input when opening
  useEffect(() => {
    if (open) {
      setQ("");
      setIdx(0);
      setRecent(loadRecent());
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  // ── Lazy-load searchable sources when palette first opens ────────
  useEffect(() => {
    if (!open) return;
    let cancelled = false;

    const grab = async (fn) => { try { return await fn(); } catch { return null; } };

    (async () => {
      const [cases, samples, training, batch, documents, heatmap] = await Promise.all([
        grab(() => api.get("/investigations?limit=50")),
        grab(() => api.get("/admin/samples")),
        grab(() => api.get("/training-inbox?limit=200")),
        grab(() => api.get("/batch/history?limit=50")),
        grab(() => api.get("/documents?limit=200")),
        grab(() => api.get("/mitre/heatmap")),
      ]);
      if (cancelled) return;

      const cs = cases?.data?.investigations || cases?.data || [];
      const sm = samples?.data?.samples || samples?.data || [];
      const tr = training?.data?.items || training?.data?.drafts || training?.data || [];
      const br = batch?.data?.runs || batch?.data?.history || batch?.data || [];
      const dc = documents?.data?.items || documents?.data?.documents || documents?.data || [];
      const hmTechs = extractMitreFromHeatmap(heatmap?.data);

      setData({
        cases:     Array.isArray(cs) ? cs.slice(0, 100) : [],
        samples:   Array.isArray(sm) ? sm.slice(0, 200) : [],
        mitre:     mergeMitre(MITRE_SEED, hmTechs),
        training:  Array.isArray(tr) ? tr.slice(0, 100) : [],
        batch:     Array.isArray(br) ? br.slice(0, 100) : [],
        documents: Array.isArray(dc) ? dc.slice(0, 100) : [],
      });
    })();

    return () => { cancelled = true; };
  }, [open]);

  // ── Ranked / grouped view ────────────────────────────────────────
  const flatResults = useMemo(() => {
    // Command palette mode — the ">" prefix filters against the
    // aliases only. Rank by exact/prefix/substring boost so typing
    // "ref" surfaces ">refresh corpus" before ">run benchmark".
    if (isCommandMode) {
      const needle = q.slice(1).trim().toLowerCase();
      const ranked = commands
        .map((c) => {
          const s = Math.max(
            scoreMatch(needle, c.label.replace(/^>/, "")),
            scoreMatch(needle, c.sub || ""),
          );
          return { c, s };
        })
        .filter(({ s }) => !needle || s > 0)
        .sort((a, b) => b.s - a.s)
        .map(({ c }) => ({
          __key: c.id, kind: "action",
          id: c.id, label: c.label, sub: c.sub,
          icon: c.icon, exec: c.exec,
        }));
      return ranked;
    }
    const out = [];
    const push = (kind, item, label, sub) => {
      const s = SECTIONS.find(x => x.key === kind);
      const key = `${kind}:${item.id || item._id || label}`;
      out.push({ __key: key, kind, id: item.id || item._id || label, label, sub,
                 raw: item, icon: s?.icon, route: s?.route });
    };
    for (const c of data.cases) {
      const lbl = c.summary || c.raw_input || c.title || c.id;
      push("cases", c, (lbl || "").slice(0, 80), `case · ${c.verdict?.label || "—"}`);
    }
    for (const s of data.samples) {
      push("samples", s, s.name || s.id || "sample", `sample · ${s.category || s.family || "—"}`);
    }
    for (const m of data.mitre) {
      push("mitre", m, `${m.id} · ${m.label || ""}`.trim(), "technique");
    }
    for (const t of data.training) {
      push("training", t, t.title || t.summary || t.headline || "training-note",
           `training · ${t.status || "pending"}`);
    }
    for (const b of data.batch) {
      push("batch", b, b.name || b.run_id || b.id, `batch · ${b.count || b.total || ""}`);
    }
    for (const d of data.documents) {
      push("documents", d, d.filename || d.name || d.id,
           `doc · ${d.mime || d.ext || "—"}`);
    }
    if (!q) return out;
    // Score every candidate: take the MAX of label/sub/kind/id scores.
    // Rows with score 0 are filtered. Sort desc so exact / prefix hits
    // float to the top ("ps1" → "PowerShell" before ".ps1" doc names).
    const scored = out
      .map((r) => {
        const s = Math.max(
          scoreMatch(q, r.label),
          scoreMatch(q, r.sub) * 0.6,       // sub-string of subtitle matters less
          scoreMatch(q, r.kind) * 0.4,
          scoreMatch(q, String(r.id)) * 0.5,
        );
        return { r, s };
      })
      .filter(({ s }) => s > 0)
      .sort((a, b) => b.s - a.s)
      .map(({ r }) => r);
    return scored.slice(0, 60);
  }, [q, data, isCommandMode, commands]);

  const grouped = useMemo(() => {
    const g = {};
    for (const r of flatResults) (g[r.kind] ||= []).push(r);
    return g;
  }, [flatResults]);

  // Reset selection when query changes
  useEffect(() => { setIdx(0); }, [q]);

  // Keyboard nav within the results list
  const activate = useCallback((row) => {
    if (!row) return;
    // Command aliases carry an `exec` function; run it and let the
    // command close the palette itself when appropriate.
    if (typeof row.exec === "function") {
      row.exec();
      return;
    }
    if (!row.route) return;
    saveRecent(row);
    setOpen(false);
    try { navigate(row.route(row)); } catch { /* ignore */ }
  }, [navigate]);

  useEffect(() => {
    if (!open) return;
    const onNav = (e) => {
      if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(i + 1, flatResults.length - 1)); }
      if (e.key === "ArrowUp")   { e.preventDefault(); setIdx((i) => Math.max(i - 1, 0)); }
      if (e.key === "Enter")     { e.preventDefault(); activate(flatResults[idx]); }
    };
    window.addEventListener("keydown", onNav);
    return () => window.removeEventListener("keydown", onNav);
  }, [open, idx, flatResults, activate]);

  if (!open) return null;

  return (
    <div
      data-testid="quick-open-palette"
      onClick={() => setOpen(false)}
      style={{
        position: "fixed", inset: 0, zIndex: 9999,
        background: "rgba(2,6,15,0.72)",
        backdropFilter: "blur(6px)",
        display: "flex", alignItems: "flex-start", justifyContent: "center",
        paddingTop: "12vh",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "min(720px, 92vw)",
          background: "linear-gradient(160deg, rgba(15,23,42,0.95), rgba(2,6,23,0.92))",
          border: "1px solid rgba(148,163,184,0.22)",
          borderRadius: 12,
          boxShadow: "0 32px 64px rgba(2,6,23,0.7), inset 0 1px 0 rgba(255,255,255,0.04)",
          backdropFilter: "blur(24px) saturate(160%)",
          overflow: "hidden",
        }}
      >
        {/* Input */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 16px", borderBottom: "1px solid rgba(148,163,184,0.14)" }}>
          <Search size={16} strokeWidth={1.9} style={{ color: "rgba(148,163,184,0.7)" }} />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Jump to case, sample, MITRE, training note, batch run or document…  (type “>” for commands)"
            data-testid="quick-open-input"
            style={{
              flex: 1,
              background: "transparent", border: "none", outline: "none",
              color: "#e2e8f0",
              fontFamily: "JetBrains Mono, ui-monospace, monospace",
              fontSize: 13, letterSpacing: "0.01em",
            }}
          />
          <kbd style={{
            fontFamily: "JetBrains Mono", fontSize: 9, letterSpacing: "0.06em",
            padding: "2px 7px", borderRadius: 4,
            background: "rgba(148,163,184,0.12)", color: "rgba(203,213,225,0.85)",
            border: "1px solid rgba(148,163,184,0.22)",
          }}>ESC</kbd>
          <button onClick={() => setOpen(false)} aria-label="Close"
                  data-testid="quick-open-close"
                  style={{ background: "transparent", border: "none", color: "rgba(148,163,184,0.7)", cursor: "pointer" }}>
            <X size={15} />
          </button>
        </div>

        {/* Body */}
        <div style={{ maxHeight: "58vh", overflowY: "auto" }}>
          {/* Recent when the query is empty AND not in command mode */}
          {!q && !isCommandMode && recent.length > 0 && (
            <Section title="Recent" icon={HistoryIcon}>
              {recent.map((r, i) => (
                <Row key={r.__key} row={r} active={idx === i} onClick={() => activate(r)}
                     onHover={() => setIdx(i)} />
              ))}
            </Section>
          )}

          {/* Grouped when the query is empty AND not in command mode */}
          {!q && !isCommandMode && SECTIONS.map((s) => {
            const rows = grouped[s.key] || [];
            if (!rows.length) return null;
            return (
              <Section key={s.key} title={s.label} icon={s.icon}>
                {rows.slice(0, 5).map((r) => (
                  <Row key={r.__key} row={r}
                       active={flatResults[idx]?.__key === r.__key}
                       onClick={() => activate(r)}
                       onHover={() => setIdx(flatResults.findIndex(x => x.__key === r.__key))} />
                ))}
              </Section>
            );
          })}

          {/* Flat ranked list when there is a query OR in command mode */}
          {(q || isCommandMode) && (
            flatResults.length === 0 ? (
              <div style={{ padding: 30, textAlign: "center", fontFamily: "JetBrains Mono, ui-monospace, monospace", fontSize: 12, color: "rgba(148,163,184,0.6)" }}>
                No matches for “{q}”
              </div>
            ) : (
              <Section>
                {flatResults.map((r, i) => (
                  <Row key={r.__key} row={r} active={i === idx}
                       onClick={() => activate(r)} onHover={() => setIdx(i)} />
                ))}
              </Section>
            )
          )}
        </div>

        {/* Footer legend */}
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "8px 16px",
          borderTop: "1px solid rgba(148,163,184,0.14)",
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 9, color: "rgba(148,163,184,0.65)",
          letterSpacing: "0.12em", textTransform: "uppercase",
        }}>
          <span>↑↓ navigate · ↵ open · esc close</span>
          <span>NivXRay quick-open</span>
        </div>
      </div>
    </div>
  );
}

// ─── Presentation helpers ────────────────────────────────────────────
function Section({ title, icon: Icon, children }) {
  return (
    <div>
      {title && (
        <div style={{
          padding: "10px 16px 4px",
          display: "flex", alignItems: "center", gap: 8,
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 9, color: "rgba(148,163,184,0.7)",
          letterSpacing: "0.18em", textTransform: "uppercase",
        }}>
          {Icon && <Icon size={11} strokeWidth={1.9} />}
          {title}
        </div>
      )}
      <div>{children}</div>
    </div>
  );
}
function Row({ row, active, onClick, onHover }) {
  const Icon = row.icon || FileText;
  return (
    <button
      onClick={onClick}
      onMouseEnter={onHover}
      data-testid={`quick-open-row-${row.kind}`}
      style={{
        display: "flex", alignItems: "center", gap: 12,
        width: "100%", padding: "10px 16px",
        background: active ? "rgba(34,211,238,0.10)" : "transparent",
        border: "none",
        borderLeft: `2px solid ${active ? "#22d3ee" : "transparent"}`,
        color: "#e2e8f0", textAlign: "left", cursor: "pointer",
        transition: "background 140ms ease",
      }}
    >
      <div style={{
        width: 26, height: 26, borderRadius: 6,
        display: "grid", placeItems: "center",
        background: active ? "rgba(34,211,238,0.15)" : "rgba(148,163,184,0.06)",
        border: `1px solid ${active ? "rgba(34,211,238,0.45)" : "rgba(148,163,184,0.14)"}`,
        color: active ? "#67e8f9" : "rgba(203,213,225,0.72)",
        flexShrink: 0,
      }}>
        <Icon size={13} strokeWidth={1.9} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {row.label}
        </div>
        <div style={{
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 10, color: "rgba(148,163,184,0.65)",
          whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
        }}>{row.sub}</div>
      </div>
      {active && <ArrowRight size={13} color="#67e8f9" />}
    </button>
  );
}

// ─── Data helpers ───────────────────────────────────────────────────
function extractMitreFromHeatmap(heatmap) {
  if (!heatmap) return [];
  const out = [];
  const stack = Array.isArray(heatmap) ? heatmap : [heatmap];
  while (stack.length) {
    const n = stack.pop();
    if (!n || typeof n !== "object") continue;
    if (typeof n.tid === "string" && n.tid.match(/^T\d{4}(\.\d+)?$/)) {
      out.push({ id: n.tid, label: n.name || n.technique || n.title || "" });
    }
    for (const v of Object.values(n)) {
      if (Array.isArray(v)) stack.push(...v);
      else if (v && typeof v === "object") stack.push(v);
    }
  }
  return out.slice(0, 200);
}
function mergeMitre(seed, extra) {
  const map = new Map();
  for (const s of seed) map.set(s.id, s);
  for (const e of extra || []) if (!map.has(e.id)) map.set(e.id, e);
  return Array.from(map.values()).slice(0, 200);
}
