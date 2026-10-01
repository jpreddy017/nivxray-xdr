/**
 * GlobalSearch — workspace-wide, IKG-backed instant search.
 *
 * Trigger : Cmd/Ctrl+K anywhere inside the Investigation Workspace, or
 *           the toolbar magnifier icon.
 * Scope   : Every node in the currently-loaded IKG:
 *             Processes · Files · Registry · Network · Modules · Services ·
 *             Tasks · MITRE techniques · Events (frames).
 * Ranking : Deterministic. Matches on label + attrs.action + attrs.cmdline
 *           + node id. Exact-substring is scored higher than tokenised.
 * Result  : Clicking (or pressing Enter) sets the global SelectionContext.
 *           Every other view (Trajectory · Story · Process Tree ·
 *           Evidence Card) refocuses immediately.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { T } from "../theme";
import { useSelection } from "./SelectionContext";

const TYPE_LABEL = {
  process:   "Process",
  file:      "File",
  registry:  "Registry",
  network:   "Network",
  module:    "Module",
  service:   "Service",
  task:      "Task",
  technique: "ATT&CK",
  event:     "Event",
  kb:        "IKB",
};

const TYPE_TONE = {
  process:   "#7DB1D6",
  file:      "#4ADE80",
  registry:  "#F5A34C",
  network:   "#FCA5A5",
  event:     "#D4C069",
  technique: "#7DB1D6",
  kb:        "#A78BFA",
};

const SEARCHABLE_TYPES = new Set([
  "process", "file", "registry", "network", "module",
  "service", "task", "technique", "event",
]);


function scoreMatch(query, node) {
  const q = query.toLowerCase();
  if (!q) return 0;
  const label = String(node.label || "").toLowerCase();
  const id    = String(node.id    || "").toLowerCase();
  const attrs = node.attrs || {};
  const hayFields = [
    label, id,
    String(attrs.action  || ""), String(attrs.cmdline || ""),
    String(attrs.rule_id || ""),
    ...(attrs.mitre || []).map(String),
    String(attrs.technique_id || ""),
  ].map(s => s.toLowerCase());

  let best = 0;
  for (const h of hayFields) {
    if (!h) continue;
    if (h === q)              best = Math.max(best, 100);
    else if (h.startsWith(q)) best = Math.max(best, 80);
    else if (h.includes(q))   best = Math.max(best, 60);
    else {
      const parts = q.split(/\s+/).filter(Boolean);
      if (parts.length > 1 && parts.every(p => h.includes(p))) {
        best = Math.max(best, 40);
      }
    }
  }
  // Small boost so exact-label matches always win over cmdline substrings.
  if (label === q) best += 20;
  return best;
}


export default function GlobalSearch({ inv }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef(null);
  const { setSelection } = useSelection();

  // Keyboard shortcut · Cmd/Ctrl+K
  useEffect(() => {
    const onKey = (e) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setOpen(o => !o);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 0);
      setQuery(""); setCursor(0);
    }
  }, [open]);

  const results = useMemo(() => {
    if (!query.trim() || !inv?.ikg?.nodes) return [];
    const scored = [];
    for (const n of inv.ikg.nodes) {
      if (!SEARCHABLE_TYPES.has(n.type)) continue;
      const s = scoreMatch(query.trim(), n);
      if (s > 0) scored.push({ node: n, score: s });
    }
    // Also search Investigation Knowledge Base entries — treat each entry
    // as a synthetic "kb" node so it slots into the same result list.
    for (const e of (inv?.ikb?.entries || [])) {
      const synth = {
        id:    "kb::" + e.id,
        type:  "kb",
        label: e.label,
        attrs: { action: e.description, cmdline: (e.category || ""),
                 target: e.id, kb_kind: e.kind },
      };
      const s = scoreMatch(query.trim(), synth);
      if (s > 0) scored.push({ node: synth, score: s });
    }
    scored.sort((a, b) => b.score - a.score
                        || String(a.node.label).localeCompare(String(b.node.label)));
    return scored.slice(0, 30);
  }, [query, inv]);

  useEffect(() => { setCursor(0); }, [query]);

  const pick = (item) => {
    const n = item.node;
    if (n.type === "event") {
      // Find its process via executed_by
      const eb = (inv.ikg.edges || []).find(e => e.type === "executed_by" && e.source === n.id);
      setSelection({
        kind: "event", id: n.id, frame_iid: n.id,
        process_iid: eb ? eb.target : null, source: "search",
      });
    } else if (n.type === "process") {
      setSelection({
        kind: "process", id: n.id, process_iid: n.id,
        frame_iid: null, source: "search",
      });
    } else if (n.type === "technique") {
      setSelection({
        kind: "technique", id: n.id, technique_id: n.attrs?.technique_id,
        source: "search",
      });
    } else {
      // File / registry / network / module / service / task — treat as
      // process-anchored via first inbound edge from a process.
      const e = (inv.ikg.edges || []).find(x => x.target === n.id);
      setSelection({
        kind: n.type, id: n.id,
        process_iid: e ? e.source : null,
        frame_iid: null, source: "search",
      });
    }
    setOpen(false);
  };

  const onKeyDown = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setCursor(c => Math.min(results.length - 1, c + 1)); }
    else if (e.key === "ArrowUp")   { e.preventDefault(); setCursor(c => Math.max(0, c - 1)); }
    else if (e.key === "Enter" && results[cursor]) { pick(results[cursor]); }
    else if (e.key === "Escape") setOpen(false);
  };

  return (
    <>
      {/* Toolbar trigger (rendered inline by parent header if desired). */}
      <button data-testid="btn-open-global-search"
              onClick={() => setOpen(true)}
              title="Search the investigation (⌘K)"
              className="text-[10px] font-mono px-2 py-1 rounded flex items-center gap-1.5 hover:opacity-80"
              style={{ background: T.paper2, color: T.inkMute,
                       border: `1px solid ${T.line}` }}>
        <span style={{ fontSize: 12 }}>⌕</span>
        Search
        <span className="text-[9px] px-1 rounded"
              style={{ background: T.paper, color: T.inkFaint,
                       border: `1px solid ${T.line}` }}>⌘K</span>
      </button>

      {open && (
        <div data-testid="global-search-overlay"
             className="fixed inset-0 z-50 flex items-start justify-center pt-20"
             style={{ background: "rgba(0,0,0,0.7)" }}
             onClick={() => setOpen(false)}>
          <div className="rounded-md w-full max-w-xl mx-4 flex flex-col"
               style={{ background: T.paper, border: `1px solid ${T.line}`,
                        maxHeight: "70vh", boxShadow: "0 12px 48px rgba(0,0,0,0.6)" }}
               onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-2 px-3 py-2 border-b"
                 style={{ borderColor: T.line }}>
              <span style={{ color: T.emerald, fontSize: 14 }}>⌕</span>
              <input ref={inputRef}
                     value={query}
                     onChange={(e) => setQuery(e.target.value)}
                     onKeyDown={onKeyDown}
                     data-testid="global-search-input"
                     placeholder="Search processes, files, registry, network, techniques, events…"
                     className="flex-1 bg-transparent outline-none text-[13px] font-mono"
                     style={{ color: T.ink }} />
              <span className="text-[9px] font-mono" style={{ color: T.inkFaint }}>
                {results.length} · esc
              </span>
            </div>

            <div className="flex-1 overflow-y-auto py-1"
                 data-testid="global-search-results">
              {query.trim() === "" ? (
                <div className="px-3 py-6 text-[11px] text-center"
                     style={{ color: T.inkFaint }}>
                  Type to search across the Investigation Knowledge Graph<br />
                  ⌘K anywhere in the workspace · ↑ ↓ Enter to select
                </div>
              ) : results.length === 0 ? (
                <div className="px-3 py-6 text-[11px] text-center"
                     style={{ color: T.inkFaint }}>
                  No matches for "{query}" in this investigation.
                </div>
              ) : (
                results.map((r, i) => {
                  const n = r.node;
                  const tone = TYPE_TONE[n.type] || T.ink;
                  const active = i === cursor;
                  const attrs = n.attrs || {};
                  const sub = attrs.cmdline || attrs.action || attrs.target
                            || attrs.technique_id || attrs.ts || n.id;
                  return (
                    <button key={n.id}
                            data-testid={`search-result-${i}`}
                            onMouseEnter={() => setCursor(i)}
                            onClick={() => pick(r)}
                            className="w-full flex items-start gap-3 px-3 py-2 text-left transition-colors"
                            style={{ background: active ? T.paper2 : "transparent" }}>
                      <span className="text-[9px] tracking-[1.2px] font-bold px-1.5 py-0.5 rounded flex-shrink-0 mt-0.5"
                            style={{ background: T.paper2, color: tone,
                                     border: `1px solid ${tone}44`,
                                     minWidth: 60, textAlign: "center" }}>
                        {TYPE_LABEL[n.type] || n.type}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="text-[12px] font-mono truncate"
                             style={{ color: T.ink }}>{n.label}</div>
                        <div className="text-[10px] font-mono truncate mt-0.5"
                             style={{ color: T.inkFaint }} title={String(sub)}>
                          {String(sub)}
                        </div>
                      </div>
                      <span className="text-[9px] font-mono" style={{ color: T.inkFaint }}>
                        {r.score}
                      </span>
                    </button>
                  );
                })
              )}
            </div>

            <div className="text-[9px] font-mono px-3 py-1.5 border-t flex items-center gap-3"
                 style={{ borderColor: T.line, color: T.inkFaint }}>
              <span>↑↓ navigate</span>
              <span>↵ select</span>
              <span>esc close</span>
              <span className="ml-auto">
                {inv?.ikg?.stats?.nodes || 0} nodes in IKG
              </span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
