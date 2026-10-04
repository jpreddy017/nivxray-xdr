/**
 * XdrRibbon · NivXRay XDR persistent ribbon.
 *
 * TARGET: Cisco XDR's ribbon, verified from
 * docs.xdr.security.cisco.com/Content/Ribbon/ribbon.htm (2026-06):
 *   • persistent across every page, pinned to the BOTTOM of the viewport
 *   • EXPANDED by default; collapses to a floating button (bottom-left by
 *     default, position configurable in ribbon settings)
 *   • vertically resizable by dragging the container's top edge, or via the
 *     double-arrow handle on that edge
 *   • hosts ribbon apps: Incidents (split-pane list + detail), Casebook,
 *     observable search, and ribbon Settings (incl. Defang on Copy)
 *
 * NivXRay XDR reality, stated on the surface rather than hidden:
 *   • Incidents app is REAL — it reads /api/incidents, the same authoritative
 *     projection the Incidents page uses.
 *   • Casebook is NOT implemented. There is no case store, so the app says so
 *     instead of rendering an empty list that looks like "no cases yet".
 *   • Observable search routes into the real federated search page.
 */
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronsUp, ChevronsDown, X, AlertOctagon, Notebook, Search,
         Settings, Bell, Ban } from "lucide-react";
import api from "@/lib/api";
import { readRibbon, writeRibbon, RIBBON_MIN, RIBBON_MAX }
  from "@/xdr/lib/ribbonSettings";
import { priorityBand } from "@/xdr/lib/ciscoSemantics";

const APPS = [
  { key: "incidents",   label: "Incidents",   icon: AlertOctagon },
  { key: "casebook",    label: "Casebook",    icon: Notebook },
  { key: "observables", label: "Observables", icon: Search },
  { key: "settings",    label: "Settings",    icon: Settings },
];

function IncidentsApp({ onOpen }) {
  const [rows, setRows]   = useState(null);
  const [error, setError] = useState(null);
  const [sel, setSel]     = useState(null);

  useEffect(() => {
    let dead = false;
    api.get("/incidents?limit=25")
      .then((r) => {
        if (dead) return;
        const d = r?.data ?? r;
        setRows(d?.incidents || d?.data || (Array.isArray(d) ? d : []));
      })
      .catch((e) => !dead && setError(String(e?.message || e)));
    return () => { dead = true; };
  }, []);

  if (error) {
    return (
      <div className="mono" data-testid="xdr-ribbon-incidents-error"
           style={{ padding: 12, fontSize: 11, color: "var(--nx-danger, #d64545)" }}>
        INCIDENTS UNAVAILABLE · {error}
      </div>
    );
  }
  if (rows === null) {
    return (
      <div className="mono" data-testid="xdr-ribbon-incidents-loading"
           style={{ padding: 12, fontSize: 11, color: "var(--faint)" }}>
        Loading incidents…
      </div>
    );
  }
  if (rows.length === 0) {
    return (
      <div className="mono" data-testid="xdr-ribbon-incidents-empty"
           style={{ padding: 12, fontSize: 11, color: "var(--faint)" }}>
        No incidents returned by /api/incidents for this tenant.
      </div>
    );
  }

  const active = sel || rows[0];
  return (
    <div data-testid="xdr-ribbon-incidents"
         style={{ display: "grid", gridTemplateColumns: "minmax(280px, 42%) 1fr",
                   height: "100%", overflow: "hidden" }}>
      <div style={{ overflowY: "auto", borderRight: "1px solid var(--line)" }}>
        {rows.map((r) => {
          const band = priorityBand(r.priority_score ?? r.priority ?? null);
          const on = active?.id === r.id;
          return (
            <button key={r.id} type="button"
                    data-testid={`xdr-ribbon-incident-${r.id}`}
                    onClick={() => setSel(r)}
                    style={{ display: "block", width: "100%", textAlign: "left",
                              padding: "7px 10px", border: 0, cursor: "pointer",
                              background: on ? "var(--hover, rgba(0,0,0,.05))"
                                             : "transparent",
                              borderBottom: "1px solid var(--line)" }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span className="mono" data-priority-band={band.band || "none"}
                      style={{ fontSize: 9, fontWeight: 800,
                                color: `var(--nx-band-${band.band || "none"}, var(--faint))` }}>
                  {band.scored ? `${band.score} ${band.label.toUpperCase()}`
                               : "NOT SCORED"}
                </span>
                <span className="mono" style={{ fontSize: 9.5,
                                                 color: "var(--faint)" }}>
                  {r.status || r.state || ""}
                </span>
              </div>
              <div style={{ fontSize: 11.5, marginTop: 2 }}>
                {r.title || r.name || r.id}
              </div>
            </button>
          );
        })}
      </div>
      <div style={{ overflowY: "auto", padding: "10px 12px" }}
           data-testid="xdr-ribbon-incident-detail">
        <div style={{ fontSize: 12.5, fontWeight: 700 }}>
          {active.title || active.name || active.id}
        </div>
        <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                        marginTop: 3 }}>
          {active.id}
        </div>
        <button type="button" className="btn primary"
                data-testid="xdr-ribbon-incident-open"
                style={{ marginTop: 10, fontSize: 11 }}
                onClick={() => onOpen(`/xdr/incidents/${active.id}`)}>
          Open incident record
        </button>
      </div>
    </div>
  );
}

function CasebookApp() {
  return (
    <div data-testid="xdr-ribbon-casebook" data-state="NOT_IMPLEMENTED"
         style={{ padding: 14, display: "flex", flexDirection: "column",
                   gap: 6 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6,
                     fontSize: 12, fontWeight: 700 }}>
        <Ban size={13} /> Casebook is not implemented
      </div>
      <div className="mono" style={{ fontSize: 10.5, lineHeight: 1.6,
                                      color: "var(--faint)", maxWidth: 620 }}>
        NivXRay XDR has no case store behind this app, so there are no cases to
        list, no observables to attach, and the pivot menu's "Add to new case"
        and "Add to active case" rows are disabled for the same reason. An
        empty list is not shown here, because an empty list is
        indistinguishable from a working casebook with no cases in it.
      </div>
    </div>
  );
}

function ObservablesApp({ onOpen }) {
  const [q, setQ] = useState("");
  return (
    <form data-testid="xdr-ribbon-observables"
          onSubmit={(e) => {
            e.preventDefault();
            if (q.trim()) onOpen(`/xdr/search?q=${encodeURIComponent(q.trim())}`);
          }}
          style={{ padding: 14, display: "flex", flexDirection: "column",
                    gap: 8, maxWidth: 720 }}>
      <div style={{ fontSize: 12, fontWeight: 700 }}>Observable search</div>
      <div style={{ display: "flex", gap: 6 }}>
        <input value={q} onChange={(e) => setQ(e.target.value)}
               data-testid="xdr-ribbon-observables-input"
               placeholder="Hash, IP, domain, URL, device, user…"
               style={{ flex: 1, padding: "6px 9px", fontSize: 12 }} />
        <button type="submit" className="btn primary"
                data-testid="xdr-ribbon-observables-submit"
                style={{ fontSize: 11 }}>Search</button>
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                      lineHeight: 1.6 }}>
        Routes into NivXRay XDR federated search, which reports per entity type
        whether it is searchable and why.
      </div>
    </form>
  );
}

function SettingsApp({ cfg, set }) {
  const Toggle = ({ id, label, note, value, onChange }) => (
    <label data-testid={`xdr-ribbon-setting-${id}`}
           style={{ display: "flex", gap: 9, alignItems: "flex-start",
                     padding: "7px 0", cursor: "pointer" }}>
      <input type="checkbox" checked={!!value}
             data-testid={`xdr-ribbon-setting-${id}-input`}
             onChange={(e) => onChange(e.target.checked)}
             style={{ marginTop: 2 }} />
      <span>
        <span style={{ fontSize: 12 }}>{label}</span>
        <span className="mono" style={{ display: "block", fontSize: 10,
                                         color: "var(--faint)",
                                         lineHeight: 1.6, maxWidth: 620 }}>
          {note}
        </span>
      </span>
    </label>
  );
  return (
    <div data-testid="xdr-ribbon-settings" style={{ padding: 14 }}>
      <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 4 }}>
        Ribbon settings
      </div>
      <Toggle id="defang" label="Defang on copy" value={cfg.defangOnCopy}
              onChange={(v) => set({ defangOnCopy: v })}
              note={'When on, the pivot menu drops "Copy defanged value" and '
                    + '"Copy value" copies the defanged form '
                    + '(216.238.85[.]220, hxxp://…), so a malicious value '
                    + "cannot be clicked by accident."} />
      <div style={{ display: "flex", gap: 8, alignItems: "center",
                     marginTop: 10 }}>
        <span style={{ fontSize: 12 }}>Collapsed position</span>
        {["left", "right"].map((s) => (
          <button key={s} type="button" className="btn"
                  data-testid={`xdr-ribbon-side-${s}`}
                  data-active={cfg.side === s ? "true" : "false"}
                  onClick={() => set({ side: s })}
                  style={{ fontSize: 10, padding: "2px 8px",
                            opacity: cfg.side === s ? 1 : 0.55 }}>
            {s}
          </button>
        ))}
      </div>
    </div>
  );
}

export default function XdrRibbon() {
  const [cfg, setCfg] = useState(readRibbon);
  const navigate = useNavigate();
  const dragRef = useRef(null);

  const set = useCallback((patch) => setCfg(writeRibbon(patch)), []);
  const onOpen = (to) => { navigate(to); };

  // Drag the top edge to resize, exactly as Cisco's ribbon does.
  useEffect(() => {
    const onMove = (e) => {
      if (!dragRef.current) return;
      const h = Math.min(RIBBON_MAX,
                  Math.max(RIBBON_MIN, window.innerHeight - e.clientY));
      setCfg((c) => ({ ...c, height: h }));
    };
    const onUp = () => {
      if (!dragRef.current) return;
      dragRef.current = null;
      setCfg((c) => writeRibbon({ height: c.height }));
      document.body.style.userSelect = "";
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  if (!cfg.expanded) {
    return (
      <button type="button" className="btn"
              data-testid="xdr-ribbon-collapsed"
              onClick={() => set({ expanded: true })}
              title="Open the NivXRay XDR ribbon"
              style={{ position: "fixed", bottom: 16, zIndex: 60,
                        [cfg.side === "right" ? "right" : "left"]: 16,
                        borderRadius: 999, padding: "8px 14px",
                        boxShadow: "0 6px 20px rgba(0,0,0,.22)" }}>
        <ChevronsUp size={13} /> Ribbon
      </button>
    );
  }

  const Active = {
    incidents:   <IncidentsApp onOpen={onOpen} />,
    casebook:    <CasebookApp />,
    observables: <ObservablesApp onOpen={onOpen} />,
    settings:    <SettingsApp cfg={cfg} set={set} />,
  }[cfg.app] || null;

  return (
    <section data-testid="xdr-ribbon" aria-label="NivXRay XDR ribbon"
             style={{ position: "fixed", left: 0, right: 0, bottom: 0,
                       height: cfg.height, zIndex: 60,
                       background: "var(--panel, var(--bg))",
                       borderTop: "1px solid var(--line)",
                       boxShadow: "0 -8px 24px rgba(0,0,0,.14)",
                       display: "flex", flexDirection: "column" }}>
      <div data-testid="xdr-ribbon-resize"
           onMouseDown={() => {
             dragRef.current = true;
             document.body.style.userSelect = "none";
           }}
           title="Drag to resize the ribbon"
           style={{ height: 10, cursor: "ns-resize", display: "flex",
                     alignItems: "center", justifyContent: "center" }}>
        <span style={{ width: 34, height: 3, borderRadius: 2,
                        background: "var(--line)" }} />
      </div>

      <header style={{ display: "flex", alignItems: "center", gap: 4,
                        padding: "0 8px 6px", borderBottom:
                          "1px solid var(--line)" }}>
        {APPS.map((a) => {
          const Icon = a.icon;
          const on = cfg.app === a.key;
          return (
            <button key={a.key} type="button" className="btn"
                    data-testid={`xdr-ribbon-app-${a.key}`}
                    data-active={on ? "true" : "false"}
                    onClick={() => set({ app: a.key })}
                    style={{ fontSize: 11, padding: "4px 10px",
                              opacity: on ? 1 : 0.6,
                              borderBottom: on
                                ? "2px solid var(--accent, #049fd9)"
                                : "2px solid transparent" }}>
              <Icon size={12} /> {a.label}
            </button>
          );
        })}
        <div style={{ flex: 1 }} />
        <button type="button" className="btn ghost"
                data-testid="xdr-ribbon-notifications"
                title="Notifications" style={{ padding: "4px 8px" }}>
          <Bell size={12} />
        </button>
        <button type="button" className="btn ghost"
                data-testid="xdr-ribbon-collapse"
                onClick={() => set({ expanded: false })}
                title="Collapse the ribbon" style={{ padding: "4px 8px" }}>
          <ChevronsDown size={13} />
        </button>
      </header>

      <div style={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
        {Active}
      </div>
    </section>
  );
}
