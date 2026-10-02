import React, { useState } from "react";

export const SIDEBAR_KEY = "nvx.sidebar.collapsed";
export const readCollapsed = () => { try { return window.localStorage.getItem(SIDEBAR_KEY) === "1"; } catch { return false; } };
export function setCollapsedGlobal(v) {
  try { window.localStorage.setItem(SIDEBAR_KEY, v ? "1" : "0"); } catch { /* ok */ }
  window.dispatchEvent(new CustomEvent("nvx-sidebar", { detail: v }));
}

/** EDR shell navigation: expanded (icons + names) or an Outlook-style icon rail. */
export default function EdrSidebar({ nav, active, collapsed, onToggle, onGo }) {
  const [tip, setTip] = useState(null);
  const show = (text) => (e) => {
    if (!collapsed) return;
    const r = e.currentTarget.getBoundingClientRect();
    setTip({ text, top: r.top + r.height / 2, left: r.right + 10 });
  };
  const hide = () => setTip(null);
  return (
    <aside className={`sidebar${collapsed ? " collapsed" : ""}`} data-testid="nvf-sidebar" data-collapsed={collapsed ? "1" : "0"}>
      <button type="button" className="nav-toggle" data-testid="nvf-sidebar-toggle" aria-expanded={!collapsed}
              aria-label={collapsed ? "Expand navigation" : "Collapse navigation"} title={collapsed ? "Expand navigation" : "Collapse navigation"}
              onClick={() => { hide(); onToggle(); }}>
        <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true" data-testid="nvf-sidebar-hamburger"><path d="M2 4h14M2 9h14M2 14h14" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>
      </button>
      {nav.map((section, si) => (
        <React.Fragment key={section.title}>
          {collapsed ? (si > 0 && <div className="nav-sep" data-testid="nvf-nav-sep" role="separator" />)
            : <div className="nav-title">{section.title}</div>}
          {section.items.map((t) => {
            const Icon = t.icon, ni = !t.to, isActive = t.key === active;
            const tipText = ni ? `${t.label} — not implemented` : t.label;
            const common = { onMouseEnter: show(tipText), onMouseLeave: hide, onFocus: show(tipText), onBlur: hide,
              "aria-label": collapsed ? tipText : undefined, "data-testid": `nvf-nav-${t.key}` };
            if (ni) {
              return (
                <button key={t.key} type="button" className="nav-item disabled" aria-disabled="true" title={collapsed ? undefined : t.reason}
                        data-state="NOT_IMPLEMENTED" onClick={(e) => e.preventDefault()} {...common}>
                  <span className="ic"><Icon size={collapsed ? 17 : 13} /></span>
                  <span className="lbl">{t.label}</span>
                  <span className="chip" style={{ marginLeft: "auto", fontSize: 8, padding: "0 4px" }}>N/I</span>
                </button>
              );
            }
            return (
              <button key={t.key} type="button" className={`nav-item ${isActive ? "active" : ""}`} onClick={() => { hide(); onGo(t.to); }}
                      data-active={isActive || undefined} aria-current={isActive ? "page" : undefined} {...common}>
                <span className="ic"><Icon size={collapsed ? 17 : 13} /></span>
                <span className="lbl">{t.label}</span>
                {t.children?.length > 0 && !collapsed && <span data-testid={`nvf-nav-chevron-${t.key}`} style={{ marginLeft: "auto", opacity: 0.6 }}>›</span>}
              </button>
            );
          })}
        </React.Fragment>
      ))}
      {collapsed && tip && <div className="nav-rail-tip" role="tooltip" data-testid="nvf-rail-tooltip" style={{ top: tip.top, left: tip.left }}>{tip.text}</div>}
    </aside>
  );
}
