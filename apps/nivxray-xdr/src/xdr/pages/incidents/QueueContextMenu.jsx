/**
 * QueueContextMenu · CELL-AWARE right-click actions on a queue row.
 *
 * Owner request 2026-09-05 (ServiceNow / Cisco MSS parity): the options
 * offered must depend on WHAT was right-clicked — the incident number
 * gives navigation + ownership actions, while a value cell (owner,
 * customer, detection source, priority, severity, verdict, technique)
 * gives "Show matching" and copy actions.
 *
 * Honest-state rule: every item is backed by something that EXISTS —
 * the audited assign endpoint, a real query parameter the API honours,
 * or a pure client capability (open / new tab / new window / copy).
 * "Filter out" is deliberately ABSENT: the API has no negation
 * predicate yet, and NivXRay does not offer a control it cannot honour.
 */
import React, { useEffect, useRef } from "react";
import {
  ExternalLink, Copy, UserCheck, UserMinus, Link2, Eye,
  Filter, AppWindow,
} from "lucide-react";
import { incidentNumber } from "./QueueTable";

// Columns whose value maps to a real API query parameter.
const FILTERABLE = {
  assignee:         { param: "assignment", label: "owner" },
  customer:         { param: "customer",         label: "customer" },
  detection_source: { param: "detection_source", label: "detection source" },
  priority:         { param: "priority",         label: "priority" },
  severity:         { param: "severity",         label: "severity" },
  verdict:          { param: "verdict",          label: "verdict" },
  mitre:            { param: "technique",        label: "technique" },
};

function cellValue(row, col) {
  switch (col) {
    case "assignee": return row.assignee || null;
    case "customer": return row.customer || null;
    case "detection_source": return row.detection_source || null;
    case "priority": return row.priority?.code || row.priority || null;
    case "severity": return row.severity || null;
    case "verdict":  return row.verdict?.stage2_label || row.verdict || null;
    case "mitre":    return (row.techniques_top || [])[0] || null;
    default: return null;
  }
}

export default function QueueContextMenu({
  row, at, col, currentUser, onClose,
  onOpen, onOpenNewTab, onOpenNewWindow, onPreview,
  onAssignToMe, onUnassign, onShowMatching, onToast,
}) {
  const ref = useRef(null);

  useEffect(() => {
    const away = (e) => { if (!ref.current?.contains(e.target)) onClose(); };
    const esc  = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
    };
  }, [onClose]);

  if (!row) return null;

  const mine  = row.assignee && currentUser && row.assignee === currentUser;
  const url   = `${window.location.origin}/xdr/incidents/${row.id}`;
  const value = cellValue(row, col);
  const filt  = FILTERABLE[col];

  const copy = async (v, what) => {
    try {
      await navigator.clipboard.writeText(v);
      onToast?.(`${what} copied`);
    } catch { onToast?.("Clipboard unavailable in this browser context"); }
    onClose();
  };

  const items = [];

  // ── 1 · Value-cell actions come FIRST when a value was clicked ────
  if (filt && value) {
    items.push({
      id: "show-matching",
      label: `Show matching ${filt.label} · ${String(value).slice(0, 28)}`,
      Icon: Filter,
      run: () => {
        // Owner cell filters by WORK MANAGEMENT (mine / team), never by
        // visibility — visibility is tenant authorization.
        const v = filt.param === "assignment"
          ? (mine ? "mine" : "team")
          : value;
        onShowMatching(filt.param, v);
        onClose();
      },
    });
    items.push({
      id: "copy-value",
      label: `Copy ${filt.label}`,
      Icon: Copy,
      run: () => copy(String(value), filt.label.replace(/^\w/, c => c.toUpperCase())),
    });
    items.push({ sep: true });
  }

  // ── 2 · Navigation (always available) ─────────────────────────────
  items.push(
    { id: "open",           label: "Open incident",        Icon: Eye,
      run: () => { onOpen(row); onClose(); } },
    { id: "open-new-tab",   label: "Open in new tab",      Icon: ExternalLink,
      run: () => { onOpenNewTab(row); onClose(); } },
    { id: "open-new-window", label: "Open in new window",  Icon: AppWindow,
      run: () => { onOpenNewWindow(row); onClose(); } },
    { id: "preview",        label: "Preview in side panel", Icon: Eye,
      run: () => { onPreview(row); onClose(); } },
    { sep: true },
  );

  // ── 3 · Ownership · "Assign to me" is ALWAYS offered ──────────────
  items.push({
    id: "assign-to-me",
    label: mine ? "Assign to me (already yours)" : "Assign to me",
    Icon: UserCheck,
    run: async () => { await onAssignToMe(row); onClose(); },
  });
  if (row.assignee) {
    items.push({
      id: "unassign",
      label: mine ? "Release (unassign me)" : `Release from ${row.assignee}`,
      Icon: UserMinus,
      run: async () => { await onUnassign(row); onClose(); },
    });
  }

  // ── 4 · Copy ──────────────────────────────────────────────────────
  items.push(
    { sep: true },
    { id: "copy-number", label: "Copy incident number", Icon: Copy,
      run: () => copy(incidentNumber(row.id), "Incident number") },
    { id: "copy-id",     label: "Copy authoritative id", Icon: Copy,
      run: () => copy(row.id, "Incident id") },
    { id: "copy-link",   label: "Copy URL to clipboard",  Icon: Link2,
      run: () => copy(url, "URL") },
  );

  const style = {
    position: "fixed",
    top:  Math.min(at.y, Math.max(8, window.innerHeight - 26 * items.length - 70)),
    left: Math.min(at.x, window.innerWidth - 280),
    zIndex: 2000,
  };

  return (
    <div ref={ref} className="ql-ctx" style={style}
          role="menu" data-testid="ql-context-menu" data-ctx-col={col || "row"}>
      <div className="ql-ctx__head">
        <span className="ql-ctx__num">{incidentNumber(row.id)}</span>
        <span className="ql-ctx__owner">
          {filt && value
            ? `${filt.label.toUpperCase()} · ${String(value).slice(0, 30)}`
            : (row.assignee ? `OWNER · ${row.assignee}` : "UNASSIGNED")}
        </span>
      </div>
      {items.map((it, i) => it.sep
        ? <div key={`sep-${i}`} className="ql-ctx__sep" />
        : (
          <button key={it.id} className="ql-ctx__item" role="menuitem"
                   onClick={it.run} data-testid={`ql-ctx-${it.id}`}>
            <it.Icon size={12} />
            <span>{it.label}</span>
          </button>
        ))}
    </div>
  );
}
