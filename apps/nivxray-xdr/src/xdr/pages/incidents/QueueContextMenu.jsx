/**
 * QueueContextMenu · right-click work-management actions on a queue row.
 *
 * Owner request 2026-09-05 (ServiceNow / Cisco MSS parity): right-click
 * an incident number and act on it without leaving the queue.
 *
 * Honest-state rule: every item here is backed by an endpoint that
 * EXISTS today (PATCH /api/incidents/{id}/assignee) or by a pure
 * client capability (open, open in new tab, copy).  No item is a
 * decorative stub — if we cannot honour it, it is not in this menu.
 */
import React, { useEffect, useRef } from "react";
import {
  ExternalLink, Copy, UserCheck, UserMinus, Link2, Eye,
} from "lucide-react";
import { incidentNumber } from "./QueueTable";

export default function QueueContextMenu({
  row, at, currentUser, onClose,
  onOpen, onOpenNewTab, onPreview, onAssignToMe, onUnassign, onToast,
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

  const mine = row.assignee && currentUser && row.assignee === currentUser;
  const copy = async (value, what) => {
    try {
      await navigator.clipboard.writeText(value);
      onToast?.(`${what} copied`);
    } catch {
      onToast?.("Clipboard unavailable in this browser context");
    }
    onClose();
  };

  const items = [
    { id: "open",         label: "Open incident",            Icon: Eye,
      run: () => { onOpen(row); onClose(); } },
    { id: "open-new-tab", label: "Open in new tab",          Icon: ExternalLink,
      run: () => { onOpenNewTab(row); onClose(); } },
    { id: "preview",      label: "Preview in side panel",    Icon: Eye,
      run: () => { onPreview(row); onClose(); } },
    { sep: true },
    // "Assign to me" is ALWAYS offered (owner request 2026-09-05) —
    // it is idempotent, so taking an incident already yours is a no-op
    // rather than a hidden control.  "Release" appears in addition
    // whenever the incident actually has an owner.
    { id: "assign-to-me",
      label: mine ? "Assign to me (already yours)" : "Assign to me",
      Icon: UserCheck,
      run: async () => { await onAssignToMe(row); onClose(); } },
    ...(row.assignee
      ? [{ id: "unassign",
             label: mine ? "Release (unassign me)" : `Release from ${row.assignee}`,
             Icon: UserMinus,
             run: async () => { await onUnassign(row); onClose(); } }]
      : []),
    { sep: true },
    { id: "copy-number",  label: "Copy incident number",     Icon: Copy,
      run: () => copy(incidentNumber(row.id), "Incident number") },
    { id: "copy-id",      label: "Copy authoritative id",    Icon: Copy,
      run: () => copy(row.id, "Incident id") },
    { id: "copy-link",    label: "Copy deep link",           Icon: Link2,
      run: () => copy(`${window.location.origin}/xdr/incidents/${row.id}`, "Link") },
  ];

  // Keep the menu on screen.
  const style = {
    position: "fixed",
    top:  Math.min(at.y, window.innerHeight - 300),
    left: Math.min(at.x, window.innerWidth - 260),
    zIndex: 2000,
  };

  return (
    <div ref={ref} className="ql-ctx" style={style}
          role="menu" data-testid="ql-context-menu">
      <div className="ql-ctx__head">
        <span className="ql-ctx__num">{incidentNumber(row.id)}</span>
        <span className="ql-ctx__owner">
          {row.assignee ? `OWNER · ${row.assignee}` : "UNASSIGNED"}
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
