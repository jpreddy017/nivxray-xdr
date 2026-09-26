/**
 * Customer picker for the NivXForge EDR console.
 *
 * Every tenant-bound EDR read is performed under ONE explicitly selected
 * customer — the platform has no default tenant. The list therefore comes
 * from the tenant REGISTRY (`/api/xdr/tenants`), not from whichever
 * tenants happen to already hold evidence: a newly provisioned customer
 * with zero computers is exactly the one an operator needs to select in
 * order to onboard the first endpoint.
 *
 * Customers that already hold evidence are marked, because that is a
 * useful fact — not because the others are hidden.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Building2, Check, ChevronDown, Search } from "lucide-react";

import api from "@/lib/api";
import { activeTenant, setActiveTenant } from "@/lib/tenant";

const KIND_RANK = { CUSTOMER: 0, MSSP: 1, LEGACY_ADOPTED: 2,
                    INTERNAL_VALIDATION: 3 };

export default function CustomerPicker({ withEvidence = [] }) {
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState(null);
  const [q, setQ] = useState("");
  const [err, setErr] = useState(null);
  const box = useRef(null);
  const current = activeTenant();

  // The registry is read on mount, not only when the menu opens, so the
  // header can name the customer instead of exposing its internal id.
  useEffect(() => {
    if (rows) return;
    api.get("/xdr/tenants", { params: { limit: 500 } })
      .then(({ data }) => setRows(data?.data?.tenants || []))
      .catch(() => setErr("the tenant registry could not be read with this "
        + "principal's permissions"));
  }, [rows]);

  useEffect(() => {
    if (!open) return undefined;
    const away = (e) => {
      if (box.current && !box.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const evidence = useMemo(() => new Set(withEvidence), [withEvidence]);
  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (rows || [])
      .filter((t) => t.state === "ACTIVE")
      .filter((t) => !needle
        || [t.id, t.slug, t.display_name]
          .some((v) => String(v || "").toLowerCase().includes(needle)))
      .sort((a, b) => (KIND_RANK[a.kind] ?? 9) - (KIND_RANK[b.kind] ?? 9)
        || (evidence.has(b.id) - evidence.has(a.id))
        || String(a.slug).localeCompare(String(b.slug)))
      .slice(0, 60);
  }, [rows, q, evidence]);

  const label = useMemo(() => {
    if (!current) return null;
    const row = (rows || []).find((t) => t.id === current);
    return row?.display_name || row?.slug || current;
  }, [rows, current]);

  const pick = (id) => { setActiveTenant(id); window.location.reload(); };

  return (
    <span className="pill" ref={box} style={{ position: "relative" }}
          data-testid="nvf-customer-pill" data-customer={current || ""}>
      <span className="k">Customer</span>
      <button onClick={() => setOpen((o) => !o)}
              data-testid="nvf-customer-open" title={current || undefined}
              style={{ background: "transparent", border: "none",
                       color: current ? "var(--cyan)" : "var(--amber)",
                       fontFamily: "var(--mono)", fontSize: 11,
                       cursor: "pointer", display: "inline-flex",
                       alignItems: "center", gap: 5, padding: 0 }}>
        {label || "◇ SELECT CUSTOMER"}
        <ChevronDown size={11} />
      </button>

      {open ? (
        <div data-testid="nvf-customer-menu"
             style={{ position: "absolute", top: "calc(100% + 6px)", right: 0,
                      width: 360, zIndex: 60, background: "var(--panel)",
                      border: "1px solid var(--border)", borderRadius: 6,
                      boxShadow: "0 18px 40px rgba(0,0,0,.5)",
                      overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6,
                        padding: "7px 10px",
                        borderBottom: "1px solid var(--border)" }}>
            <Search size={11} color="var(--faint)" />
            <input autoFocus value={q} onChange={(e) => setQ(e.target.value)}
                   placeholder="customer · slug · id"
                   data-testid="nvf-customer-search"
                   style={{ background: "transparent", border: "none",
                            outline: "none", color: "var(--text)",
                            fontFamily: "var(--mono)", fontSize: 11,
                            width: "100%" }} />
          </div>
          <div style={{ maxHeight: 340, overflowY: "auto" }}>
            {err ? (
              <div style={{ padding: "12px 11px", fontSize: 11,
                            color: "var(--red)" }}>{err}</div>
            ) : null}
            {!rows && !err ? (
              <div style={{ padding: "12px 11px", fontSize: 11,
                            color: "var(--muted)" }}>reading the registry…</div>
            ) : null}
            {(list || []).map((t) => (
              <button key={t.id} onClick={() => pick(t.id)}
                      data-testid={`nvf-customer-option-${t.id}`}
                      style={{ display: "flex", width: "100%", gap: 8,
                               alignItems: "center", textAlign: "left",
                               background: t.id === current
                                 ? "var(--surf-active)" : "transparent",
                               border: "none",
                               borderBottom: "1px solid var(--border-sf)",
                               padding: "7px 11px", cursor: "pointer" }}>
                <Building2 size={11} color="var(--faint)" />
                <span style={{ minWidth: 0, flex: 1 }}>
                  <span style={{ display: "block", fontSize: 11.4,
                                 color: "var(--text)" }}>
                    {t.display_name || t.slug}
                  </span>
                  <span className="mono" style={{ display: "block",
                                                  fontSize: 9.6,
                                                  color: "var(--faint)" }}>
                    {t.id} · {t.kind}
                  </span>
                </span>
                {evidence.has(t.id)
                  ? <span className="chip" style={{ fontSize: 8.6 }}>
                      evidence
                    </span>
                  : null}
                {t.id === current ? <Check size={11} color="var(--cyan)" />
                                  : null}
              </button>
            ))}
            {rows && list.length === 0 ? (
              <div style={{ padding: "12px 11px", fontSize: 11,
                            color: "var(--muted)" }}>
                No ACTIVE customer matches “{q}”.
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </span>
  );
}
