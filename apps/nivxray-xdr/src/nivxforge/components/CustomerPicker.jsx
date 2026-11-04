/**
 * Customer picker for the NivXForge EDR console.
 *
 * P0-FIX-6B-2 · THE LIST IS AN AUTHORIZATION, NOT A DIRECTORY.
 *
 * This menu used to read the whole tenant registry (`GET /api/xdr/tenants`),
 * so its contents were a `tenants.read` artefact: a principal could be
 * OFFERED every customer on the platform and learn that they exist. It now
 * renders exactly `session-context.authorized_customers` — the explicit
 * grants of a CUSTOMER principal, or the authoritative ACTIVE tenants of a
 * designated PLATFORM Super Admin. Nothing is read from the registry, from
 * `localStorage`, from `?tenant=` or from a role name.
 *
 * Choosing a customer is a SERVER action: it calls the audited
 * `POST /api/edr/session/active-tenant`, which re-runs the whole authority
 * chain (grants/PLATFORM → registry → RBAC) and writes
 * `TENANT_CONTEXT_SWITCHED`. The browser only persists what the server
 * already confirmed, and a refusal changes nothing.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Building2, Check, ChevronDown, Search, ShieldAlert } from "lucide-react";

import api from "@/lib/api";
import { TENANT_HEADER, activeTenant, setActiveTenant } from "@/lib/tenant";

const KIND_RANK = { CUSTOMER: 0, MSSP: 1, LEGACY_ADOPTED: 2,
                    INTERNAL_VALIDATION: 3 };

export default function CustomerPicker({ customers = [], withEvidence = [],
                                         platform = false }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(null);
  const box = useRef(null);
  const current = activeTenant();

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
    return (customers || [])
      .filter((t) => !needle
        || [t.customer, t.slug, t.display_name]
          .some((v) => String(v || "").toLowerCase().includes(needle)))
      .sort((a, b) => (KIND_RANK[a.kind] ?? 9) - (KIND_RANK[b.kind] ?? 9)
        || (evidence.has(b.customer) - evidence.has(a.customer))
        || String(a.display_name).localeCompare(String(b.display_name)))
      .slice(0, 60);
  }, [customers, q, evidence]);

  const label = useMemo(() => {
    if (!current) return null;
    const row = (customers || []).find((t) => t.customer === current);
    return row?.display_name || row?.slug || current;
  }, [customers, current]);

  // The SERVER establishes the context; the browser records the answer.
  const pick = async (id) => {
    setErr(null);
    setBusy(id);
    try {
      await api.post("/edr/session/active-tenant", null,
                     { headers: { [TENANT_HEADER]: id } });
      setActiveTenant(id);
      window.location.reload();
    } catch (e) {
      const code = e?.response?.data?.detail?.code;
      setErr(code
        ? `the server refused this customer (${code})`
        : "the server could not establish this customer context");
      setBusy(null);
    }
  };

  return (
    <span className="pill" ref={box} style={{ position: "relative" }}
          data-testid="nvf-customer-pill" data-customer={current || ""}
          data-authority-scope={platform ? "PLATFORM" : "CUSTOMER"}>
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
      {platform ? (
        <span className="chip" data-testid="nvf-platform-badge"
              style={{ fontSize: 8.6, marginLeft: 6 }}>PLATFORM</span>
      ) : null}

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
          <div style={{ padding: "6px 11px", fontSize: 9.4,
                        color: "var(--faint)", fontFamily: "var(--mono)",
                        borderBottom: "1px solid var(--border-sf)" }}
               data-testid="nvf-customer-source">
            {platform
              ? "AUTHORITATIVE ACTIVE CUSTOMERS · PLATFORM AUTHORITY"
              : "SERVER-AUTHORIZED CUSTOMERS ONLY"}
          </div>
          <div style={{ maxHeight: 340, overflowY: "auto" }}>
            {err ? (
              <div data-testid="nvf-customer-refusal"
                   style={{ display: "flex", gap: 6, alignItems: "center",
                            padding: "12px 11px", fontSize: 11,
                            color: "var(--red)" }}>
                <ShieldAlert size={12} /> {err}
              </div>
            ) : null}
            {(list || []).map((t) => (
              <button key={t.customer} onClick={() => pick(t.customer)}
                      disabled={busy != null}
                      data-testid={`nvf-customer-option-${t.customer}`}
                      style={{ display: "flex", width: "100%", gap: 8,
                               alignItems: "center", textAlign: "left",
                               background: t.customer === current
                                 ? "var(--surf-active)" : "transparent",
                               border: "none",
                               borderBottom: "1px solid var(--border-sf)",
                               padding: "7px 11px",
                               opacity: busy && busy !== t.customer ? .5 : 1,
                               cursor: busy ? "progress" : "pointer" }}>
                <Building2 size={11} color="var(--faint)" />
                <span style={{ minWidth: 0, flex: 1 }}>
                  <span style={{ display: "block", fontSize: 11.4,
                                 color: "var(--text)" }}>
                    {t.display_name || t.slug || t.customer}
                  </span>
                  <span className="mono" style={{ display: "block",
                                                  fontSize: 9.6,
                                                  color: "var(--faint)" }}>
                    {t.customer}{t.kind ? ` · ${t.kind}` : ""}
                  </span>
                </span>
                {evidence.has(t.customer)
                  ? <span className="chip" style={{ fontSize: 8.6 }}>
                      evidence
                    </span>
                  : null}
                {t.customer === current ? <Check size={11} color="var(--cyan)" />
                                        : null}
              </button>
            ))}
            {list.length === 0 ? (
              <div data-testid="nvf-customer-empty"
                   style={{ padding: "12px 11px", fontSize: 11,
                            color: "var(--muted)" }}>
                {q
                  ? `No authorized customer matches “${q}”.`
                  : "This principal holds no authorized customer."}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </span>
  );
}
