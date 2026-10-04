/**
 * NivXForge EDR · Audit.
 *
 * Entirely inside the EDR plane. Every record is read from the
 * authoritative store the operation itself wrote — there is no separate
 * audit copy for this page to disagree with, and the response says which
 * store each record came from.
 *
 * Delivery, acknowledgement, apply and verification appear as FOUR
 * records, because they are four different facts.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronDown, RefreshCw, Search } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { getAudit, getAuditFacets } from "@/nivxforge/managementApi";
import { Ago, Kpi, NA, OpsTable, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";
import "@/nivxforge/nvf-ops.css";

const WINDOWS = [{ d: 1, l: "24h" }, { d: 7, l: "7d" },
                 { d: 30, l: "30d" }, { d: 365, l: "1y" }];

const TONE = { POLICY: "info", EXCLUSION: "warn", POLICY_DELIVERY: "ok",
               CONNECTOR: "info", RESPONSE: "bad", ENROLMENT: "ok" };

export default function EdrAuditPage() {
  const [days, setDays] = useState(30);
  const [category, setCategory] = useState("");
  const [actor, setActor] = useState("");
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const [rows, setRows] = useState([]);
  const [meta, setMeta] = useState(null);
  const [facets, setFacets] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);

  const params = useMemo(() => {
    const p = { days, limit: 50 };
    if (category) p.category = category;
    if (actor) p.actor = actor;
    if (term && term.length >= 2) p.q = term;
    return p;
  }, [days, category, actor, term]);

  const load = useCallback((append = false, cursor = null) => {
    setLoading(true); setErr(null);
    getAudit(cursor ? { ...params, cursor } : params)
      .then((d) => {
        setMeta(d);
        setRows((prev) => (append ? [...prev, ...d.audit] : d.audit));
      })
      .catch((e) => setErr(apiErrorText(e, "audit unavailable")))
      .finally(() => setLoading(false));
  }, [params]);

  useEffect(() => { load(false, null); }, [load]);
  useEffect(() => {
    let live = true;
    getAuditFacets(days).then((d) => { if (live) setFacets(d); })
      .catch(() => { if (live) setFacets(null); });
    return () => { live = false; };
  }, [days]);

  const columns = useMemo(() => [
    { key: "at", label: "When", width: 96,
      render: (r) => <Ago iso={r.at} /> },
    { key: "category", label: "Category", width: 150,
      render: (r) => <StateChip token={r.category} tone={TONE[r.category]} /> },
    { key: "action", label: "Action", width: 230,
      render: (r) => <span className="mono">{r.action}</span> },
    { key: "actor", label: "Actor", width: 180,
      render: (r) => r.actor || <NA label="UNATTRIBUTED" /> },
    { key: "target", label: "Target",
      render: (r) => (
        <span title={`${r.target_type}: ${r.target}`}>
          {r.target || <NA />}
        </span>) },
    { key: "transition", label: "State change", width: 200,
      render: (r) => (r.previous_state || r.new_state ? (
        <span className="chipline">
          {r.previous_state
            ? <span className="chip">{r.previous_state}</span> : null}
          {r.new_state
            ? <StateChip token={r.new_state} /> : null}
        </span>) : <NA label="NOT RECORDED" />) },
    { key: "policy_version", label: "Ver", width: 56, cls: "mono",
      render: (r) => (r.policy_version != null ? r.policy_version : <NA />) },
    { key: "reason", label: "Reason / approval", cls: "basis",
      render: (r) => (
        <span title={r.reason || r.approval || ""}>
          {r.approval || r.reason || <NA label="NONE RECORDED" />}
        </span>) },
    { key: "source_store", label: "Evidence store", width: 210, cls: "mono",
      render: (r) => (
        <span title={`reference: ${r.evidence_ref || "none"}`}>
          {r.source_store}
        </span>) },
  ], []);

  return (
    <NivXForgeConsole activeTab="audit">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Management</span>
          <h1 className="ttl">Audit</h1>
          <div className="sub">
            Auditable NivXForge EDR operations, read from the
            <strong> authoritative store each operation wrote</strong>. No
            separate audit copy exists, so this page cannot disagree with
            what actually happened.
          </div>
        </div>
        <div className="spacer" />
        <div className="ops-actions">
          <button className="btn" onClick={() => load(false, null)}
                  data-testid="edr-audit-refresh">
            <RefreshCw size={11} /> Refresh
          </button>
        </div>
      </div>

      {facets ? (
        <div className="kpi-rail" data-testid="edr-audit-kpis">
          <Kpi label="Recorded operations" value={facets.total}
               testid="edr-kpi-audit-total" />
          <Kpi label="Policy + delivery"
               value={(facets.category?.POLICY || 0)
                      + (facets.category?.POLICY_DELIVERY || 0)}
               testid="edr-kpi-audit-policy" />
          <Kpi label="Exclusion decisions"
               value={facets.category?.EXCLUSION || 0}
               tone={facets.category?.EXCLUSION ? "amber" : undefined}
               testid="edr-kpi-audit-exclusion" />
          <Kpi label="Response actions" value={facets.category?.RESPONSE || 0}
               tone={facets.category?.RESPONSE ? "red" : undefined}
               testid="edr-kpi-audit-response" />
          <Kpi label="Distinct actors"
               value={Object.keys(facets.actor || {}).length}
               testid="edr-kpi-audit-actors" />
        </div>
      ) : null}

      <div className="ops-toolbar" data-testid="edr-audit-toolbar">
        <div className="seg">
          {WINDOWS.map((w) => (
            <button key={w.d} data-on={days === w.d}
                    onClick={() => setDays(w.d)}
                    data-testid={`edr-audit-window-${w.d}`}>{w.l}</button>))}
        </div>
        <select value={category} onChange={(e) => setCategory(e.target.value)}
                data-testid="edr-audit-category-filter">
          <option value="">All categories</option>
          {(meta?.categories || []).map((c) => (
            <option key={c} value={c}>
              {c}{facets?.category?.[c] ? ` (${facets.category[c]})` : ""}
            </option>))}
        </select>
        <select value={actor} onChange={(e) => setActor(e.target.value)}
                data-testid="edr-audit-actor-filter">
          <option value="">All actors</option>
          {Object.entries(facets?.actor || {}).map(([a, n]) => (
            <option key={a} value={a}>{a} ({n})</option>))}
        </select>
        <div className="ops-search">
          <Search size={11} />
          <input value={q} placeholder="Search actions, targets, reasons…"
                 onChange={(e) => setQ(e.target.value)}
                 onKeyDown={(e) => { if (e.key === "Enter") setTerm(q); }}
                 data-testid="edr-audit-search" />
          <button className="btn" onClick={() => setTerm(q)}
                  data-testid="edr-audit-search-apply">Apply</button>
        </div>
        <div className="spacer" />
        <span className="ops-count" data-testid="edr-audit-count">
          {rows.length} loaded
        </span>
      </div>

      {err ? <Refusal title="Audit unavailable" body={err}
                      testid="edr-audit-refusal" /> : null}

      {meta?.sources_capped?.length ? (
        <div className="basis" style={{ marginBottom: 8 }}
             data-testid="edr-audit-truncated">
          {meta.completeness}
        </div>
      ) : null}

      {loading && !rows.length
        ? <Skeleton rows={8} testid="edr-audit-loading" />
        : (
          <>
            <OpsTable columns={columns} rows={rows}
                      rowKey={(r) => r.record_id}
                      testid="edr-audit-table" />
            {!rows.length && !loading ? (
              <div className="basis" data-testid="edr-audit-empty">
                NO AUDITABLE OPERATION was recorded for this customer in this
                window. Check the CUSTOMER selector in the header if you
                expected activity: an operation in one customer is never
                visible in another.
              </div>
            ) : null}
            {meta?.next_cursor ? (
              <button className="btn mint" style={{ marginTop: 10 }}
                      disabled={loading}
                      onClick={() => load(true, meta.next_cursor)}
                      data-testid="edr-audit-load-more">
                <ChevronDown size={11} />
                {loading ? "Loading…" : "Load more"}
              </button>
            ) : null}
            {meta ? (
              <div className="basis" style={{ marginTop: 10 }}
                   data-testid="edr-audit-provenance">
                {meta.provenance}
              </div>
            ) : null}
          </>
        )}
    </NivXForgeConsole>
  );
}
