/**
 * `/xdr/hunting` — Threat Hunting workbench (B3 · nx modernization).
 *
 * Hunting is analyst-initiated interrogation of the authoritative stores:
 * one question — "what does this platform know about this observable?" —
 * answered by `GET /api/xdr/search`, which reads canonical records only
 * and builds no index of its own.
 *
 * The surface now speaks the investigation language: summary → ONE dense
 * result table → contextual inspection → pivot → technical detail on
 * demand. `/xdr/search` remains a permanent redirect into it.
 *
 * What this platform cannot hunt is STATED (saved hunts, scheduled hunts,
 * a hunt query language) rather than mocked with empty widgets.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Loader2, Radar, Search } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvValue,
  ABSENCE,
} from "@/xdr/nx";
import "@/xdr/nx/nx-inv.css";
import "@/xdr/nx/nx-workspace.css";

const UNSUPPORTED = [
  { k: "Saved hunts", state: ABSENCE.NOT_AVAILABLE,
    why: "no saved-hunt persistence model exists in this backend; a saved "
       + "hunt that silently forgets itself would be worse than none" },
  { k: "Scheduled hunts", state: ABSENCE.NOT_AVAILABLE,
    why: "no scheduler owns hunt execution; automation lives in Automate ▸ "
       + "Automation Rules and acts on detections, not hunts" },
  { k: "Hunt query language", state: ABSENCE.UNSUPPORTED,
    why: "search accepts an observable (hostname · SHA-256 · IP · rule id · "
       + "incident · process), not a query grammar" },
];

export default function XdrHuntingPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const q = params.get("q") || "";
  const [term, setTerm] = useState(q);
  const [data, setData] = useState(null);
  const [caps, setCaps] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [types, setTypes] = useState([]);
  const [sel, setSel] = useState(null);
  const [paneTab, setPaneTab] = useState("details");

  const run = useCallback((value) => {
    if (!value.trim()) { setData(null); return; }
    setBusy(true); setErr(null); setSel(null);
    api.get("/xdr/search", { params: { q: value.trim() } })
      .then(({ data: d }) => setData(d))
      .catch((e) => setErr(e?.response?.data?.detail || e?.message || String(e)))
      .finally(() => setBusy(false));
  }, []);

  useEffect(() => { setTerm(q); run(q); }, [q, run]);
  useEffect(() => {
    api.get("/xdr/search/capabilities").then(({ data: d }) => setCaps(d))
      .catch((e) => setCaps({ error: e?.message }));
  }, []);

  const rows = useMemo(() => (data?.groups || []).flatMap((g) =>
    (g.results || []).map((r) => ({ ...r, entity_type: r.entity_type
      || g.entity_type }))), [data]);

  const typeCounts = useMemo(() => {
    const c = {};
    (data?.groups || []).forEach((g) => { c[g.entity_type] = g.count; });
    return c;
  }, [data]);

  const visible = useMemo(() => (types.length
    ? rows.filter((r) => types.includes(r.entity_type)) : rows), [rows, types]);

  const selected = useMemo(() => visible.find(
    (r) => `${r.entity_type}-${r.id}` === sel) || null, [visible, sel]);

  const columns = [
    { key: "label", label: "Entity",
      render: (r) => <NxInvValue value={r.label} /> },
    { key: "entity_type", label: "Type", width: 128,
      render: (r) => <span className="inv-chip" style={{ cursor: "default",
                       padding: "1px 7px", fontSize: 9.8 }}>
        {r.entity_type}</span> },
    { key: "detail", label: "What the record says",
      render: (r) => <NxInvValue value={r.detail}
                                 absent="NOTHING FURTHER RECORDED" /> },
    { key: "tenant_id", label: "Customer", width: 160,
      render: (r) => <NxInvValue value={r.tenant_id} mono
                                 absent="TENANT NOT ATTRIBUTED" /> },
    { key: "source_product", label: "Source product", width: 130,
      render: (r) => (r.source_product === "NIVXFORGE_EDR"
        ? "NivXRay EDR" : "NivXRay XDR") },
    { key: "actions", label: "Actions", width: 96,
      render: (r) => (
        <button className="inv-chip" style={{ padding: "1px 6px",
                  fontSize: 9.4 }}
                disabled={!r.href}
                onClick={(e) => { e.stopPropagation();
                                  if (r.href) navigate(r.href); }}
                data-testid={`xdr-hunting-result-${r.id}`}>
          Open →
        </button>
      ) },
  ];

  return (
    <XdrShell>
      <div className="inv" data-testid="xdr-hunting-page"
           style={{ padding: "12px 16px 24px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12,
                      flexWrap: "wrap", marginBottom: 10 }}>
          <h1 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}
              data-testid="xdr-hunting-title">
            Hunting
          </h1>
          <span style={{ fontSize: 11, color: "var(--nx-muted, var(--muted))",
                         maxWidth: 720, lineHeight: 1.6 }}>
            Interrogate the authoritative NivXRay stores directly. Every result
            traces to a canonical record; nothing is inferred and nothing is
            indexed twice.
          </span>
          <button className="inv-chip" style={{ marginLeft: "auto" }}
                  data-testid="xdr-hunting-activities"
                  onClick={() => navigate("/xdr/activities")}>
            <Radar size={11} /> Environment activity
          </button>
        </div>

        <form onSubmit={(e) => { e.preventDefault();
                                 setParams(term.trim() ? { q: term.trim() } : {}); }}
              style={{ display: "flex", gap: 8, maxWidth: 860,
                       marginBottom: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1,
                        border: "1px solid var(--nx-bd-quiet, var(--border))",
                        borderRadius: 5, padding: "8px 10px",
                        background: "var(--nx-surf, var(--panel))" }}>
            <Search size={13} style={{ opacity: .7 }} />
            <input value={term} onChange={(e) => setTerm(e.target.value)}
                   data-testid="xdr-hunting-input"
                   placeholder="Hostname · endpoint id · SHA-256 · IP · rule id · incident · process · evidence id"
                   style={{ flex: 1, background: "transparent", border: "none",
                            outline: "none", fontSize: 12,
                            color: "var(--nx-text, var(--text))" }} />
          </div>
          <button type="submit" className="inv-chip"
                  data-testid="xdr-hunting-submit"
                  style={{ padding: "0 18px" }}>
            Hunt
          </button>
        </form>

        {busy && (
          <div className="inv-empty" data-testid="xdr-hunting-busy">
            <Loader2 size={13} className="rl-spin"
                     style={{ verticalAlign: "middle", marginRight: 6 }} />
            READING THE AUTHORITATIVE STORES…
          </div>
        )}
        {err && (
          <NxInvEmpty testid="xdr-hunting-error"
            title={`${ABSENCE.ERROR} — the hunt could not be completed`}
            body={typeof err === "object" ? JSON.stringify(err) : String(err)} />
        )}

        {!q && !busy && (
          <NxInvSection title="What you can hunt"
                        subtitle="the stores this hunt reads, named at the source"
                        testid="xdr-hunting-idle">
            {!caps ? (
              <div className="inv-empty">Reading capability contract…</div>
            ) : caps.error ? (
              <NxInvEmpty testid="xdr-hunting-caps-error"
                title={ABSENCE.NOT_EVALUATED} body={String(caps.error)} />
            ) : (
              <NxInvTable testid="xdr-hunting-surfaces"
                          rows={caps.searchable || []}
                          rowKey={(r) => r.entity_type}
                          columns={[
                            { key: "entity_type", label: "Entity", width: 200,
                              render: (r) => <b data-testid={
                                `xdr-hunting-surface-${r.entity_type}`}>
                                {r.entity_type}</b> },
                            { key: "source", label: "Authoritative source",
                              render: (r) => <NxInvValue value={r.source} mono
                                absent={ABSENCE.NOT_RECORDED} /> },
                          ]} />
            )}
          </NxInvSection>
        )}

        {data && (
          <div data-testid="xdr-hunting-results"
               data-state={data.state} data-total={data.total ?? 0}>
            <NxInvSection title="Hunt result"
              subtitle={`${visible.length} of ${rows.length} record(s) · ${
                (data.groups || []).length} entity type(s)`}
              testid="xdr-hunting-summary">
              <div className="inv-filters" data-testid="xdr-hunting-filters">
                <span className="inv-chip" style={{ cursor: "default" }}
                      data-testid="xdr-hunting-classification">
                  {data.term_classification || ABSENCE.NOT_EVALUATED}
                  <span className="inv-chip__n">term</span>
                </span>
                <button className="inv-chip" aria-pressed={types.length === 0}
                        onClick={() => setTypes([])}
                        data-testid="xdr-hunting-filter-all">All types</button>
                {(data.groups || []).map((g) => (
                  <button key={g.entity_type} className="inv-chip"
                          aria-pressed={types.includes(g.entity_type)}
                          onClick={() => setTypes(types.includes(g.entity_type)
                            ? types.filter((x) => x !== g.entity_type)
                            : [...types, g.entity_type])}
                          data-testid={`xdr-hunting-group-${g.entity_type}`}>
                    {g.entity_type}
                    <span className="inv-chip__n">{typeCounts[g.entity_type]
                      ?? "—"}</span>
                  </button>
                ))}
                <span className="inv-filters__sp inv-sec__s">
                  {data.searched
                    ? `${data.searched.authorised_endpoints} authorized endpoint(s) searched`
                    : "search scope not reported"}
                </span>
              </div>
            </NxInvSection>

            {data.state === "NO_MATCH" && (
              <NxInvEmpty testid="xdr-hunting-no-match"
                title="NO MATCHING RECORD"
                body={data.message || "No canonical record references this observable. An empty hunt means the platform holds nothing about it — not that it is benign."} />
            )}
            {data.state === "NOT_AUTHORIZED" && (
              <NxInvEmpty testid="xdr-hunting-unauthorized"
                title={ABSENCE.NOT_AUTHORIZED}
                body="Your principal resolves to no customer scope, so no record may be hunted." />
            )}

            {rows.length > 0 && (
              <div className="inv-split" data-testid="xdr-hunting-wk"
                   data-pane={selected ? "open" : "closed"}>
                <div className="inv-split__t">
                  <NxInvTable testid="xdr-hunting-table" columns={columns}
                              rows={visible}
                              rowKey={(r) => `${r.entity_type}-${r.id}`}
                              onRowClick={(r) => {
                                setSel(`${r.entity_type}-${r.id}`);
                                setPaneTab("details");
                              }}
                              empty={<NxInvEmpty testid="xdr-hunting-filtered-empty"
                                title="No record matches the selected entity types"
                                body="Clear the type filters to see every record this hunt returned." />} />
                </div>

                {selected && (
                  <div className="inv-split__p" data-testid="xdr-hunting-pane">
                    <div className="inv-pane__h">
                      <span style={{ minWidth: 0 }}>
                        <div className="inv-pane__k">{selected.entity_type}</div>
                        <div className="inv-pane__t"
                             data-testid="xdr-hunting-pane-title">
                          {selected.label}
                        </div>
                      </span>
                      <button className="inv-chip" style={{ marginLeft: "auto" }}
                              onClick={() => setSel(null)}
                              data-testid="xdr-hunting-pane-close">Close</button>
                    </div>
                    <div className="inv-pane__tabs" role="tablist">
                      {[["details", "Details"], ["context", "Context"],
                        ["technical", "Technical"]].map(([k, label]) => (
                        <button key={k} className="inv-pane__tab" role="tab"
                                aria-selected={paneTab === k}
                                onClick={() => setPaneTab(k)}
                                data-testid={`xdr-hunting-pane-tab-${k}`}>
                          {label}
                        </button>
                      ))}
                    </div>
                    <div className="inv-pane__b">
                      {paneTab === "details" && (
                        <>
                          <dl className="inv-kv">
                            <dt>Record</dt>
                            <dd><NxInvValue value={selected.detail}
                                  absent="NOTHING FURTHER RECORDED" /></dd>
                            <dt>Customer</dt>
                            <dd className="mono"><NxInvValue
                                  value={selected.tenant_id}
                                  absent="TENANT NOT ATTRIBUTED" /></dd>
                            <dt>Source product</dt>
                            <dd>{selected.source_product === "NIVXFORGE_EDR"
                              ? "NivXRay EDR" : "NivXRay XDR"}</dd>
                            <dt>Record id</dt>
                            <dd className="mono">{selected.id}</dd>
                          </dl>
                          <button className="inv-chip"
                                  style={{ marginTop: 10 }}
                                  disabled={!selected.href}
                                  onClick={() => selected.href
                                    && navigate(selected.href)}
                                  data-testid="xdr-hunting-pane-open">
                            Open the authoritative record →
                          </button>
                        </>
                      )}
                      {paneTab === "context" && (
                        <dl className="inv-kv">
                          <dt>Term classification</dt>
                          <dd className="mono"><NxInvValue
                                value={data.term_classification}
                                absent={ABSENCE.NOT_EVALUATED} /></dd>
                          <dt>Hunt state</dt>
                          <dd className="mono"><NxInvValue value={data.state}
                                absent={ABSENCE.NOT_EVALUATED} /></dd>
                          <dt>Endpoints searched</dt>
                          <dd className="mono">{data.searched
                            ? data.searched.authorised_endpoints
                            : <span className="inv-tb__na">
                                {ABSENCE.NOT_RECORDED}</span>}</dd>
                          <dt>Total records</dt>
                          <dd className="mono">{data.total ?? "—"}</dd>
                        </dl>
                      )}
                      {paneTab === "technical" && (
                        <pre style={{ margin: 0, fontSize: 10.4,
                                      whiteSpace: "pre-wrap",
                                      wordBreak: "break-all" }}>
                          {JSON.stringify(selected, null, 1)}
                        </pre>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        <NxInvTech label="What this platform cannot hunt yet — stated, not hidden"
                   testid="xdr-hunting-unsupported">
          <NxInvTable testid="xdr-hunting-unsupported-table" rows={UNSUPPORTED}
                      rowKey={(r) => r.k}
                      columns={[
                        { key: "k", label: "Capability", width: 190,
                          render: (r) => <b data-testid={
                            `xdr-hunting-unsupported-${r.k.toLowerCase()
                              .replace(/\W+/g, "-")}`}>{r.k}</b> },
                        { key: "state", label: "State", width: 150,
                          render: (r) => <span className="inv-tb__na">
                            {r.state}</span> },
                        { key: "why", label: "Why" },
                      ]} />
        </NxInvTech>

        <NxInvTech label="Entities with no index" testid="xdr-hunting-not-searchable">
          {!caps?.not_searchable?.length ? (
            <div className="inv-empty">
              Every entity this platform stores is searchable.
            </div>
          ) : (
            <NxInvTable testid="xdr-hunting-not-searchable-table"
                        rows={caps.not_searchable}
                        rowKey={(r) => r.entity_type}
                        columns={[
                          { key: "entity_type", label: "Entity", width: 170,
                            render: (r) => <b>{r.entity_type}</b> },
                          { key: "state", label: "State", width: 150,
                            render: (r) => <span className="inv-tb__na">
                              {r.state}</span> },
                          { key: "reason", label: "Reason" },
                        ]} />
          )}
        </NxInvTech>
      </div>
    </XdrShell>
  );
}
