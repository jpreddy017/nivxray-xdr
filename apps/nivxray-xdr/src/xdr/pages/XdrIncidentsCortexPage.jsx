/**
 * `/xdr/incidents` — Cortex-structured incident workspace on REAL data.
 *
 * Wave B2. The layout, proportions and interaction model are the reference
 * structure proven in `/xdr/_ux0-preview/workspace`; the DATA is the
 * authoritative queue projection (`GET /api/incidents`) plus a second
 * authoritative read per selection (`GET /api/incidents/{id}`).
 *
 * NO FIXTURE IS IMPORTED HERE. Every field NivXRay cannot compute renders
 * `NOT AVAILABLE` / `NOT OBSERVED` in its reference position rather than a
 * fabricated value — the same rule the prototype declared, now enforced
 * against a live backend.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  ChevronDown, Monitor, MoreVertical, Search, Star, User, UserCheck,
  RefreshCw, Shield, Layers,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { NxEmpty } from "@/xdr/nx";
import { listIncidents, getIncident } from "@/lib/incidentsApi";
import "@/xdr/ux0/ux0.css";
import "@/xdr/ux0/ux0-cortex.css";

const NA = <em className="cx-na">NOT AVAILABLE</em>;
const NOT_OBSERVED = <em className="cx-na">NOT OBSERVED</em>;

const SEV_OF = (row) => {
  const code = row?.priority?.code;
  if (code === "P1") return "critical";
  if (code === "P2") return "high";
  if (code === "P3") return "medium";
  return String(row?.severity || "unknown").toLowerCase();
};

const AGO = (iso) => {
  const t = Date.parse(iso || "");
  if (!Number.isFinite(t)) return "Not recorded";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return "Updated a few seconds ago";
  if (s < 3600) return `Updated ${Math.floor(s / 60)} minutes ago`;
  if (s < 86400) return `Updated ${Math.floor(s / 3600)} hours ago`;
  return `Updated ${Math.floor(s / 86400)} days ago`;
};

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "story", label: "Attack Story" },
  { key: "timeline", label: "Timeline" },
  { key: "evidence", label: "Evidence" },
  { key: "entities", label: "Entities" },
  { key: "detections", label: "Detections" },
  { key: "mitre", label: "MITRE" },
  { key: "response", label: "Response" },
  { key: "activity", label: "Activity" },
];

export default function XdrIncidentsCortexPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [invariant, setInvariant] = useState(null);
  const [sort, setSort] = useState("updated");
  const [q, setQ] = useState("");

  const selId = params.get("sel") || null;
  const [detail, setDetail] = useState(null);
  const [dLoading, setDLoading] = useState(false);
  const [dError, setDError] = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await listIncidents({
        state: params.get("state") || null,
        lens: params.get("lens") || null,
        sort: "updated_at", order: "desc", limit: 300,
      });
      setRows(res.incidents || []);
      setInvariant(res.invariant || null);
    } catch (e) {
      setError(e?.response?.data?.detail?.error
        || e?.response?.data?.detail
        || e?.message || "Failed to load incidents.");
      setRows([]);
    } finally { setLoading(false); }
  }, [params]);

  useEffect(() => { load(); }, [load]);

  const visible = useMemo(() => {
    let out = rows;
    if (q.trim()) {
      const n = q.trim().toLowerCase();
      out = out.filter((r) => `${r.number} ${r.name} ${r.customer}`
        .toLowerCase().includes(n));
    }
    const byScore = (r) => (r?.verdict?.risk_score ?? -1);
    const RANK = { critical: 3, high: 2, medium: 1 };
    if (sort === "score") out = [...out].sort((a, b) => byScore(b) - byScore(a));
    else if (sort === "severity") {
      out = [...out].sort((a, b) =>
        (RANK[SEV_OF(b)] || 0) - (RANK[SEV_OF(a)] || 0));
    } else {
      out = [...out].sort((a, b) =>
        Date.parse(b.last_activity || 0) - Date.parse(a.last_activity || 0));
    }
    return out;
  }, [rows, q, sort]);

  const selected = useMemo(
    () => visible.find((r) => r.id === selId) || visible[0] || null,
    [visible, selId]);

  useEffect(() => {
    if (!selected?.id) { setDetail(null); return; }
    let live = true;
    setDLoading(true); setDError(null);
    getIncident(selected.id)
      .then((d) => { if (live) setDetail(d); })
      .catch((e) => {
        if (live) setDError(e?.response?.data?.detail || e?.message
          || "Load failed.");
      })
      .finally(() => { if (live) setDLoading(false); });
    return () => { live = false; };
  }, [selected?.id]);

  const select = (id) => {
    const next = new URLSearchParams(params);
    next.set("sel", id);
    setParams(next, { replace: true });
  };

  const openFull = (tab) => {
    if (!selected) return;
    navigate(`/xdr/incidents/${selected.id}${tab ? `?tab=${tab}` : ""}`);
  };

  return (
    <XdrShell flush activeTop="incidents">
      <div data-testid="xdr-incidents-cortex-page">
        <div className="cx-top">
          <h1>Incidents</h1>
          <span className="cx-top__count" data-testid="cx-result-count">
            {loading ? "Loading…" : `Found ${visible.length} results`}
          </span>
          <div className="cx-top__right">
            <button className="cx-pill" onClick={load} disabled={loading}
                    data-testid="cx-refresh">
              <RefreshCw size={11} /> Refresh
            </button>
            <MoreVertical size={14} />
          </div>
        </div>

        {invariant && (
          <div className="cx-note" data-testid="cx-invariant">
            {typeof invariant === "string"
              ? invariant
              : (invariant.statement || JSON.stringify(invariant))}
          </div>
        )}

        {error && (
          <NxEmpty title="Incident queue failed to load" body={String(error)}
                   testid="cx-queue-error" />
        )}

        <div className="cx">
          <aside className="cx-queue" data-testid="cx-queue">
            <div className="cx-queue__bar">
              <Search size={12} />
              <input data-testid="cx-queue-search"
                     placeholder="Filter incident, customer…"
                     value={q} onChange={(e) => setQ(e.target.value)}
                     style={{ flex: 1, background: "transparent", border: 0,
                              outline: "none", color: "inherit",
                              fontSize: 11.5 }} />
              <label>Sort:</label>
              <select data-testid="cx-queue-sort" value={sort}
                      onChange={(e) => setSort(e.target.value)}>
                <option value="updated">Last Updated</option>
                <option value="score">Risk</option>
                <option value="severity">Priority</option>
              </select>
            </div>

            {!loading && visible.length === 0 && !error && (
              <div className="cx-empty" data-testid="cx-queue-empty">
                No incident matches this scope. The queue is a projection of
                canonical evidence — it never fabricates a row.
              </div>
            )}

            {visible.map((r) => {
              const sev = SEV_OF(r);
              const score = r?.verdict?.risk_score;
              return (
                <button key={r.id} type="button"
                        className={`cx-row${r.id === selected?.id ? " is-sel" : ""}`}
                        onClick={() => select(r.id)}
                        data-testid={`cx-queue-row-${r.id}`}>
                  <div className="cx-row__upd">{AGO(r.last_activity)}</div>
                  <div className="cx-row__l1">
                    <span className="cx-row__sev" data-s={sev}>
                      {sev.slice(0, 1).toUpperCase()}
                    </span>
                    <span className="cx-row__score">
                      Risk {score == null ? NA : `${score}/100`}
                    </span>
                    <span className="cx-row__who">
                      <UserCheck size={11} />{r.assignee || "Unassigned"}
                    </span>
                    <span className={`cx-row__state${r.state === "new" ? " is-new" : ""}`}>
                      {String(r.state || "").replace("_", " ").toUpperCase()}
                    </span>
                  </div>
                  <div className="cx-row__title">
                    <b>{r.number || r.incident_number || r.id}</b> {r.name}
                  </div>
                  <div className="cx-row__ctx">
                    <span><Monitor size={11} />{r.customer || "Not attributed"}</span>
                    <span><Layers size={11} />
                      {r.evidence_count == null
                        ? "Evidence not counted"
                        : `${r.evidence_count} evidence`}
                    </span>
                  </div>
                </button>
              );
            })}
          </aside>

          <section className="cx-detail" data-testid="cx-detail">
            {!selected ? (
              <div className="cx-empty" data-testid="cx-detail-empty">
                Select an incident to inspect it without leaving the queue.
              </div>
            ) : (
              <>
                <div className="cx-hdr" data-testid="cx-incident-header">
                  <span className="cx-pill cx-pill--sev" data-s={SEV_OF(selected)}
                        data-testid="cx-hdr-severity">
                    {selected?.priority?.label || SEV_OF(selected)}
                  </span>
                  <Star size={14} color="var(--nx-muted)" />
                  <span className="cx-hdr__id" data-testid="cx-hdr-id">
                    {selected.number || selected.id}
                  </span>
                  <span className="cx-div" />
                  <span className="cx-hdr__name" data-testid="cx-hdr-name">
                    {selected.name}
                  </span>
                  <div className="cx-hdr__sp">
                    <span className="cx-pill cx-pill--quiet"
                          data-testid="cx-hdr-risk"
                          title="Detection risk from the authoritative verdict; NivXRay does not compute an asset-weighted incident score.">
                      Risk {selected?.verdict?.risk_score == null
                        ? NA : `${selected.verdict.risk_score}/100`}
                    </span>
                    <span className="cx-div" />
                    <span className="cx-pill" data-testid="cx-hdr-assignee">
                      <UserCheck size={12} />
                      {selected.assignee || "Unassigned"}
                    </span>
                    <span className="cx-pill" data-testid="cx-hdr-status">
                      {String(selected.state || "").replace("_", " ")}
                    </span>
                    <button className="cx-pill" onClick={() => openFull()}
                            data-testid="cx-open-full">
                      Open investigation <ChevronDown size={12} />
                    </button>
                  </div>
                </div>

                <p className="cx-sentence" data-testid="cx-incident-sentence">
                  {selected.name} · detected by{" "}
                  <b>{selected.detection_source || "source not recorded"}</b>
                  {" "}for customer <b>{selected.customer || "not attributed"}</b>.
                  {" "}Verdict{" "}
                  <b>{selected?.verdict?.stage2_label || "not issued"}</b>
                  {selected?.verdict?.stage2_confidence
                    ? ` · ${selected.verdict.stage2_confidence} confidence`
                    : " · confidence not recorded"}.
                </p>

                <div className="cx-stats" data-testid="cx-stat-clusters">
                  <div className="cx-stat">
                    <span className="cx-stat__ring">
                      <i>{selected.evidence_count ?? "—"}</i>
                    </span>
                    <div>
                      <div className="cx-stat__k">Evidence</div>
                      <div className="cx-stat__srcs">
                        Source: <span>{selected.detection_source || "not recorded"}</span>
                      </div>
                    </div>
                  </div>
                  <div className="cx-stat">
                    <span className="cx-stat__icon"><Monitor size={19} /></span>
                    <div>
                      <div className="cx-stat__v" data-testid="cx-stat-customer">
                        {selected.customer || "—"}
                      </div>
                      <div className="cx-stat__k">Customer</div>
                    </div>
                  </div>
                  <div className="cx-stat">
                    <span className="cx-stat__icon"><Shield size={19} /></span>
                    <div>
                      <div className="cx-stat__v" data-testid="cx-stat-techniques">
                        {selected.techniques_total ? selected.techniques_total : 0}
                      </div>
                      <div className="cx-stat__k">
                        ATT&amp;CK techniques
                        {!selected.techniques_total && (
                          <span style={{ marginLeft: 6 }}>{NOT_OBSERVED}</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="cx-stat">
                    <span className="cx-stat__icon"><User size={19} /></span>
                    <div>
                      <div className="cx-stat__v" data-testid="cx-stat-provenance">
                        {selected.provenance_is_real ? "Real sensor" : "Unverified"}
                      </div>
                      <div className="cx-stat__k" title={selected.provenance_basis}>
                        {selected.provenance || "PROVENANCE_UNKNOWN"}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="cx-tabs" data-testid="cx-tabs">
                  {TABS.map((t) => (
                    <button key={t.key} className="cx-tab"
                            data-testid={`cx-tab-${t.key}`}
                            onClick={() => openFull(t.key)}>
                      {t.label}
                    </button>
                  ))}
                </div>

                <div className="cx-panel" data-testid="cx-detail-facts">
                  <div className="cx-panel__h">Incident facts</div>
                  <div className="cx-panel__b">
                    {dLoading && <div>Reading the authoritative record…</div>}
                    {dError && (
                      <div data-testid="cx-detail-error">
                        {String(typeof dError === "object"
                          ? (dError.error || dError.reason || JSON.stringify(dError))
                          : dError)}
                      </div>
                    )}
                    <div className="cx-grid">
                      <Fact k="Incident" v={selected.number || selected.id} />
                      <Fact k="State" v={String(selected.state || "")
                        .replace("_", " ")} />
                      <Fact k="Priority" v={selected?.priority?.label} />
                      <Fact k="Verdict" v={selected?.verdict?.stage2_label} />
                      <Fact k="Confidence" v={selected.confidence} />
                      <Fact k="Customer" v={selected.customer} />
                      <Fact k="Detection source" v={selected.detection_source} />
                      <Fact k="Evidence" v={selected.evidence_count} />
                      <Fact k="Assignee" v={selected.assignee}
                            fallback="Unassigned" />
                      <Fact k="SLA due" v={selected.sla_due_at} />
                      <Fact k="Created" v={selected.created_at} />
                      <Fact k="Last activity" v={selected.last_activity} />
                      <Fact k="Auto-investigation"
                            v={typeof selected.auto_investigation === "object"
                              ? selected.auto_investigation?.status
                              : selected.auto_investigation} />
                      <Fact k="Attack story"
                            v={detail?.attack_story_available === false
                              ? null : detail?.state_history?.length
                                ? `${detail.state_history.length} worklog entries`
                                : null} />
                    </div>
                  </div>
                </div>
              </>
            )}
          </section>
        </div>
      </div>
    </XdrShell>
  );
}


function Fact({ k, v, fallback }) {
  const empty = v == null || v === "" || v === "unset";
  return (
    <div className="cx-ent" data-testid={`cx-fact-${k.toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")}`}>
      <span className="cx-ent__k">{k}</span>
      <span className="cx-ent__n">
        {empty ? (fallback ? fallback : NA) : String(v)}
      </span>
    </div>
  );
}
