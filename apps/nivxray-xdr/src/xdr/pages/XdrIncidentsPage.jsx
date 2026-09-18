/**
 * XdrIncidentsPage · `/xdr/incidents` · E2E-1
 *
 * The enterprise incident queue, rebuilt on the authoritative `xdr/nx/`
 * primitives: ONE page shell, ONE tab bar, ONE table, ONE flyout, ONE
 * severity grammar.
 *
 * Workflow (owner directive §4): queue → contextual flyout → full
 * investigation. An analyst inspects without losing the queue, and only opens
 * the workspace when they commit to the investigation.
 *
 * Every column and every flyout field maps to an authoritative field of
 * `GET /api/incidents` / `GET /api/incidents/{id}`. Absent facts render as
 * absence with a reason — never as a zero (§18).
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ArrowUpRight, Shield } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  NxPageShell, NxDataTable, NxFlyout, NxTabs, NxEmpty, NxChip,
  NxVerdict, NxLifecycle, NxPriority, NxConfidence, NxRisk,
  NxProvenanceChip, NxAttackChain, NxFact, NxMetric,
} from "@/xdr/nx";
import { useAccess } from "@/xdr/access/AccessProvider";
import {
  listIncidents, getIncident, bulkAssign, bulkState, listSavedViews,
} from "@/lib/incidentsApi";
import "@/xdr/nx/nx-entity.css";
import { apiErrorText } from "@/xdr/nx/apiError";

const STATE_TABS = [
  { key: "",            label: "All open" },
  { key: "new",         label: "New" },
  { key: "in_progress", label: "In progress" },
  { key: "on_hold",     label: "On hold" },
  { key: "resolved",    label: "Resolved" },
  { key: "closed",      label: "Closed" },
];

const TIME_WINDOWS = [
  { key: "24h", label: "Last 24 hours", ms: 86400e3 },
  { key: "7d",  label: "Last 7 days",   ms: 7 * 86400e3 },
  { key: "30d", label: "Last 30 days",  ms: 30 * 86400e3 },
  { key: "all", label: "All time",      ms: null },
];

function fmtWhen(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const mins = Math.round((Date.now() - t) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const h = Math.round(mins / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function Absent({ children = "Not recorded", title }) {
  return <span className="nx-unavail" title={title}>{children}</span>;
}

// ── Flyout body ──────────────────────────────────────────────────────
function IncidentFlyoutBody({ row, detail, loading, error }) {
  if (error) {
    return (
      <div className="nx-dt-error" role="alert"
           data-testid="incident-flyout-error">
        <strong>This incident could not be loaded.</strong>
        <span>{String(error)}</span>
      </div>
    );
  }
  const d = detail || {};
  const vc = d.verdict_card || {};
  const assets = d.assets || {};
  const pointers = d.evidence_pointers || [];
  const withEvidence = pointers.filter((p) => p.status === "available");

  return (
    <div data-testid="incident-flyout-body">
      <div className="nx-eh-chips" style={{ marginBottom: 14 }}>
        <NxVerdict value={vc.verdict || row.severity}
                   title={vc.reason} testid="flyout-verdict" />
        <NxPriority priority={row.priority} testid="flyout-priority" />
        <NxRisk score={row.verdict?.risk_score ?? vc.confidence}
                testid="flyout-risk" />
        <NxLifecycle value={d.state || row.state} testid="flyout-state" />
        <NxProvenanceChip provenance={d.provenance || row.provenance}
                          basis={d.provenance_basis || row.provenance_basis}
                          isReal={d.provenance_is_real ?? row.provenance_is_real}
                          testid="flyout-provenance" />
      </div>

      <section className="nx-sec">
        <h3 className="nx-sec-title">Verdict, cited</h3>
        <dl className="nx-kv">
          <dt>Engine</dt>
          <dd>{vc.engine || row.detection_source || <Absent />}</dd>
          <dt>Basis</dt>
          <dd>{vc.reason
            || <Absent title="No verdict derivation was recorded">
                 No derivation recorded
               </Absent>}</dd>
          <dt>Provenance</dt>
          <dd>{d.provenance_basis || row.provenance_basis || <Absent />}</dd>
        </dl>
      </section>

      <section className="nx-sec">
        <h3 className="nx-sec-title">Impacted assets</h3>
        {Object.keys(assets).length === 0 ? (
          <Absent>No asset roll-up on this record</Absent>
        ) : (
          <div className="nx-grid4">
            {["hosts", "users", "processes", "files", "network"].map((k) => (
              <NxMetric key={k} label={k} value={assets[k] ?? null}
                        reason="Not counted on this record"
                        testid={`flyout-asset-${k}`} />
            ))}
          </div>
        )}
      </section>

      <section className="nx-sec">
        <h3 className="nx-sec-title">
          MITRE ATT&amp;CK
          {(d.mitre || []).length > 0 && ` · ${d.mitre.length}`}
        </h3>
        {(d.mitre || []).length === 0 ? (
          <Absent title="The record carries no technique mapping">
            No technique mapped to this incident
          </Absent>
        ) : (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {d.mitre.map((m, i) => (
              <NxChip key={m.id || i} tone="purple" variant="tinted"
                      title={m.name}>
                {m.id}{m.name ? ` · ${m.name}` : ""}
              </NxChip>
            ))}
          </div>
        )}
      </section>

      <section className="nx-sec">
        <h3 className="nx-sec-title">
          Evidence · {withEvidence.length} of {pointers.length} domains
        </h3>
        {pointers.length === 0 ? (
          <Absent>No evidence pointers on this record</Absent>
        ) : (
          <div style={{ display: "grid", gap: 8 }}>
            {pointers.map((p) => (
              <div key={p.domain}
                   style={{ display: "flex", gap: 10, alignItems: "flex-start" }}
                   data-testid={`flyout-evidence-${p.domain}`}>
                <NxChip tone={p.status === "available" ? "available"
                            : p.status === "not_connected" ? "not_connected"
                            : "no_evidence"}
                        variant={p.status === "available" ? "tinted" : "dashed"}>
                  {p.label}
                </NxChip>
                <span style={{ fontSize: 11.5, color: "var(--nx-text-dim)",
                               lineHeight: 1.5 }}>
                  {p.reason}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="nx-sec">
        <h3 className="nx-sec-title">Attack progression</h3>
        {loading
          ? <Absent>loading…</Absent>
          : <NxAttackChain nodes={d.attack_progression}
                           testid="flyout-attack-chain" />}
      </section>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────
export default function XdrIncidentsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const access = useAccess();

  const urlState = params.get("state") || "";
  const urlTime  = params.get("time")  || "7d";
  const urlLens  = params.get("lens")  || null;
  const mine     = params.get("mine")  === "1";

  const [rows, setRows]       = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [invariant, setInv]   = useState(null);
  const [views, setViews]     = useState([]);

  const [openRow, setOpenRow]   = useState(null);
  const [detail, setDetail]     = useState(null);
  const [dLoading, setDLoading] = useState(false);
  const [dError, setDError]     = useState(null);

  const setParam = useCallback((k, v) => {
    const next = new URLSearchParams(params);
    if (v == null || v === "") next.delete(k); else next.set(k, v);
    setParams(next, { replace: true });
  }, [params, setParams]);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await listIncidents({
        state: urlState || null,
        lens:  urlLens,
        sort:  "updated_at",
        order: "desc",
        limit: 500,
      });
      setRows(res.incidents || []);
      setInv(res.invariant || null);
    } catch (e) {
      setError(e?.response?.data?.detail?.error
        || apiErrorText(e, "Failed to load incidents."));
    } finally { setLoading(false); }
  }, [urlState, urlLens]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    listSavedViews().then((r) => setViews(r.views || [])).catch(() => {});
  }, []);

  // Flyout detail — a second authoritative read, never a guess from the row.
  useEffect(() => {
    if (!openRow) { setDetail(null); setDError(null); return; }
    let live = true;
    setDLoading(true); setDError(null);
    getIncident(openRow.id)
      .then((d) => { if (live) setDetail(d); })
      .catch((e) => {
        if (live) setDError(apiErrorText(e, "Load failed."));
      })
      .finally(() => { if (live) setDLoading(false); });
    return () => { live = false; };
  }, [openRow]);

  const visible = useMemo(() => {
    let out = rows;
    if (mine && access.principal) {
      out = out.filter((r) => r.assignee === access.principal);
    }
    const win = TIME_WINDOWS.find((w) => w.key === urlTime)?.ms;
    if (win) {
      const cutoff = Date.now() - win;
      out = out.filter((r) => {
        const t = Date.parse(r.last_activity || r.updated_at || r.created_at);
        return Number.isFinite(t) ? t >= cutoff : true;
      });
    }
    return out;
  }, [rows, mine, access.principal, urlTime]);

  const counts = useMemo(() => {
    const c = {};
    rows.forEach((r) => { c[r.state || "new"] = (c[r.state || "new"] || 0) + 1; });
    return c;
  }, [rows]);

  const canManage = access.can("incidents.update");
  const canAssign = access.can("incidents.assign");

  const columns = useMemo(() => [
    { key: "priority", header: "Priority", width: 116,
      value: (r) => r.priority?.code || "",
      render: (r) => <NxPriority priority={r.priority} /> },
    { key: "number", header: "Incident", width: 330,
      value: (r) => `${r.number} ${r.name}`,
      render: (r) => (
        <div style={{ minWidth: 0 }}>
          <div style={{ fontFamily: "'IBM Plex Mono', monospace",
                        fontSize: 10.5, color: "var(--nx-muted)" }}>
            {r.number || r.id}
          </div>
          <div style={{ fontSize: 12.5, color: "var(--nx-text)",
                        overflow: "hidden", textOverflow: "ellipsis",
                        whiteSpace: "nowrap" }} title={r.name}>
            {r.name}
          </div>
        </div>
      ) },
    { key: "verdict", header: "Verdict", width: 120,
      value: (r) => r.verdict?.stage2_label || r.severity,
      render: (r) => <NxVerdict value={r.verdict?.stage2_label || r.severity} /> },
    { key: "risk", header: "Risk", width: 104, align: "right",
      value: (r) => r.verdict?.risk_score ?? -1,
      render: (r) => <NxRisk score={r.verdict?.risk_score} /> },
    { key: "state", header: "Status", width: 116,
      render: (r) => <NxLifecycle value={r.state} /> },
    { key: "assets", header: "Assets", width: 80, align: "right",
      value: (r) => r.evidence_count ?? -1,
      render: (r) => (r.evidence_count == null
        ? <Absent>—</Absent> : r.evidence_count) },
    { key: "mitre", header: "MITRE", width: 150,
      value: (r) => (r.techniques_top || []).join(" "),
      render: (r) => ((r.techniques_top || []).length === 0
        ? <Absent title="No technique mapped">none</Absent>
        : <span style={{ fontFamily: "'IBM Plex Mono', monospace",
                         fontSize: 10.5 }}>
            {r.techniques_top.slice(0, 2).join(", ")}
            {r.techniques_total > 2 ? ` +${r.techniques_total - 2}` : ""}
          </span>) },
    { key: "source", header: "Source", width: 170,
      value: (r) => r.detection_source,
      render: (r) => <span style={{ fontFamily: "'IBM Plex Mono', monospace",
                                    fontSize: 10.5 }}>
        {r.detection_source || "—"}</span> },
    { key: "provenance", header: "Provenance", width: 172,
      value: (r) => r.provenance,
      render: (r) => <NxProvenanceChip provenance={r.provenance}
                                       basis={r.provenance_basis}
                                       isReal={r.provenance_is_real} /> },
    { key: "assignee", header: "Assignee", width: 150,
      render: (r) => (r.assignee
        ? r.assignee
        : <Absent title="Nobody is assigned">Unassigned</Absent>) },
    { key: "updated", header: "Updated", width: 110, align: "right",
      value: (r) => r.last_activity || r.updated_at,
      render: (r) => fmtWhen(r.last_activity || r.updated_at)
        || <Absent>—</Absent> },
  ], []);

  const toolbarExtra = (
    <>
      <select className="nx-dt-btn" value={urlTime}
              onChange={(e) => setParam("time", e.target.value)}
              data-testid="incidents-time-window"
              aria-label="Time window">
        {TIME_WINDOWS.map((w) => (
          <option key={w.key} value={w.key}>{w.label}</option>
        ))}
      </select>
      {views.length > 0 && (
        <select className="nx-dt-btn" value={urlLens || ""}
                onChange={(e) => setParam("lens", e.target.value)}
                data-testid="incidents-saved-views"
                aria-label="Saved views">
          <option value="">Saved views</option>
          {views.map((v) => (
            <option key={v.id} value={v.lens || v.id}>{v.name}</option>
          ))}
        </select>
      )}
      <button className={`nx-dt-btn${mine ? " is-active" : ""}`}
              onClick={() => setParam("mine", mine ? "" : "1")}
              data-testid="incidents-mine-toggle">
        {mine ? "My queue · on" : "My queue"}
      </button>
    </>
  );

  const bulkActions = (keys, clear) => (
    <>
      <button className="nx-dt-btn" data-testid="incidents-bulk-assign"
              disabled={canAssign === false}
              title={canAssign === false
                ? "You are not authorized to assign incidents"
                : canAssign === null
                  ? "Authorization contract unavailable — the server will decide"
                  : undefined}
              onClick={async () => {
                if (!access.principal) return;
                await bulkAssign(keys, access.principal);
                clear(); load();
              }}>
        Assign to me
      </button>
      <button className="nx-dt-btn" data-testid="incidents-bulk-progress"
              disabled={canManage === false}
              title={canManage === false
                ? "You are not authorized to change incident state"
                : undefined}
              onClick={async () => {
                await bulkState(keys, "in_progress");
                clear(); load();
              }}>
        Move to in progress
      </button>
    </>
  );

  return (
    <XdrShell>
      <NxPageShell
        eyebrow="Security operations"
        title="Incidents"
        description="Every incident NivXRay has correlated for this tenant.
                     Select a row to inspect it without leaving the queue, then
                     open the investigation when you commit to it."
        testid="xdr-incidents-page"
        action={
          <button className="nx-dt-btn" onClick={load}
                  data-testid="incidents-refresh-top">
            Refresh
          </button>
        }
      >
        {access.available === false && access.error !== "unauthenticated" && (
          <div className="nx-sec" style={{ marginBottom: 14 }}
               data-testid="incidents-access-unavailable">
            <NxChip tone="not_run" variant="dashed">
              Authorization contract unavailable
            </NxChip>
            <span style={{ marginLeft: 10, fontSize: 11.5,
                           color: "var(--nx-text-dim)" }}>
              Effective permissions could not be read
              {access.error ? ` (${access.error})` : ""}. Controls are shown as
              normal and the server remains the authority — it will reject any
              action you are not entitled to.
            </span>
          </div>
        )}

        <NxTabs
          tabs={STATE_TABS.map((t) => ({
            ...t,
            count: t.key ? (counts[t.key] ?? 0) : rows.length,
          }))}
          active={urlState}
          onChange={(k) => setParam("state", k)}
          testid="incidents-state-tabs"
        />

        {invariant && (
          <div className="nx-eh-prov" style={{ margin: "10px 0 12px" }}
               data-testid="incidents-invariant">
            {invariant.statement || invariant.reason || String(invariant)}
          </div>
        )}

        <NxDataTable
          columns={columns}
          rows={visible}
          rowKey={(r) => r.id}
          loading={loading}
          error={error}
          onRefresh={load}
          searchPlaceholder="Search incident, asset, source, technique, assignee…"
          pageSize={25}
          selectable
          bulkActions={bulkActions}
          toolbarExtra={toolbarExtra}
          onRowClick={(r) => setOpenRow(r)}
          emptyTitle="No incident matches this view"
          emptyHint="Nothing was returned by /api/incidents for this tenant,
                     state and time window. This is an authorized empty set,
                     not a failure."
          testid="incidents-table"
        />
      </NxPageShell>

      <NxFlyout
        open={!!openRow}
        eyebrow={openRow ? `INCIDENT · ${openRow.number || openRow.id}` : ""}
        title={openRow?.name || ""}
        onClose={() => setOpenRow(null)}
        width={660}
        fullPageHref={openRow ? `/xdr/incidents/${openRow.id}` : null}
        fullPageLabel="Full page"
        testid="incident-flyout"
        footer={openRow && (
          <button className="nx-dt-btn"
                  data-testid="incident-flyout-open-investigation"
                  onClick={() => navigate(`/xdr/incidents/${openRow.id}`)}>
            Open investigation <ArrowUpRight size={13} />
          </button>
        )}
      >
        {openRow && (
          <IncidentFlyoutBody row={openRow} detail={detail}
                              loading={dLoading} error={dError} />
        )}
      </NxFlyout>
    </XdrShell>
  );
}
