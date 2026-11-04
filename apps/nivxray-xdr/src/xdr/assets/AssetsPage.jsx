/**
 * AssetsPage · `/xdr/assets` · E2E-3
 *
 * ONE authoritative asset inventory. Row → entity flyout → full Entity 360.
 * There is no second device-detail destination: `/xdr/endpoints` now
 * redirects here, and the flyout's escape is the existing Entity 360 canvas.
 *
 * Provenance (§18):
 *   Devices       GET /api/edr/endpoints   (real hosts from observations)
 *   Users         derived from the `users[]` observed on those same endpoints
 *                 — labelled as derived, never presented as an identity
 *                 directory
 *   Cloud         NOT AVAILABLE — no cloud asset producer is connected
 *   Applications  NOT AVAILABLE — no application inventory producer exists
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  NxPageShell, NxTabs, NxDataTable, NxFlyout, NxEmpty, NxChip,
  NxVerdict, NxMetric, NxFact, NxStatus,
} from "@/xdr/nx";
import { listEndpoints } from "@/nivxforge/edrApi";
import { getSessionContext } from "@/nivxforge/edrApi";
import { activeTenant, setActiveTenant } from "@/lib/tenant";
import "@/xdr/nx/nx-entity.css";

const TABS = [
  { key: "devices",      label: "Devices" },
  { key: "users",        label: "Users" },
  { key: "cloud",        label: "Cloud" },
  { key: "applications", label: "Applications" },
];

function fmtWhen(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const h = Math.round((Date.now() - t) / 3600e3);
  if (h < 1) return "under 1h ago";
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function Absent({ children = "Not recorded", title }) {
  return <span className="nx-unavail" title={title}>{children}</span>;
}

function NotAvailable({ what, reason, testid }) {
  return (
    <NxEmpty
      title={`${what} inventory is not available`}
      hint={reason}
      data-testid={testid}
    />
  );
}

function agentState(row) {
  const st = row?.health?.agent_lifecycle?.state;
  if (!st) return null;
  return {
    NO_AGENT: "never_connected", HEALTHY: "healthy", ONLINE: "healthy",
    STALE: "degraded", OFFLINE: "offline",
  }[st] || "not_measured";
}

// ── Entity flyout · the ONE entity grammar in contextual form ────────
function EntityFlyoutBody({ row }) {
  const lanes = row.lane_counts || {};
  return (
    <div data-testid="asset-flyout-body">
      <div className="nx-eh-chips" style={{ marginBottom: 14 }}>
        <NxVerdict value={row.worst_label} testid="asset-flyout-verdict" />
        <NxStatus state={agentState(row) || "not_measured"}
                  reason={row?.health?.agent_lifecycle?.reason}
                  testid="asset-flyout-agent" />
        <NxChip tone={row.identity_confidence === "authoritative"
                      ? "available" : "no_evidence"}
                variant={row.identity_confidence === "authoritative"
                         ? "tinted" : "dashed"}
                title={row.attribution_basis}>
          identity · {row.identity_confidence || "unknown"}
        </NxChip>
      </div>

      <section className="nx-sec">
        <h3 className="nx-sec-title">Identity</h3>
        <dl className="nx-kv">
          <dt>Hostname</dt><dd>{row.hostname || row.host || <Absent />}</dd>
          <dt>Device ref</dt>
          <dd style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            {row.device_ref || <Absent />}
          </dd>
          <dt>Tenant</dt><dd>{row.tenant || <Absent />}</dd>
          <dt>Attribution</dt>
          <dd>{row.tenant_attribution || <Absent />}</dd>
          <dt>Basis</dt><dd>{row.attribution_basis || <Absent />}</dd>
          <dt>Observed users</dt>
          <dd>{(row.users || []).length
            ? row.users.join(", ")
            : <Absent>No user observed on this endpoint</Absent>}</dd>
          <dt>Provenance</dt>
          <dd>{(row.provenance || []).join(", ") || <Absent />}</dd>
        </dl>
      </section>

      <section className="nx-sec">
        <h3 className="nx-sec-title">Activity</h3>
        <div className="nx-grid4">
          <NxMetric label="observations" value={row.observation_count ?? null}
                    reason="Not counted for this endpoint"
                    testid="asset-flyout-observations" />
          <NxMetric label="incidents" value={row.incident_count ?? null}
                    reason="Not counted for this endpoint"
                    testid="asset-flyout-incidents" />
          <NxMetric label="detections" value={row.detection_count ?? null}
                    reason="Not counted for this endpoint"
                    testid="asset-flyout-detections" />
          <NxMetric label="risk" value={row.worst_risk ?? null}
                    reason="No risk score is recorded for this endpoint"
                    testid="asset-flyout-risk" />
        </div>
      </section>

      <section className="nx-sec">
        <h3 className="nx-sec-title">Telemetry lanes</h3>
        {Object.keys(lanes).length === 0 ? (
          <Absent>No lane carries evidence for this endpoint</Absent>
        ) : (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {Object.entries(lanes).map(([k, v]) => (
              <NxChip key={k} tone="purple" variant="tinted">
                {k} · {v}
              </NxChip>
            ))}
          </div>
        )}
        <div style={{ marginTop: 10, fontSize: 11.5,
                      color: "var(--nx-text-dim)" }}>
          First seen {row.first_seen || "—"} · last seen {row.last_seen || "—"}
        </div>
      </section>
    </div>
  );
}

export default function AssetsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = TABS.some((t) => t.key === params.get("tab"))
    ? params.get("tab") : "devices";

  const [rows, setRows]       = useState([]);
  const [meta, setMeta]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [openRow, setOpenRow] = useState(null);
  const [needsTenant, setNeedsTenant] = useState(false);
  const [customers, setCustomers]     = useState([]);

  const load = useCallback(async () => {
    setLoading(true); setError(null); setNeedsTenant(false);
    try {
      const d = await listEndpoints();
      setRows(d.endpoints || []);
      setMeta({ source: d.source, note: d.note,
                contract: d.identity_contract });
    } catch (e) {
      const det = e?.response?.data?.detail;
      // The EDR control plane has NO default tenant by design, so a
      // cross-tenant operator must name one. That is an authorization fact,
      // not a failure — so we ask, rather than inventing `default`.
      if (det?.code === "TENANT_REQUIRED") {
        setNeedsTenant(true);
        try {
          const sess = await getSessionContext();
          setCustomers((sess?.customers || []).map((c) => c.customer)
            .filter(Boolean));
        } catch { /* customers unavailable — the picker degrades to input */ }
      } else {
        setError(det?.reason || det || e?.message
          || "Failed to load the asset inventory.");
      }
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const setTab = (k) => {
    const next = new URLSearchParams(params);
    next.set("tab", k);
    setParams(next, { replace: true });
  };

  const userRows = useMemo(() => {
    const byUser = new Map();
    rows.forEach((r) => {
      (r.users || []).forEach((u) => {
        const cur = byUser.get(u)
          || { user: u, devices: [], observations: 0, incidents: 0,
               worst: "unknown", last_seen: null };
        cur.devices.push(r.hostname || r.host);
        cur.observations += r.observation_count || 0;
        cur.incidents    += r.incident_count || 0;
        if (r.worst_label === "malicious"
            || (r.worst_label === "suspicious" && cur.worst !== "malicious")) {
          cur.worst = r.worst_label;
        }
        if (!cur.last_seen
            || Date.parse(r.last_seen) > Date.parse(cur.last_seen)) {
          cur.last_seen = r.last_seen;
        }
        byUser.set(u, cur);
      });
    });
    return [...byUser.values()];
  }, [rows]);

  const deviceColumns = useMemo(() => [
    { key: "hostname", header: "Name", width: 280,
      value: (r) => `${r.hostname || r.host} ${r.device_ref}`,
      render: (r) => (
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12.5, color: "var(--nx-text)" }}>
            {r.hostname || r.host}
          </div>
          <div style={{ fontFamily: "'IBM Plex Mono', monospace",
                        fontSize: 10, color: "var(--nx-muted)" }}>
            {r.device_ref}
          </div>
        </div>
      ) },
    { key: "type", header: "Type", width: 90, sortable: false,
      render: () => <NxChip tone="neutral" variant="dashed">endpoint</NxChip> },
    { key: "worst_label", header: "Verdict", width: 120,
      render: (r) => <NxVerdict value={r.worst_label} /> },
    { key: "worst_risk", header: "Risk", width: 84, align: "right",
      render: (r) => (r.worst_risk == null
        ? <Absent title="No risk score recorded">—</Absent> : r.worst_risk) },
    { key: "users", header: "Users", width: 150,
      value: (r) => (r.users || []).join(" "),
      render: (r) => ((r.users || []).length
        ? r.users.slice(0, 2).join(", ")
          + ((r.users.length > 2) ? ` +${r.users.length - 2}` : "")
        : <Absent>none observed</Absent>) },
    { key: "lanes", header: "Sources", width: 170, sortable: false,
      render: (r) => {
        const l = Object.keys(r.lane_counts || {});
        return l.length
          ? <span style={{ fontFamily: "'IBM Plex Mono', monospace",
                           fontSize: 10.5 }}>{l.join(", ")}</span>
          : <Absent>no lane</Absent>;
      } },
    { key: "incident_count", header: "Incidents", width: 96, align: "right",
      render: (r) => (r.incident_count ?? <Absent>—</Absent>) },
    { key: "last_seen", header: "Last seen", width: 118, align: "right",
      render: (r) => fmtWhen(r.last_seen) || <Absent>—</Absent> },
    { key: "health", header: "Health", width: 150, sortable: false,
      render: (r) => {
        const s = agentState(r);
        return s
          ? <NxStatus state={s}
                      reason={r?.health?.agent_lifecycle?.reason} />
          : <Absent title="No agent lifecycle recorded">not measured</Absent>;
      } },
  ], []);

  const userColumns = useMemo(() => [
    { key: "user", header: "User", width: 220 },
    { key: "type", header: "Type", width: 90, sortable: false,
      render: () => <NxChip tone="neutral" variant="dashed">observed</NxChip> },
    { key: "worst", header: "Verdict", width: 120,
      render: (r) => <NxVerdict value={r.worst} /> },
    { key: "devices", header: "Devices", width: 280,
      value: (r) => r.devices.join(" "),
      render: (r) => r.devices.join(", ") },
    { key: "observations", header: "Observations", width: 120, align: "right" },
    { key: "incidents", header: "Incidents", width: 96, align: "right" },
    { key: "last_seen", header: "Last seen", width: 118, align: "right",
      render: (r) => fmtWhen(r.last_seen) || <Absent>—</Absent> },
  ], []);

  return (
    <XdrShell>
      <NxPageShell
        eyebrow="Exposure"
        title="Assets"
        description="One inventory for everything NivXRay can attribute to this
                     tenant. Select a row to inspect the entity, then open the
                     full Entity 360 when you need its trajectory."
        testid="xdr-assets-page"
        action={
          <button className="nx-dt-btn" onClick={load}
                  data-testid="assets-refresh-top">Refresh</button>
        }
      >
        <NxTabs
          tabs={TABS.map((t) => ({
            ...t,
            count: t.key === "devices" ? rows.length
                 : t.key === "users"   ? userRows.length : null,
          }))}
          active={tab} onChange={setTab} testid="assets-tabs"
        />

        {meta?.note && tab === "devices" && (
          <div className="nx-eh-prov" style={{ margin: "10px 0 12px" }}
               data-testid="assets-provenance-note">
            {meta.note}
          </div>
        )}

        {tab === "devices" && (needsTenant ? (
          <section className="nx-sec" data-testid="assets-tenant-required">
            <h3 className="nx-sec-title">Select a customer</h3>
            <p style={{ fontSize: 12.5, color: "var(--nx-text-dim)",
                        lineHeight: 1.6, margin: "0 0 12px" }}>
              You hold a cross-tenant role, and the endpoint control plane has
              no default tenant — an asset inventory always belongs to exactly
              one customer. NivXRay will not pick one for you, because reading
              the wrong tenancy is worse than reading none.
            </p>
            {customers.length > 0 ? (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {customers.map((c) => (
                  <button key={c} className="nx-dt-btn"
                          data-testid={`assets-pick-tenant-${c}`}
                          onClick={() => { setActiveTenant(c); load(); }}>
                    {c}
                  </button>
                ))}
              </div>
            ) : (
              <NxEmpty
                title="No customer is available to select"
                hint="The session context returned no customer list, so no
                      tenant can be named for this inventory."
                data-testid="assets-no-customers"
              />
            )}
            {activeTenant() && (
              <div style={{ marginTop: 12, fontSize: 11.5,
                            color: "var(--nx-muted)" }}>
                Currently selected: <strong>{activeTenant()}</strong>
              </div>
            )}
          </section>
        ) : (
          <NxDataTable
            columns={deviceColumns} rows={rows} rowKey={(r) => r.device_ref}
            loading={loading} error={error} onRefresh={load}
            searchPlaceholder="Search host, device ref, user, source…"
            pageSize={25}
            onRowClick={(r) => setOpenRow(r)}
            emptyTitle="No device is attributed to this tenant"
            emptyHint="GET /api/edr/endpoints returned an authorized empty set.
                       Devices appear once a collector delivers observations
                       that can be attributed to this tenant."
            testid="assets-devices-table"
          />
        ))}

        {tab === "users" && (
          <>
            <div className="nx-eh-prov" style={{ margin: "10px 0 12px" }}
                 data-testid="assets-users-derivation">
              These users are <strong>derived</strong> from the accounts observed
              on the endpoints above. NivXRay has no identity-directory
              integration in this tenant, so this is endpoint evidence — not an
              authoritative user inventory, and it is not presented as one.
            </div>
            <NxDataTable
              columns={userColumns} rows={userRows} rowKey={(r) => r.user}
              loading={loading} error={error} onRefresh={load}
              searchPlaceholder="Search user, device…"
              pageSize={25}
              emptyTitle="No user has been observed on any attributed endpoint"
              emptyHint="Endpoint observations carry no account for this
                         tenant yet."
              testid="assets-users-table"
            />
          </>
        )}

        {tab === "cloud" && (
          <NotAvailable
            what="Cloud asset"
            reason="No cloud asset producer is connected to this tenant. When a
                    cloud data source is onboarded in Data Sources, its assets
                    will appear here. NivXRay does not show an empty cloud
                    inventory as if the estate had none."
            testid="assets-cloud-unavailable"
          />
        )}

        {tab === "applications" && (
          <NotAvailable
            what="Application"
            reason="NivXRay has no application-inventory producer in this
                    build. This is a missing capability, not an empty estate."
            testid="assets-applications-unavailable"
          />
        )}
      </NxPageShell>

      <NxFlyout
        open={!!openRow}
        eyebrow="DEVICE"
        title={openRow ? (openRow.hostname || openRow.host) : ""}
        onClose={() => setOpenRow(null)}
        width={620}
        fullPageHref={openRow
          ? `/xdr/endpoints/${encodeURIComponent(openRow.device_ref
                                                 || openRow.host)}`
          : null}
        fullPageLabel="Open Entity 360"
        testid="asset-flyout"
        footer={openRow && (
          <>
            <button className="nx-dt-btn" data-testid="asset-flyout-entity360"
                    onClick={() => navigate(
                      `/xdr/endpoints/${encodeURIComponent(
                        openRow.device_ref || openRow.host)}`)}>
              Open Entity 360 <ArrowUpRight size={13} />
            </button>
            <button className="nx-dt-btn" data-testid="asset-flyout-trajectory"
                    onClick={() => navigate(
                      `/xdr/endpoints/${encodeURIComponent(
                        openRow.device_ref || openRow.host)}/trajectory`)}>
              Device trajectory <ArrowUpRight size={13} />
            </button>
          </>
        )}
      >
        {openRow && <EntityFlyoutBody row={openRow} />}
      </NxFlyout>
    </XdrShell>
  );
}
