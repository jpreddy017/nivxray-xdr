/**
 * XdrAdminPage · Slice 10 — Native XDR Admin console.
 *
 * Route: `/xdr/admin` (Overview) or `/xdr/admin/:section`.
 *
 * Every section renders inside XDR (never a deep-link back to the
 * base NivXRay `/admin` UI).  All data comes from authoritative
 * NivXRay backend APIs; no engines/stores duplicated.
 *
 * Honest-state contract (§9 · Slice 7 quality bar):
 *   LOADING → real spinner
 *   POPULATED → table / KV grid rendered from authoritative payload
 *   EMPTY → NO MATCHING EVIDENCE (with the section's contextual note)
 *   ERROR → ERROR badge + payload detail
 *   NOT CONNECTED → integration required (never faked)
 *   NOT AVAILABLE → capability absent (never faked)
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { NavLink, useParams } from "react-router-dom";
import { Loader2, RefreshCcw, ArrowRightLeft } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { ADMIN_SECTIONS, ADMIN_BY_KEY } from "@/xdr/admin/adminMeta";
import IntegrationsBody from "@/xdr/admin/IntegrationsBody";
import EnginesBody from "@/xdr/admin/EnginesBody";
import CorpusBody from "@/xdr/admin/CorpusBody";
import CapabilityHubBody from "@/xdr/admin/CapabilityHubBody";
import DetectionContentBody from "@/xdr/admin/DetectionContentBody";
import DeprecatedBanner     from "@/xdr/admin/DeprecatedBanner";
import AuditLogBody from "@/xdr/admin/AuditLogBody";
import SecretsBody from "@/xdr/admin/SecretsBody";
import ContentPackLolbasBody from "@/xdr/admin/ContentPackLolbasBody";
import DataSourcesBody       from "@/xdr/admin/DataSourcesBody";
import CollectorsBody        from "@/xdr/admin/CollectorsBody";
import DetectionRegistryBody from "@/xdr/admin/DetectionRegistryBody";
import CorrelationRulesBody  from "@/xdr/admin/CorrelationRulesBody";
import PlatformOverviewBody  from "@/xdr/admin/PlatformOverviewBody";
import UsersRolesBody from "@/xdr/admin/UsersRolesBody";
import ApiKeysBody from "@/xdr/admin/ApiKeysBody";
import WebhooksBody from "@/xdr/admin/WebhooksBody";
import * as collectorApi from "@/xdr/admin/collectorApi";
import api from "@/lib/api";

// ── Small state helpers ─────────────────────────────────────────
function HonestBadge({ label, color = "var(--faint)", testid }) {
  return (
    <span data-testid={testid} style={{
      display: "inline-block", padding: "2px 7px", borderRadius: 3,
      border: `1px solid ${color}`, color,
      fontFamily: "var(--xmono)", fontSize: 9.5, letterSpacing: ".4px",
      fontWeight: 800, textTransform: "uppercase",
    }}>{label}</span>
  );
}

// ── Renderers per row `kind` ────────────────────────────────────
function KVBlock({ payload }) {
  if (!payload || typeof payload !== "object") return null;
  const entries = Object.entries(payload)
    .filter(([, v]) => v !== undefined && v !== null && v !== "");
  if (entries.length === 0) return null;
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
      gap: 10,
    }} data-testid="xdr-admin-kv-grid">
      {entries.map(([k, v]) => (
        <div key={k} className="panel" style={{ padding: "10px 12px" }}>
          <div style={{
            fontFamily: "var(--xmono)", fontSize: 9.5, letterSpacing: ".3px",
            fontWeight: 800, textTransform: "uppercase",
            color: "var(--faint)", marginBottom: 4,
          }}>{k}</div>
          <div style={{
            color: "var(--text)", fontSize: 12,
            fontFamily: typeof v === "number" || /^\d+/.test(String(v))
              ? "var(--xmono)" : "inherit",
            wordBreak: "break-all",
          }}>
            {typeof v === "boolean" ? (v ? "TRUE" : "FALSE")
              : typeof v === "object" ? JSON.stringify(v)
              : String(v)}
          </div>
        </div>
      ))}
    </div>
  );
}

function TableBlock({ rows, columns }) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  return (
    <table className="x-table" style={{ width: "100%" }}
              data-testid="xdr-admin-table">
      <thead>
        <tr>{columns.map((c) => <th key={c.k}>{c.label}</th>)}</tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={r.id || r._id || i}>
            {columns.map((c) => {
              const raw = r[c.k];
              const shown = c.render ? c.render(raw, r) : (raw ?? "—");
              return (
                <td key={c.k} className={c.mono ? "mono" : ""}>
                  {shown}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// Best-effort extraction of a list from a JSON payload.
function extractRows(payload, key) {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (key && Array.isArray(payload[key])) return payload[key];
  for (const k of ["items","results","rows","data","users","services","models","records","data_sources","collectors"]) {
    if (Array.isArray(payload[k])) return payload[k];
  }
  return [];
}

// Route an API path — `collector:/…` targets the standalone XDR
// collector service; everything else targets the authoritative
// NivXRay backend.
async function fetchSection(section) {
  const path = section.api;
  if (!path) return { kind: "not_connected" };
  if (path.startsWith("collector:")) {
    if (!collectorApi.COLLECTOR_CONFIGURED) {
      const err = new Error("COLLECTOR_RUNTIME_NOT_DEPLOYED");
      err.code = "COLLECTOR_RUNTIME_NOT_DEPLOYED";
      throw err;
    }
    const fn = {
      "collector:/data-sources":      collectorApi.listDataSources,
      "collector:/collectors":        collectorApi.listCollectors,
      "collector:/telemetry-health":  collectorApi.getTelemetryHealth,
      "collector:/connectors":        collectorApi.listCollectorConnectors,
    }[path];
    if (!fn) throw new Error(`unknown_collector_route:${path}`);
    return { kind: "populated", data: await fn() };
  }
  const { data } = await api.get(path);
  return { kind: "populated", data };
}

// ── The admin body ──────────────────────────────────────────────
function AdminBody({ section }) {
  // Overview is the Phase A.2 visual benchmark — it composes its
  // own hero + KPI + analytical rows and fetches all authoritative
  // aggregates directly.  Skip the generic KV pipeline.
  if (section.key === "overview") {
    return <PlatformOverviewBody />;
  }

  const [state, setState] = useState("loading");
  const [payload, setPayload] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    if (section.kind === "integrations") {
      // Live wizard fetches directly from the collector — the outer
      // state machine only needs to render the container.
      setPayload(null);
      setState("populated");
      return;
    }
    if (section.kind === "engines") {
      // The Engines panel is fully driven by the local capability
      // registry — no network call required.  It IS the authoritative
      // surface for what XDR consumes.
      setPayload(null);
      setState("populated");
      return;
    }
    if (section.kind === "corpus") {
      // Corpus panel reads exclusively from the in-tree scenario
      // registry.  No network call required.
      setPayload(null);
      setState("populated");
      return;
    }
    if (section.kind === "capability_hub" || section.kind === "detection_content"
         || section.kind === "deprecated_detection_content"
         || section.kind === "audit_log" || section.kind === "secrets"
         || section.kind === "content_pack_lolbas"
         || section.kind === "users_roles"
         || section.kind === "api_keys"
         || section.kind === "webhooks"
         || section.kind === "data_sources_native"
         || section.kind === "collectors_native"
         || section.kind === "detection_registry"
         || section.kind === "correlation_rules") {
      // Fully client-side (each fetches from base API on mount).
      setPayload(null);
      setState("populated");
      return;
    }
    if (!section.api) {
      setState(section.connected === false ? "not_connected" : "not_available");
      return;
    }
    setState("loading"); setError(null);
    try {
      const res = await fetchSection(section);
      const data = res.data;
      setPayload(data);
      const rows = extractRows(data, section.payloadKey);
      const kv = data && typeof data === "object" && !Array.isArray(data)
                    ? Object.keys(data).length : 0;
      if (section.kind === "integrations") setState("populated");
      else setState((rows.length + kv) === 0 ? "empty" : "populated");
    } catch (e) {
      if (e && e.code === "COLLECTOR_RUNTIME_NOT_DEPLOYED") {
        setState("collector_not_deployed");
      } else {
        setError(e?.response?.data?.detail || e?.message || "Request failed.");
        setState("error");
      }
    }
  }, [section]);

  useEffect(() => { load(); }, [load]);

  return (
    <section data-testid={`xdr-admin-body-${section.key}`}>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                      marginBottom: 8 }}>
        <section.icon size={16} style={{ color: "var(--mint)" }} />
        <h1 className="page-h1" style={{ margin: 0 }}>{section.label}</h1>
        <div style={{ flex: 1 }} />
        {section.api && (
          <button
            className="btn" style={{ padding: "4px 10px" }}
            onClick={load}
            data-testid={`xdr-admin-refresh-${section.key}`}
          >
            <RefreshCcw size={11} /> Refresh
          </button>
        )}
      </div>
      <div className="page-sub">{section.subtitle}</div>

      <section className="panel" style={{ padding: 14, marginTop: 12 }}>
        {state === "loading" && (
          <div className="x-empty" data-testid={`xdr-admin-loading-${section.key}`}>
            <Loader2 size={13} className="spin"
                      style={{ verticalAlign: "middle", marginRight: 6 }} />
            Loading …
          </div>
        )}
        {state === "error" && (
          <div style={{ padding: 14 }}>
            <HonestBadge label="ERROR" color="#ff5b5b"
                            testid={`xdr-admin-error-${section.key}`} />
            <div style={{ marginTop: 8, color: "#ff9494", fontSize: 11.5 }}>
              {String(error)}
            </div>
          </div>
        )}
        {state === "not_connected" && (
          <NotConnected section={section} />
        )}
        {state === "not_available" && (
          <NotAvailable section={section} />
        )}
        {state === "collector_not_deployed" && (
          <div style={{ padding: 14 }}>
            <HonestBadge label="COLLECTOR RUNTIME NOT DEPLOYED"
                            color="var(--amber)"
                            testid={`xdr-admin-collector-missing-${section.key}`} />
            <div style={{ marginTop: 8, color: "var(--text-dim)", fontSize: 11.5,
                             lineHeight: 1.6 }}>
              This surface reads live state from the NivXRay XDR Collector
              service, a separately deployable runtime.  It is not yet
              configured for this XDR frontend.
            </div>
            <div style={{ marginTop: 6, color: "var(--faint)", fontSize: 10.5,
                             fontFamily: "var(--xmono)" }}>
              To wire it: set <span style={{ color: "var(--cyan)" }}>
              VITE_XDR_COLLECTOR_URL</span> in the Vercel project settings
              to point at the deployed collector service, then redeploy.
              Reference implementation: <span style={{ color: "var(--cyan)" }}>
              /app/apps/nivxray-xdr-collector</span>.
            </div>
          </div>
        )}
        {state === "empty" && (
          <div style={{ padding: 14 }}>
            <HonestBadge label="NO MATCHING EVIDENCE"
                            testid={`xdr-admin-empty-${section.key}`} />
            <div style={{ marginTop: 8, color: "var(--text-dim)", fontSize: 11.5 }}>
              {section.empty || "The authoritative surface returned nothing for this scope."}
            </div>
            <div style={{ marginTop: 6, color: "var(--faint)", fontSize: 10.5,
                            fontFamily: "var(--xmono)" }}>
              source: <span style={{ color: "var(--cyan)" }}>{section.api}</span>
            </div>
          </div>
        )}
        {state === "populated" && (
          <div data-testid={`xdr-admin-populated-${section.key}`}>
            {section.deprecated && (
              <DeprecatedBanner
                authoritativeKey={section.redirect_to || "detection-registry"}
                authoritativeLabel="Detection Registry"
                rationale={`This surface (${section.label}) has been superseded by the authoritative Detection Registry. Rule state, counts, RBAC, audit and provenance now live in a single registry — do not treat this legacy page as source of truth.`}
              />
            )}
            {section.kind === "integrations"
              ? <IntegrationsBody />
              : section.kind === "engines"
              ? <EnginesBody />
              : section.kind === "corpus"
              ? <CorpusBody />
              : section.kind === "capability_hub"
              ? <CapabilityHubBody />
              : (section.kind === "detection_content"
                  || section.kind === "deprecated_detection_content")
              ? <DetectionContentBody />
              : section.kind === "audit_log"
              ? <AuditLogBody />
              : section.kind === "secrets"
              ? <SecretsBody />
              : section.kind === "content_pack_lolbas"
              ? <ContentPackLolbasBody />
              : section.kind === "users_roles"
              ? <UsersRolesBody />
              : section.kind === "api_keys"
              ? <ApiKeysBody />
              : section.kind === "webhooks"
              ? <WebhooksBody />
              : section.kind === "data_sources_native"
              ? <DataSourcesBody />
              : section.kind === "collectors_native"
              ? <CollectorsBody />
              : section.kind === "detection_registry"
              ? <DetectionRegistryBody />
              : section.kind === "correlation_rules"
              ? <CorrelationRulesBody />
              : section.kind === "table"
              ? <TableBlock rows={extractRows(payload)} columns={section.columns} />
              : <KVBlock payload={payload} />}
            {section.api && (
              <div style={{ marginTop: 10, color: "var(--faint)", fontSize: 10.5,
                              fontFamily: "var(--xmono)" }}>
                source: <span style={{ color: "var(--cyan)" }}>{section.api}</span>{" "}
                · read-only projection · never mutated.
              </div>
            )}
          </div>
        )}
      </section>
    </section>
  );
}

function NotConnected({ section }) {
  return (
    <div style={{ padding: 14 }}>
      <HonestBadge label="NOT CONNECTED"
                      testid={`xdr-admin-notconnected-${section.key}`} />
      <div style={{ marginTop: 8, color: "var(--text-dim)", fontSize: 11.5,
                       lineHeight: 1.6 }}>
        This admin surface requires <b>{section.integration}</b> to be wired
        for the tenant.  NivXRay XDR does not fabricate an inventory here —
        we surface this state so an empty pane is never mistaken for a
        healthy control-plane.
      </div>
    </div>
  );
}

function NotAvailable({ section }) {
  return (
    <div style={{ padding: 14 }}>
      <HonestBadge label="NOT AVAILABLE"
                      testid={`xdr-admin-notavailable-${section.key}`} />
      <div style={{ marginTop: 8, color: "var(--text-dim)", fontSize: 11.5 }}>
        No authoritative backend surface exposes this admin capability yet.
      </div>
    </div>
  );
}

// ── The admin shell (left nav + right body) ─────────────────────
export default function XdrAdminPage() {
  const { section: routeKey } = useParams();
  const key = routeKey || "overview";
  const section = ADMIN_BY_KEY[key];

  const nav = useMemo(() => ADMIN_SECTIONS, []);

  return (
    <XdrShell>
      <div style={{
        display: "grid",
        gridTemplateColumns: "220px 1fr",
        gap: 14, alignItems: "start",
      }} data-testid="xdr-admin-shell">
        <aside className="panel" style={{ padding: 8, position: "sticky", top: 12 }}>
          <div className="section-title" style={{ marginBottom: 6 }}>
            Administration
          </div>
          {nav.map((s) => (
            <NavLink
              key={s.key}
              to={s.key === "overview" ? "/xdr/admin" : `/xdr/admin/${s.key}`}
              end={s.key === "overview"}
              className={({ isActive }) => `btn ghost ${isActive ? "primary" : ""}`}
              style={({ isActive }) => ({
                width: "100%", justifyContent: "flex-start",
                padding: "5px 8px", borderRadius: 3,
                borderColor: isActive ? "var(--mint)" : "transparent",
                color: isActive ? "var(--mint)" : "var(--text-dim)",
                textDecoration: "none",
              })}
              data-testid={`xdr-admin-nav-${s.key}`}
            >
              <s.icon size={12} />
              <span style={{ flex: 1, textAlign: "left", fontSize: 11.5 }}>
                {s.label}
              </span>
              {!s.api && (
                <ArrowRightLeft size={9}
                  style={{ color: "var(--faint)", opacity: 0.6 }}
                  title="Not connected" />
              )}
            </NavLink>
          ))}
        </aside>

        <main>
          {section ? <AdminBody section={section} /> : (
            <div className="x-empty" data-testid="xdr-admin-unknown">
              <b>NOT AVAILABLE</b> — Unknown admin section{" "}
              <span className="mono">{key}</span>.
            </div>
          )}
        </main>
      </div>
    </XdrShell>
  );
}
