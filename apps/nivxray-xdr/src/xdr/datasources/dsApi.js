/**
 * Data Sources · authoritative read surface.
 *
 * Every field the Data Sources experience renders is loaded here, and every
 * loader records WHERE the value came from.  Nothing is synthesised: when a
 * backend contract does not exist yet the loader returns `null` and the UI
 * renders the honest "not yet measured / verification unavailable" state.
 *
 * Backend provenance (all read-only):
 *   XDR plane        /api/xdr/collectors                    enrolled collectors
 *                    /api/xdr/collectors/sources/catalog    declared sources
 *                    /api/xdr/ingest/routing/summary        accepted / refused
 *                    /api/xdr/ingest/routing/deliveries     per-delivery evidence
 *   collector plane  /telemetry-health · /outbox/health · /source-types
 *                    /collectors · /connectors
 */
import api from "@/lib/api";
import { activeTenant } from "@/lib/tenant";
import {
  COLLECTOR_CONFIGURED, getOutboxHealth, getTelemetryHealth,
  listCollectorConnectors, listCollectors as listRuntimeCollectors,
  listSourceTypes,
} from "@/xdr/admin/collectorApi";

/** BUILD contracts — declared, not faked.  The UI shows the reason. */
export const BUILD_CONTRACTS = {
  eps:            "Per-stream event rate is not published by any backend yet",
  latency:        "Collection latency P50/P95/P99 is not computed yet",
  parse_measured: "parser_ok / normalized_ok are collector-asserted, not measured",
  completeness:   "COLLECTION_GAP records are not implemented yet (W2 contract C-4)",
  dedupe:         "xdr_ingest_dedupe has no read API yet",
  rules:          "Rule-to-source binding is not implemented yet",
  drops:          "Collector drop counters are not published yet",
};

async function settle(label, fn) {
  try {
    return { label, ok: true, data: await fn(), error: null };
  } catch (e) {
    const raw = e?.response?.data?.error?.reason
      || e?.response?.data?.detail
      || e?.note || e?.message || String(e);
    // A fail-closed backend answers with a DETAIL OBJECT
    // (`{code, reason, fail_closed}`). Handing that object to React as a
    // child crashed the whole Data Sources page — and with it the shell.
    // The reason is preserved; only its shape is normalised here, at the
    // boundary, so no renderer has to defend itself.
    const detail = typeof raw === "string" ? raw
      : (raw && typeof raw === "object"
          ? (raw.reason || raw.error || raw.code || raw.message
             || JSON.stringify(raw))
          : String(raw));
    return { label, ok: false, data: null, error: detail };
  }
}

export async function loadDataSources() {
  const tenant = activeTenant();
  const [cats, cols, summary, health, outbox, types, runtime, conns] =
    await Promise.all([
      settle("sources/catalog", async () =>
        (await api.get("/xdr/collectors/sources/catalog")).data?.data?.sources || []),
      settle("collectors", async () =>
        (await api.get("/xdr/collectors")).data?.data || {}),
      settle("routing/summary", async () =>
        (await api.get("/xdr/ingest/routing/summary")).data || {}),
      settle("telemetry-health", getTelemetryHealth),
      settle("outbox/health", getOutboxHealth),
      settle("source-types", async () =>
        (await listSourceTypes())?.source_types || []),
      settle("collector runtime", async () =>
        (await listRuntimeCollectors())?.collectors || []),
      settle("connectors", async () =>
        (await listCollectorConnectors())?.connectors || []),
    ]);

  const accepted = summary.data?.accepted || {};
  const bySource = accepted.by_declared_source || {};
  const catalog = (cats.data || []).map((s) => ({
    ...s,
    accepted: bySource[s.declared_source] ?? 0,
    state: (bySource[s.declared_source] ?? 0) > 0 ? "receiving" : "not_receiving",
  }));

  return {
    tenant,
    collectorPlaneConfigured: COLLECTOR_CONFIGURED,
    catalog,
    sourceTypes: types.data || [],
    connectors: conns.data || [],
    collectors: cols.data?.collectors || [],
    protocols: cols.data?.protocols || {},
    runtime: runtime.data || [],
    summary: summary.data || null,
    accepted,
    refused: summary.data?.refused || summary.data?.blocked || null,
    telemetryHealth: health.data || null,
    outbox: outbox.data || null,
    loaders: [cats, cols, summary, health, outbox, types, runtime, conns],
  };
}

/** One accepted delivery, used by Verify to prove canonical evidence exists. */
export async function probeAcceptedDelivery() {
  const { data } = await api.get(
    "/xdr/ingest/routing/deliveries?result=ACCEPTED&limit=1");
  return (data?.rows || data?.data?.rows || [])[0] || null;
}
