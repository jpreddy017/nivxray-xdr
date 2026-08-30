/**
 * Base-capability consumers.
 *
 * Every helper here CONSUMES an existing NivXRay Tool API rather than
 * reimplementing the underlying engine.  On any failure we return an
 * "adapter_disconnected" envelope so the UI can render an honest
 * ``AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED`` banner
 * instead of faking data.
 *
 * Adopt-before-invent — see docs/NIVXRAY_XDR_TECHNOLOGY_ADOPTION_MATRIX.md.
 */
import api from "@/lib/api";

async function _call(method, url, opts = {}) {
  try {
    const r = await api.request({ method, url, ...opts });
    return { ok: true, data: r.data };
  } catch (e) {
    return {
      ok: false,
      status: e?.response?.status,
      error:  e?.response?.data?.detail || e?.response?.data?.error || e?.message,
      not_wired: e?.response?.status === 404 || e?.code === "ERR_NETWORK",
    };
  }
}

// ── Verdict Stage-2 ─────────────────────────────────────────────
export const VerdictConsumer = {
  /**
   * `POST /api/verdict/stage2` — authoritative deterministic verdict.
   * XDR NEVER re-implements this; it only surfaces it.  Body shape
   * mirrors the base contract: at minimum ``{ incident_id }``.
   */
  fetch: (body) => _call("POST", "/api/verdict/stage2", { data: body }),
};

// ── IOC Intelligence ────────────────────────────────────────────
export const IocConsumer = {
  /**
   * `GET /api/ioc/lookup` — reputation / relationships / sightings.
   * Never re-implements TI logic.  Query params match the base
   * endpoint: ``{ value, kind }``.
   */
  lookup: ({ value, kind }) => _call("GET", "/api/ioc/lookup",
                                                   { params: { value, kind } }),
};

// ── Decode chain (`/api/analyze`) ───────────────────────────────
export const AnalyzeConsumer = {
  /**
   * `POST /api/analyze` — deterministic multi-stage decoder chain +
   * command-line analyzer.  Used by the Sigma test/replay screen so
   * an encoded PowerShell command is decoded by the AUTHORITATIVE
   * NivXRay decoder, not a copy-pasted ad-hoc one.
   */
  analyzeCommand: (command_line, opts = {}) =>
    _call("POST", "/api/analyze",
             { data: { input: command_line, kind: "commandline", ...opts } }),
};

// ── Investigation report ────────────────────────────────────────
export const ReportConsumer = {
  /**
   * `GET /api/incidents/{id}/summary` — authoritative investigation
   * summary written by NivXRay's report writer.  XDR surfaces this
   * verbatim; there is no second XDR-side report engine.
   */
  summary: (incidentId) =>
    _call("GET", `/api/incidents/${encodeURIComponent(incidentId)}/summary`),
};
