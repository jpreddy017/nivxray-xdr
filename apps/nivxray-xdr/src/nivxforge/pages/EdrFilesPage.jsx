/**
 * NivXForge EDR · File Trajectory (SHA-256).
 *
 * Where one piece of content has been seen across the acting customer's
 * endpoints: the paths it ran from, what the activity was, and WHEN the
 * endpoint observed it. Clicking a sighting opens that endpoint's Device
 * Trajectory in a NEW TAB at the observed time, so this file investigation
 * stays open beside it.
 *
 * Two honesty rules the page states rather than hides:
 *   · a sighting is an executed-image digest, not file create/write/delete;
 *   · a sighting is placed at `observed_at`, never at ingest time — those fall
 *     on different UTC days whenever delivery crosses midnight.
 */
import { FileText, Loader2, Search } from "lucide-react";
import React, { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { fileSightings } from "@/nivxforge/edrApi";
import { readActingCustomer } from "@/lib/actingCustomer";

const SHA256 = /^[0-9a-f]{64}$/i;

const utc = (iso) => {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, 19) + "Z"; }
  catch { return String(iso); }
};

/** The link that carries this sighting into the device canvas, at its time. */
export function sightingHref(sha256, s, customer) {
  if (!s?.endpoint_id || !s?.observed_at) return null;
  const q = new URLSearchParams({ device: s.endpoint_id, at: s.observed_at,
                                  sha256 });
  if (customer) q.set("tenant", customer);
  return `/edr/device-trajectory?${q.toString()}`;
}

const SightingRow = ({ s, sha256, customer, testid }) => {
  const href = sightingHref(sha256, s, customer);
  return (
    <tr data-testid={testid} data-day-shift={s.ingest_day_differs ? "1" : "0"}>
      <td className="mono" style={{ whiteSpace: "nowrap" }}>{utc(s.observed_at)}</td>
      <td>{s.activity || "—"}</td>
      <td className="mono" style={{ wordBreak: "break-all" }}>{s.path || "—"}</td>
      <td className="mono">{s.user || "—"}</td>
      <td className="mono">{s.pid ?? "—"}</td>
      <td>
        {href ? (
          <a href={href} target="_blank" rel="noopener noreferrer"
             data-testid={`${testid}-open`}
             title={`Open ${s.endpoint_id} at ${utc(s.observed_at)}`}>
            Open trajectory
            <span className="sr-only"> (opens in a new tab)</span>
          </a>
        ) : (
          <span data-testid={`${testid}-no-link`} className="muted"
                title="This sighting records no endpoint or no observation time, so there is nothing to open.">
            ◇ not openable
          </span>
        )}
      </td>
    </tr>
  );
};

const SightingTable = ({ rows, sha256, customer, prefix }) => (
  <table className="x-table" data-testid={`${prefix}-table`}>
    <thead><tr>
      <th>Observed (UTC)</th><th>Activity</th><th>Path</th>
      <th>User</th><th>PID</th><th>Device Trajectory</th>
    </tr></thead>
    <tbody>
      {rows.map((s, i) => (
        <SightingRow key={s.raw_id || i} s={s} sha256={sha256}
                     customer={customer} testid={`${prefix}-row-${i}`} />
      ))}
    </tbody>
  </table>
);

export default function EdrFilesPage() {
  const [params, setParams] = useSearchParams();
  const urlHash = (params.get("sha256") || "").trim();
  const [draft, setDraft] = useState(urlHash);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const customer = readActingCustomer()?.customer || null;

  useEffect(() => setDraft(urlHash), [urlHash]);

  const look = useCallback((hash) => {
    if (!hash) { setData(null); setErr(null); return; }
    setLoading(true); setErr(null);
    fileSightings(hash)
      .then((d) => setData(d))
      .catch((e) => {
        const detail = e?.response?.data?.detail || {};
        // "Pick a customer first" is not a failure of the read, and must not
        // be dressed in red as one.
        setErr({
          neutral: ["TENANT_REQUIRED", "TENANT_NOT_RESOLVED"].includes(detail.code),
          code: detail.code || null,
          text: detail.reason || detail.error || e?.message || String(e),
        });
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { look(urlHash); }, [urlHash, look]);

  const submit = (e) => {
    e?.preventDefault?.();
    const v = draft.trim();
    setParams(v ? { sha256: v } : {}, { replace: true });
  };

  const malformed = draft.trim() && !SHA256.test(draft.trim());

  return (
    <NivXForgeConsole activeTab="files">
      <div className="x-page" data-testid="edr-files-page">
        <h1 className="x-h1"><FileText size={18} /> File Trajectory</h1>
        <p className="x-sub" data-testid="edr-files-scope">
          Every endpoint in the acting customer where this content was seen
          executing. The sensor reports the digest of the executed image, so a
          sighting means this content ran from this path — file create, write
          and delete are not collected, and silence here is not proof the file
          is absent.
        </p>

        <form onSubmit={submit} className="x-row" data-testid="edr-files-form"
              style={{ gap: 8, margin: "14px 0" }}>
          <input value={draft} onChange={(e) => setDraft(e.target.value)}
                 data-testid="edr-files-sha256-input"
                 aria-label="SHA-256"
                 placeholder="SHA-256 (64 hex characters)"
                 className="mono" style={{ flex: 1, maxWidth: 620 }} />
          <button type="submit" className="x-btn" data-testid="edr-files-lookup"
                  disabled={!draft.trim() || !!malformed}>
            <Search size={13} /> Look up
          </button>
        </form>

        {malformed && (
          <div className="x-empty" data-testid="edr-files-malformed">
            A SHA-256 is 64 hexadecimal characters. Nothing has been looked up,
            so this is not an empty result.
          </div>
        )}

        {loading && (
          <div className="x-empty" data-testid="edr-files-loading">
            <Loader2 size={13} className="spin"
                     style={{ verticalAlign: "middle", marginRight: 6 }} />
            Reading sightings in {customer || "the acting customer"} …
          </div>
        )}

        {err && !loading && (
          err.neutral ? (
            <div className="x-empty" data-testid="edr-files-no-customer"
                 data-code={err.code}>
              Select a customer to look up a file. Sightings are read within one
              customer, so there is nothing to search until you name it.
            </div>
          ) : (
            <div className="x-empty" data-testid="edr-files-error"
                 data-code={err.code} style={{ color: "var(--red)" }}>
              The sighting read failed: {err.text}. No evidence was returned, so
              this is not an absence of sightings.
            </div>
          )
        )}

        {data && !loading && !err && data.ok === false && (
          <div className="x-empty" data-testid="edr-files-rejected"
               data-reason={data.reason}>{data.note}</div>
        )}

        {data?.ok && !loading && (
          <div data-testid="edr-files-result" data-total={data.total_sightings}>
            <div className="x-facts" data-testid="edr-files-summary">
              <span><span className="k">SHA-256</span>
                <span className="v mono" data-testid="edr-files-key">{data.sha256}</span></span>
              <span><span className="k">Customer</span>
                <span className="v" data-testid="edr-files-customer">{data.tenant}</span></span>
              <span><span className="k">Sightings</span>
                <span className="v">{data.total_sightings}</span></span>
              <span><span className="k">Endpoints</span>
                <span className="v">{data.endpoint_count}</span></span>
              <span><span className="k">First observed</span>
                <span className="v mono">{utc(data.first_observed)}</span></span>
              <span><span className="k">Last observed</span>
                <span className="v mono">{utc(data.last_observed)}</span></span>
            </div>

            {data.total_sightings === 0 && (
              <div className="x-empty" data-testid="edr-files-none">
                No endpoint in {data.tenant} has reported this content. The
                lookup succeeded and returned nothing — this is an honest zero
                for this customer, not a failed read, and it says nothing about
                any other customer.
              </div>
            )}

            {data.truncated && (
              <div className="x-note" data-testid="edr-files-truncated">
                This digest has more sightings than one read returns
                ({data.scanned} read). The newest are shown; the totals above
                describe what was read, not the whole history.
              </div>
            )}

            {data.day_shifted_sightings > 0 && (
              <section data-testid="edr-files-day-shift">
                <h2 className="x-h2">
                  Delivered on a different UTC day ({data.day_shifted_sightings})
                </h2>
                <p className="x-sub">
                  These were observed on one UTC day and ingested on another.
                  The link uses the day the endpoint OBSERVED them, which is
                  where the evidence actually is.
                </p>
                <SightingTable rows={data.day_shifted_examples || []}
                               sha256={data.sha256} customer={data.tenant}
                               prefix="edr-files-shift" />
              </section>
            )}

            {(data.endpoints || []).map((ep, i) => (
              <section key={ep.endpoint_id || i}
                       data-testid={`edr-files-endpoint-${i}`}
                       data-endpoint={ep.endpoint_id}>
                <h2 className="x-h2">
                  {ep.hostname || ep.endpoint_id}
                  <span className="muted mono" style={{ fontSize: 12, marginLeft: 10 }}>
                    {ep.endpoint_id} · {ep.sighting_count} sightings ·{" "}
                    {ep.paths.length} path{ep.paths.length === 1 ? "" : "s"}
                  </span>
                  {ep.identity !== "registered" && (
                    <span className="muted" data-testid={`edr-files-endpoint-${i}-unregistered`}
                          style={{ fontSize: 12, marginLeft: 10 }}
                          title="The events name this endpoint, but no registered endpoint record matches it in this customer.">
                      ◇ unregistered reference
                    </span>
                  )}
                </h2>
                {ep.paths.length > 1 && (
                  <p className="x-sub" data-testid={`edr-files-endpoint-${i}-paths`}>
                    Same content, {ep.paths.length} recorded paths:{" "}
                    <span className="mono">{ep.paths.join(" · ")}</span>
                  </p>
                )}
                <SightingTable rows={ep.sightings} sha256={data.sha256}
                               customer={data.tenant}
                               prefix={`edr-files-endpoint-${i}`} />
              </section>
            ))}
          </div>
        )}
      </div>
    </NivXForgeConsole>
  );
}
