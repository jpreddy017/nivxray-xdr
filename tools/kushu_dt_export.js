// NivXForge DT · READ-ONLY production export (owner-run in DevTools on the logged-in production console tab).
// Issues only GET /api/edr/endpoints/{device}/trajectory (the page's own read). No writes to production.
// Output: downloads nvx_dt_export_<device>.json and (best effort) POSTs chunks to the E3 preview import route.
(async () => {
  const DEVICE = "dev_8b90e7c9a70d";
  const DAYS = 30, LIMIT = 4000, CHUNK = 1500, MAX_PAGES_PER_DAY = 200;
  const PROBE_EVENTS = ["obs_2e29e40ee2dc#c133a4ab50"], MAX_DETAIL = 300;
  const PREVIEW = "https://edr-forge-complete.preview.emergentagent.com/api/e3/trajectory/import";
  const TOKEN = "e3imp_b15b1c9df69ed529c11f1c0c707333b9";
  const H = { Authorization: `Bearer ${localStorage.getItem("nvx_token")}` };
  const tenant = localStorage.getItem("nvx_tenant");
  if (tenant) H["X-Tenant-Id"] = tenant;
  const DAY = 86400000, now = Date.now(), byIid = new Map();
  let computer = null, identity = null, gets = 0;
  for (let d = DAYS - 1; d >= 0; d--) {
    const t1 = now - d * DAY, t0 = t1 - DAY;
    let cursor = null, pages = 0;
    do {
      const qs = new URLSearchParams({ time_start: new Date(t0).toISOString(), time_end: new Date(t1).toISOString(),
        lane_start: "0", lane_end: "100000", limit: String(LIMIT) });
      if (cursor) qs.set("cursor", cursor);
      const r = await fetch(`/api/edr/endpoints/${encodeURIComponent(DEVICE)}/trajectory?${qs}`, { headers: H, credentials: "include" });
      gets++;
      await new Promise((res) => setTimeout(res, 350));
      if (!r.ok) throw new Error(`GET trajectory ${r.status} (day -${d})`);
      const j = await r.json();
      computer = computer || j.computer; identity = identity || j.identity;
      const lanes = new Map((j.lane_axis?.lanes || []).map((l) => [l.lane_index, l]));
      for (const e of j.events || []) byIid.set(e.event_iid, { ...e, lane_label: lanes.get(e.lane_index)?.label ?? null });
      cursor = j.has_more ? j.next_cursor : null;
      pages++;
    } while (cursor && pages < MAX_PAGES_PER_DAY);
    console.log(`[nvx-dt-export] day -${d}: ${byIid.size} unique events so far (${gets} GETs)`);
  }
  const events = [...byIid.values()].sort((a, b) => a.timestamp_instant_ms - b.timestamp_instant_ms);
  // Extra read-only detail for detection events (capped): the page's own focus + observation-narrative responses.
  let detailGets = 0;
  for (const e of events.filter((x) => x.is_detection || x.detection || x.findings?.length).slice(-MAX_DETAIL)) {
    const q = `device=${encodeURIComponent(DEVICE)}&event_iid=${encodeURIComponent(e.event_iid)}`;
    const n = await fetch(`/api/edr/observation-narrative?${q}`, { headers: H, credentials: "include" });
    await new Promise((res) => setTimeout(res, 350));
    detailGets++;
    if (n.ok) e.e3_prod_detail = { observation_narrative: await n.json(), captured_at: new Date().toISOString() };
  }
  console.log(`[nvx-dt-export] captured detail for ${detailGets} detection events`);
  // Raw observation records: production exposes no read-only GET for raw v2_shadow_observations docs. The closest read-only
  // evidence reads are the page's own focus + observation-narrative endpoints; capture them for the probe event(s).
  const probes = {};
  for (const iid of PROBE_EVENTS) {
    const f = await fetch(`/api/edr/endpoints/${encodeURIComponent(DEVICE)}/trajectory/focus?event_iid=${encodeURIComponent(iid)}`, { headers: H, credentials: "include" });
    await new Promise((res) => setTimeout(res, 350));
    const n = await fetch(`/api/edr/observation-narrative?device=${encodeURIComponent(DEVICE)}&event_iid=${encodeURIComponent(iid)}`, { headers: H, credentials: "include" });
    await new Promise((res) => setTimeout(res, 350));
    probes[iid] = { focus: f.ok ? await f.json() : { http: f.status }, narrative: n.ok ? await n.json() : { http: n.status },
      in_export: byIid.has(iid) };
  }
  const head = { format: "NVX_DT_EXPORT_V1", device: DEVICE, source_origin: location.origin, exported_at: new Date().toISOString(),
    window: { start: new Date(now - DAYS * DAY).toISOString(), end: new Date(now).toISOString() }, computer, identity, probes };
  const blob = new Blob([JSON.stringify({ ...head, events })], { type: "application/json" });
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `nvx_dt_export_${DEVICE}.json` });
  document.body.appendChild(a); a.click(); a.remove();
  console.log(`[nvx-dt-export] downloaded ${events.length} events`);
  try {
    const total = Math.ceil(events.length / CHUNK);
    for (let i = 0; i < total; i++) {
      const r = await fetch(PREVIEW, { method: "POST", headers: { "Content-Type": "application/json", "X-E3-Import-Token": TOKEN },
        body: JSON.stringify({ ...head, chunk: { index: i, total }, events: events.slice(i * CHUNK, (i + 1) * CHUNK) }) });
      console.log(`[nvx-dt-export] chunk ${i + 1}/${total}:`, r.status, await r.json());
    }
  } catch (e) {
    console.warn("[nvx-dt-export] direct POST blocked (CSP/CORS). Upload the downloaded file with:\n" +
      `curl -X POST ${PREVIEW} -H 'Content-Type: application/json' -H 'X-E3-Import-Token: ${TOKEN}' --data-binary @nvx_dt_export_${DEVICE}.json`, e);
  }
})();
