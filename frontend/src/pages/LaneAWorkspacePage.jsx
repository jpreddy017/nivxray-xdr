import { useMemo, useState } from "react";

// Lane-A vertical slice · Analyst Workspace projection.
//
// The frontend renders LogicalEvents produced by the T2-frozen wire
// contract.  There is NO verdict calculation, MITRE inference, IOC
// disposition, correlation, or security reasoning here — those live
// in backend services (die.canonical, ice, mitigation, verdict).
//
// This projection reads canonical fields directly:
//   canonical.event.action / category / timestamp
//   canonical.source.ip / user / host
//   canonical.destination.ip / port / domain / url
//   canonical.process.command_line / name / parent
//   canonical.file.hash.sha256 / path

const API = process.env.REACT_APP_BACKEND_URL;

const CATEGORY_LABEL = {
  process: "Process",
  network: "Network",
  file: "File",
  identity: "Identity",
  registry: "Registry",
  unknown: "Uncategorised",
};

function categoryFor(ev) {
  const cf = ev?.canonical_fields || {};
  const variability = ev?.variability || {};
  const cat = cf["canonical.event.category"]
           || variability["canonical.event.category"]?.[0]
           || null;
  if (cat) return String(cat).toLowerCase();
  if (cf["canonical.process.command_line"]) return "process";
  if (cf["canonical.destination.ip"] || cf["canonical.destination.port"]) return "network";
  if (cf["canonical.file.hash.sha256"] || cf["canonical.file.path"]) return "file";
  if (cf["canonical.source.user"] || variability["canonical.source.user"]) return "identity";
  return "unknown";
}

function extractIOCs(events) {
  const ips = new Set();
  const hashes = new Set();
  const domains = new Set();
  const urls = new Set();
  for (const ev of events || []) {
    const cf = ev.canonical_fields || {};
    if (cf["canonical.source.ip"]) ips.add(cf["canonical.source.ip"]);
    if (cf["canonical.destination.ip"]) ips.add(cf["canonical.destination.ip"]);
    if (cf["canonical.file.hash.sha256"]) hashes.add(cf["canonical.file.hash.sha256"]);
    if (cf["canonical.destination.domain"]) domains.add(cf["canonical.destination.domain"]);
    if (cf["canonical.destination.url"]) urls.add(cf["canonical.destination.url"]);
  }
  return {
    ips: [...ips],
    hashes: [...hashes],
    domains: [...domains],
    urls: [...urls],
  };
}

function EventCard({ ev, onSelect, selected }) {
  const cf = ev.canonical_fields || {};
  const label = cf["canonical.event.action"] || "event";
  const cmd = cf["canonical.process.command_line"];
  const src = cf["canonical.source.ip"];
  const dst = cf["canonical.destination.ip"];
  const dstPort = cf["canonical.destination.port"];
  const hash = cf["canonical.file.hash.sha256"];
  const host = ev.variability?.["canonical.source.host"]?.[0];
  const user = ev.variability?.["canonical.source.user"]?.[0];

  return (
    <div
      data-testid={`lane-a-event-${ev.event_id}`}
      onClick={() => onSelect(ev)}
      className={`px-4 py-3 border rounded-lg cursor-pointer transition
        ${selected ? "border-cyan-500 bg-cyan-950/30" : "border-slate-800 bg-slate-900/40 hover:border-slate-700"}`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-mono text-cyan-300">{label}</span>
        <span data-testid={`lane-a-event-count-${ev.event_id}`}
              className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
          ×{ev.count}
        </span>
      </div>
      {cmd && (
        <div className="text-xs text-slate-300 font-mono truncate mb-1">{cmd}</div>
      )}
      <div className="text-xs text-slate-500 flex flex-wrap gap-2">
        {host && <span>host={host}</span>}
        {user && <span>user={user}</span>}
        {src && <span>src={src}</span>}
        {dst && <span>dst={dst}{dstPort ? `:${dstPort}` : ""}</span>}
        {hash && <span title={hash}>sha256={hash.slice(0, 12)}…</span>}
      </div>
      <div className="text-[10px] text-slate-600 mt-2 font-mono">
        {ev.first_seen} → {ev.last_seen}
      </div>
    </div>
  );
}

function ProvenancePanel({ ev }) {
  if (!ev) {
    return (
      <div data-testid="lane-a-provenance-empty"
           className="text-xs text-slate-500 italic p-4">
        Select an event to trace its provenance lineage.
      </div>
    );
  }
  const chain = ev.provenance?.upstream_evidence_ids || [];
  return (
    <div data-testid="lane-a-provenance-panel" className="p-4 space-y-3">
      <h3 className="text-sm font-semibold text-slate-200">Provenance</h3>
      <div className="text-xs text-slate-400 font-mono break-all">
        <div>event_id: {ev.event_id}</div>
        <div>source_file_id: {ev.source_file_id}</div>
        <div>tenant_id: {ev.tenant_id}</div>
        <div>records: {ev.record_refs?.length ?? 0}</div>
      </div>
      <div>
        <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">
          Lineage
        </div>
        <ol data-testid="lane-a-provenance-chain"
            className="text-[11px] font-mono text-slate-400 space-y-0.5">
          {chain.map((entry, i) => (
            <li key={i} className="truncate" title={entry}>
              {i + 1}. {entry}
            </li>
          ))}
        </ol>
      </div>
      <div>
        <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">
          Canonical fields
        </div>
        <ul className="text-[11px] font-mono text-slate-400 space-y-0.5">
          {Object.entries(ev.canonical_fields || {}).map(([k, v]) => (
            <li key={k} className="truncate">
              <span className="text-cyan-500">{k}</span>: {String(v)}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default function LaneAWorkspacePage() {
  const [file, setFile] = useState(null);
  const [parser, setParser] = useState("ndjson");
  const [wire, setWire] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedEv, setSelectedEv] = useState(null);

  const events = wire?.logical_events || [];
  const iocs = useMemo(() => extractIOCs(events), [events]);

  const grouped = useMemo(() => {
    const out = { process: [], network: [], file: [], identity: [], unknown: [] };
    for (const ev of events) {
      const c = categoryFor(ev);
      (out[c] || out.unknown).push(ev);
    }
    return out;
  }, [events]);

  async function onAnalyze() {
    if (!file) return;
    setLoading(true);
    setError(null);
    setWire(null);
    setSelectedEv(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("parser", parser);
      const res = await fetch(`${API}/api/iue/lane-a/analyze`, {
        method: "POST",
        body: fd,
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body?.detail?.error || `http_${res.status}`);
        return;
      }
      const data = await res.json();
      setWire(data);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div data-testid="lane-a-workspace" className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-7xl mx-auto p-6 space-y-6">
        <header className="border-b border-slate-800 pb-4">
          <h1 className="text-2xl font-semibold tracking-tight">
            Lane A · Structured Evidence
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            NDJSON / JSON / CSV / XML → LogicalEvents.  Aggregation only;
            correlation happens later in ICE.
          </p>
        </header>

        <section className="flex flex-wrap gap-3 items-center">
          <input
            data-testid="lane-a-file-input"
            type="file"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            className="text-sm text-slate-300 file:mr-3 file:py-1.5 file:px-3
                       file:rounded file:border file:border-slate-700
                       file:bg-slate-800 file:text-slate-200"
          />
          <select
            data-testid="lane-a-parser-select"
            value={parser}
            onChange={(e) => setParser(e.target.value)}
            className="text-sm bg-slate-800 border border-slate-700 rounded px-2 py-1.5"
          >
            <option value="ndjson">NDJSON</option>
            <option value="json">JSON</option>
            <option value="csv">CSV</option>
            <option value="xml">XML</option>
          </select>
          <button
            data-testid="lane-a-analyze-btn"
            onClick={onAnalyze}
            disabled={!file || loading}
            className="text-sm px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500
                       disabled:bg-slate-800 disabled:text-slate-500 text-white"
          >
            {loading ? "Analyzing…" : "Analyze"}
          </button>
          {error && (
            <span data-testid="lane-a-error" className="text-sm text-red-400">
              Error: {error}
            </span>
          )}
        </section>

        {wire && (
          <>
            <section
              data-testid="lane-a-summary"
              className="grid grid-cols-2 md:grid-cols-4 gap-3"
            >
              <SummaryChip label="Logical Events" value={events.length}
                            testId="lane-a-summary-events" />
              <SummaryChip label="Records"
                            value={wire.report_extraction_fragment?.logical_record_total || 0}
                            testId="lane-a-summary-records" />
              <SummaryChip label="Malformed"
                            value={wire.malformed?.length || 0}
                            testId="lane-a-summary-malformed"
                            danger={(wire.malformed?.length || 0) > 0} />
              <SummaryChip label="Tenant"
                            value={wire.intake_decision?.tenant_id || "—"}
                            testId="lane-a-summary-tenant" mono />
            </section>

            <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {["process", "network", "file", "identity", "unknown"]
                .filter((c) => grouped[c].length > 0)
                .map((c) => (
                  <div
                    key={c}
                    data-testid={`lane-a-panel-${c}`}
                    className="border border-slate-800 rounded-lg p-4 bg-slate-900/30 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <h2 className="text-sm font-semibold text-slate-200">
                        {CATEGORY_LABEL[c]}
                      </h2>
                      <span className="text-xs text-slate-500">
                        {grouped[c].length}
                      </span>
                    </div>
                    <div className="space-y-2">
                      {grouped[c].map((ev) => (
                        <EventCard
                          key={ev.event_id}
                          ev={ev}
                          onSelect={setSelectedEv}
                          selected={selectedEv?.event_id === ev.event_id}
                        />
                      ))}
                    </div>
                  </div>
                ))}
            </section>

            <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div
                data-testid="lane-a-panel-ioc"
                className="border border-slate-800 rounded-lg p-4 bg-slate-900/30"
              >
                <h2 className="text-sm font-semibold text-slate-200 mb-3">
                  IOCs (extracted from canonical fields)
                </h2>
                <IOCList label="IP addresses" items={iocs.ips}
                          testId="lane-a-ioc-ips" />
                <IOCList label="Hashes (SHA-256)" items={iocs.hashes}
                          testId="lane-a-ioc-hashes" mono />
                <IOCList label="Domains" items={iocs.domains}
                          testId="lane-a-ioc-domains" />
                <IOCList label="URLs" items={iocs.urls}
                          testId="lane-a-ioc-urls" />
              </div>

              <div className="border border-slate-800 rounded-lg bg-slate-900/30">
                <ProvenancePanel ev={selectedEv} />
              </div>
            </section>
          </>
        )}
      </div>
    </div>
  );
}

function SummaryChip({ label, value, testId, mono = false, danger = false }) {
  return (
    <div
      data-testid={testId}
      className={`border rounded px-3 py-2 bg-slate-900/40
        ${danger ? "border-red-800" : "border-slate-800"}`}
    >
      <div className="text-[10px] uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className={`text-lg ${mono ? "font-mono" : ""}
        ${danger ? "text-red-400" : "text-slate-100"}`}>
        {value}
      </div>
    </div>
  );
}

function IOCList({ label, items, testId, mono = false }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="mb-3">
      <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">
        {label} · {items.length}
      </div>
      <ul data-testid={testId} className={`text-xs text-slate-300 space-y-0.5 ${mono ? "font-mono" : ""}`}>
        {items.map((it) => (
          <li key={it} className="truncate" title={it}>{it}</li>
        ))}
      </ul>
    </div>
  );
}
