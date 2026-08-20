// Structured Evidence Tab — the Lane-A projection.
//
// Reads canonical LogicalEvents from `POST /api/iue/lane-a/analyze`
// and displays them grouped by canonical.event.category.  The
// frontend is a pure projection layer:
//   - NO verdict calculation
//   - NO MITRE inference
//   - NO IOC disposition
//   - NO correlation
//   - NO scoring / reasoning / security decisions
// All of the above live in backend services (die.canonical, ice,
// mitigation, verdict).  This component only maps canonical fields
// to visual chips.
import { useMemo, useState } from "react";

const API = process.env.REACT_APP_BACKEND_URL;

const CATEGORY_LABEL = {
    process: "Process",
    network: "Network",
    file: "File",
    identity: "Identity",
    registry: "Registry",
    unknown: "Uncategorised",
};

// Render-safe: never render a raw object.  Anything non-primitive is
// stringified through JSON.stringify to keep [object Object] out of the DOM.
function display(v) {
    if (v === null || v === undefined) return "";
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
    try { return JSON.stringify(v); } catch { return String(v); }
}

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
    const ips = new Set(), hashes = new Set(), domains = new Set(), urls = new Set();
    for (const ev of events || []) {
        const cf = ev.canonical_fields || {};
        if (cf["canonical.source.ip"]) ips.add(cf["canonical.source.ip"]);
        if (cf["canonical.destination.ip"]) ips.add(cf["canonical.destination.ip"]);
        if (cf["canonical.file.hash.sha256"]) hashes.add(cf["canonical.file.hash.sha256"]);
        if (cf["canonical.destination.domain"]) domains.add(cf["canonical.destination.domain"]);
        if (cf["canonical.destination.url"]) urls.add(cf["canonical.destination.url"]);
    }
    return { ips: [...ips], hashes: [...hashes], domains: [...domains], urls: [...urls] };
}

function EventCard({ ev, onSelect, selected }) {
    const cf = ev.canonical_fields || {};
    const label = display(cf["canonical.event.action"] || "event");
    const cmd = display(cf["canonical.process.command_line"]);
    const src = display(cf["canonical.source.ip"]);
    const dst = display(cf["canonical.destination.ip"]);
    const dstPort = display(cf["canonical.destination.port"]);
    const hash = display(cf["canonical.file.hash.sha256"]);
    const host = display(ev.variability?.["canonical.source.host"]?.[0]);
    const user = display(ev.variability?.["canonical.source.user"]?.[0]);

    return (
        <div
            data-testid={`evidence-event-${ev.event_id}`}
            onClick={() => onSelect(ev)}
            className={
                "px-3 py-2 border rounded cursor-pointer transition " +
                (selected
                    ? "border-cyan-500 bg-cyan-950/30"
                    : "border-slate-800 bg-slate-900/40 hover:border-slate-700")
            }>
            <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-cyan-300">{label}</span>
                <span
                    data-testid={`evidence-event-count-${ev.event_id}`}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                    ×{ev.count}
                </span>
            </div>
            {cmd && <div className="text-[11px] text-slate-300 font-mono truncate mb-1">{cmd}</div>}
            <div className="text-[10px] text-slate-500 flex flex-wrap gap-2">
                {host && <span>host={host}</span>}
                {user && <span>user={user}</span>}
                {src && <span>src={src}</span>}
                {dst && <span>dst={dst}{dstPort ? `:${dstPort}` : ""}</span>}
                {hash && <span title={hash}>sha256={hash.slice(0, 12)}…</span>}
            </div>
            <div className="text-[9px] text-slate-600 mt-1 font-mono">
                {display(ev.first_seen)} → {display(ev.last_seen)}
            </div>
        </div>
    );
}

function ProvenancePanel({ ev }) {
    if (!ev) {
        return (
            <div
                data-testid="evidence-provenance-empty"
                className="text-xs text-slate-500 italic p-3">
                Select an event to trace its provenance lineage.
            </div>
        );
    }
    const chain = ev.provenance?.upstream_evidence_ids || [];
    return (
        <div data-testid="evidence-provenance-panel" className="p-3 space-y-3">
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wide">
                Provenance
            </h3>
            <div className="text-[11px] text-slate-400 font-mono break-all">
                <div>event_id: {display(ev.event_id)}</div>
                <div>source_file_id: {display(ev.source_file_id)}</div>
                <div>tenant_id: {display(ev.tenant_id)}</div>
                <div>records: {ev.record_refs?.length ?? 0}</div>
            </div>
            <div>
                <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">
                    Lineage
                </div>
                <ol
                    data-testid="evidence-provenance-chain"
                    className="text-[10px] font-mono text-slate-400 space-y-0.5">
                    {chain.map((entry, i) => (
                        <li
                            key={i}
                            data-testid={`evidence-provenance-chain-${i}`}
                            className="truncate"
                            title={display(entry)}>
                            {i + 1}. {display(entry)}
                        </li>
                    ))}
                </ol>
            </div>
            <div>
                <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">
                    Canonical fields
                </div>
                <ul className="text-[10px] font-mono text-slate-400 space-y-0.5">
                    {Object.entries(ev.canonical_fields || {}).map(([k, v]) => (
                        <li key={k} className="truncate">
                            <span className="text-cyan-500">{k}</span>: {display(v)}
                        </li>
                    ))}
                </ul>
            </div>
            <div>
                <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">
                    Record references
                </div>
                <ul
                    data-testid="evidence-record-refs"
                    className="text-[10px] font-mono text-slate-500 space-y-0.5">
                    {(ev.record_refs || []).map((r) => (
                        <li key={r}>{display(r)}</li>
                    ))}
                </ul>
            </div>
        </div>
    );
}

function SummaryChip({ label, value, testId, mono = false, danger = false }) {
    return (
        <div
            data-testid={testId}
            className={
                "border rounded px-2 py-1.5 bg-slate-900/40 " +
                (danger ? "border-red-800" : "border-slate-800")
            }>
            <div className="text-[9px] uppercase tracking-wide text-slate-500">{label}</div>
            <div
                className={
                    "text-sm " +
                    (mono ? "font-mono " : "") +
                    (danger ? "text-red-400" : "text-slate-100")
                }>
                {display(value)}
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
            <ul
                data-testid={testId}
                className={"text-xs text-slate-300 space-y-0.5 " + (mono ? "font-mono" : "")}>
                {items.map((it) => (
                    <li key={it} className="truncate" title={display(it)}>
                        {display(it)}
                    </li>
                ))}
            </ul>
        </div>
    );
}

// The reusable tab body.  Consumers pass EITHER:
//   - `wire` (already-fetched T2 shape from the backend)
//   - OR nothing → this component renders an in-tab uploader that calls
//     POST /api/iue/lane-a/analyze itself.
export default function StructuredEvidenceTab({ wire: externalWire = null }) {
    const [file, setFile] = useState(null);
    const [parser, setParser] = useState("ndjson");
    const [internalWire, setInternalWire] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [selectedEv, setSelectedEv] = useState(null);

    const wire = externalWire || internalWire;
    const events = wire?.logical_events || [];
    const iocs = useMemo(() => extractIOCs(events), [events]);
    const malformedCount = wire?.malformed?.length || 0;

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
        setInternalWire(null);
        setSelectedEv(null);
        try {
            const fd = new FormData();
            fd.append("file", file);
            fd.append("parser", parser);
            const res = await fetch(`${API}/api/iue/lane-a/analyze`, { method: "POST", body: fd });
            if (!res.ok) {
                const body = await res.json().catch(() => ({}));
                setError(body?.detail?.error || `http_${res.status}`);
                return;
            }
            const data = await res.json();
            setInternalWire(data);
        } catch (e) {
            setError(String(e.message || e));
        } finally {
            setLoading(false);
        }
    }

    return (
        <div
            data-testid="structured-evidence-tab"
            className="text-slate-100 space-y-4"
            style={{ padding: 14 }}>
            {!externalWire && (
                <section className="flex flex-wrap gap-2 items-center">
                    <input
                        data-testid="evidence-file-input"
                        type="file"
                        onChange={(e) => setFile(e.target.files?.[0] || null)}
                        className="text-xs text-slate-300 file:mr-2 file:py-1 file:px-2
                             file:rounded file:border file:border-slate-700
                             file:bg-slate-800 file:text-slate-200"
                    />
                    <select
                        data-testid="evidence-parser-select"
                        value={parser}
                        onChange={(e) => setParser(e.target.value)}
                        className="text-xs bg-slate-800 border border-slate-700 rounded px-2 py-1">
                        <option value="ndjson">NDJSON</option>
                        <option value="json">JSON</option>
                        <option value="csv">CSV</option>
                        <option value="xml">XML</option>
                    </select>
                    <button
                        data-testid="evidence-analyze-btn"
                        onClick={onAnalyze}
                        disabled={!file || loading}
                        className="text-xs px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500
                             disabled:bg-slate-800 disabled:text-slate-500 text-white">
                        {loading ? "Analyzing…" : "Analyze"}
                    </button>
                    {error && (
                        <span data-testid="evidence-error" className="text-xs text-red-400">
                            Error: {display(error)}
                        </span>
                    )}
                </section>
            )}

            {!wire && (
                <div
                    data-testid="evidence-empty-state"
                    className="text-xs text-slate-500 italic py-6 text-center">
                    Upload NDJSON / JSON / CSV / XML security telemetry to project
                    LogicalEvents into this tab.
                </div>
            )}

            {wire && (
                <>
                    <section
                        data-testid="evidence-summary"
                        className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        <SummaryChip
                            label="Logical Events"
                            value={events.length}
                            testId="evidence-summary-events"
                        />
                        <SummaryChip
                            label="Records"
                            value={wire.report_extraction_fragment?.logical_record_total || 0}
                            testId="evidence-summary-records"
                        />
                        <SummaryChip
                            label="Malformed"
                            value={malformedCount}
                            testId="evidence-summary-malformed"
                            danger={malformedCount > 0}
                        />
                        <SummaryChip
                            label="Tenant"
                            value={wire.intake_decision?.tenant_id || "—"}
                            testId="evidence-summary-tenant"
                            mono
                        />
                    </section>

                    <section
                        data-testid="evidence-panels"
                        className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                        {["process", "network", "file", "identity", "unknown"]
                            .filter((c) => grouped[c].length > 0)
                            .map((c) => (
                                <div
                                    key={c}
                                    data-testid={`evidence-panel-${c}`}
                                    className="border border-slate-800 rounded p-2 bg-slate-900/30 space-y-2">
                                    <div className="flex items-center justify-between">
                                        <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wide">
                                            {CATEGORY_LABEL[c]}
                                        </h2>
                                        <span className="text-[10px] text-slate-500">
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

                    <section className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                        <div
                            data-testid="evidence-panel-ioc"
                            className="border border-slate-800 rounded p-3 bg-slate-900/30">
                            <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wide mb-2">
                                IOCs · projected from canonical fields
                            </h2>
                            <IOCList label="IP addresses" items={iocs.ips} testId="evidence-ioc-ips" />
                            <IOCList label="Hashes (SHA-256)" items={iocs.hashes} testId="evidence-ioc-hashes" mono />
                            <IOCList label="Domains" items={iocs.domains} testId="evidence-ioc-domains" />
                            <IOCList label="URLs" items={iocs.urls} testId="evidence-ioc-urls" />
                            {iocs.ips.length + iocs.hashes.length + iocs.domains.length + iocs.urls.length === 0 && (
                                <div
                                    data-testid="evidence-ioc-empty"
                                    className="text-xs text-slate-500 italic">
                                    No IOCs projected from the current LogicalEvents.
                                </div>
                            )}
                        </div>

                        <div className="border border-slate-800 rounded bg-slate-900/30">
                            <ProvenancePanel ev={selectedEv} />
                        </div>
                    </section>
                </>
            )}
        </div>
    );
}
