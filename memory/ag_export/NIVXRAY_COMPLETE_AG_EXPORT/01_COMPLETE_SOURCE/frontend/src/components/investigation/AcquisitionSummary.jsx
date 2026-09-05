/**
 * P0.15C-2 · Acquisition Summary Panel
 * ─────────────────────────────────────
 * Read-only display of the acquisition-layer counters emitted by
 * `services/veee/summary.py`.  Never mutates anything, never
 * fetches anything — it consumes the `acquisition_summary` field
 * already attached to the case-read response by
 * `routers/cases.py`.
 *
 * Tolerant of missing data: if `acquisition_summary` is null or
 * every counter is zero the panel renders zeros rather than an
 * error.  When `NVX_VEEE_ENABLED=0` this is exactly the observed
 * state — the panel stays quiet and the Workspace is
 * byte-identical to pre-P0.15C.
 */
import React, { useState } from "react";

// Status → badge styling map (P0.15C-2 refinement)
const STATUS_STYLES = {
    completed:     { icon: "✓", className: "bg-emerald-50 text-emerald-700" },
    partial:       { icon: "⚠", className: "bg-amber-50 text-amber-700" },
    failed:        { icon: "✗", className: "bg-rose-50 text-rose-700" },
    disabled:      { icon: "–", className: "bg-neutral-100 text-neutral-500" },
    not_available: { icon: "–", className: "bg-neutral-100 text-neutral-500" },
};

// Small drill-down chevron.  Rotates 90° when the section is open.
function Chevron({ open }) {
    return (
        <svg
            aria-hidden="true"
            viewBox="0 0 20 20"
            className={
                "w-3 h-3 text-neutral-500 transition-transform duration-150 " +
                (open ? "rotate-90" : "rotate-0")
            }>
            <path
                fill="currentColor"
                d="M7 5l6 5-6 5V5z"
            />
        </svg>
    );
}

export default function AcquisitionSummary({ summary }) {
    // Drill-down state.  Panel starts open; sub-sections start open.
    const [panelOpen, setPanelOpen] = useState(true);
    const [openSections, setOpenSections] = useState({
        HTML: true, Images: true, Recovered: true,
        Quality: true, Performance: true, "Pipeline Stage Health": true,
    });
    const toggleSection = (title) =>
        setOpenSections((prev) => ({ ...prev, [title]: !prev[title] }));

    // Tolerance rule (§0.2) — a missing summary renders zeros,
    // never an error.
    const s = summary || {
        schema_version: "1.0",
        veee_enabled:   false,
        structured_blocks: 0,
        sections: {
            html:        { paragraphs: 0, tables: 0, code_blocks: 0 },
            images:      { found: 0, ocr_candidates: 0, processed: 0, skipped: 0, skipped_reasons: {} },
            recovered:   { commands: 0, powershell: 0, registry: 0, urls: 0, hashes: 0, iocs: 0 },
            quality:     { average_ocr_confidence: 0, ocr_commands_extracted: 0,
                              canonicalized_successfully: 0, classification_success_rate: 0 },
            performance: { processing_time_ms: 0, cache_hits: 0, cache_misses: 0 },
            pipeline_health: {
                html:          { status: "not_available", detail: "no HTML acquired" },
                images:        { status: "not_available", detail: "no images discovered" },
                ocr:           { status: "not_available", detail: "no OCR candidates" },
                canonicalizer: { status: "not_available", detail: "no commands extracted" },
                classifier:    { status: "not_available", detail: "no commands to classify" },
            },
        },
    };
    const sec = s.sections;
    // Defensive default in case an older payload lacks pipeline_health
    const health = sec.pipeline_health || {
        html:          { status: "not_available", detail: "" },
        images:        { status: "not_available", detail: "" },
        ocr:           { status: "not_available", detail: "" },
        canonicalizer: { status: "not_available", detail: "" },
        classifier:    { status: "not_available", detail: "" },
    };

    const row = (label, value) => (
        <div className="flex items-center justify-between text-sm py-0.5"
                data-testid={`acq-row-${label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}>
            <span className="text-neutral-500">{label}</span>
            <span className="font-mono tabular-nums text-neutral-900">{value}</span>
        </div>
    );

    const Section = ({ title, children }) => {
        const open = openSections[title] !== false;
        const testId = `acq-section-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
        return (
            <div className="mb-3" data-testid={testId}>
                <button
                    type="button"
                    onClick={() => toggleSection(title)}
                    data-testid={`${testId}-toggle`}
                    aria-expanded={open}
                    className="w-full flex items-center gap-1.5 mb-1 text-left cursor-pointer hover:text-neutral-900">
                    <Chevron open={open} />
                    <span className="text-xs font-semibold uppercase tracking-wide text-neutral-600">
                        {title}
                    </span>
                </button>
                {open && <div data-testid={`${testId}-body`}>{children}</div>}
            </div>
        );
    };

    return (
        <div
            data-testid="acquisition-summary-panel"
            className="rounded-lg border border-neutral-200 bg-white p-4 max-w-md">
            <div className="flex items-center justify-between mb-3">
                <button
                    type="button"
                    onClick={() => setPanelOpen(!panelOpen)}
                    data-testid="acq-panel-toggle"
                    aria-expanded={panelOpen}
                    className="flex items-center gap-2 text-left cursor-pointer hover:text-neutral-900">
                    <Chevron open={panelOpen} />
                    <h3 className="text-sm font-semibold text-neutral-800">Acquisition Summary</h3>
                </button>
                <span
                    data-testid="acq-flag-status"
                    className={
                        "px-2 py-0.5 rounded text-xs font-medium "
                        + (s.veee_enabled
                              ? "bg-emerald-50 text-emerald-700"
                              : "bg-neutral-100 text-neutral-500")
                    }>
                    {s.veee_enabled ? "VEEE ON" : "VEEE OFF"}
                </span>
            </div>

            {panelOpen && (<div data-testid="acq-panel-body">

            <Section title="HTML">
                {row("Paragraphs",   sec.html.paragraphs)}
                {row("Tables",       sec.html.tables)}
                {row("Code blocks",  sec.html.code_blocks)}
            </Section>

            <Section title="Images">
                {row("Found",           sec.images.found)}
                {row("OCR candidates",  sec.images.ocr_candidates)}
                {row("Processed",       sec.images.processed)}
                {row("Skipped",         sec.images.skipped)}
            </Section>

            <Section title="Recovered">
                {row("Commands",    sec.recovered.commands)}
                {row("PowerShell",  sec.recovered.powershell)}
                {row("Registry",    sec.recovered.registry)}
                {row("URLs",        sec.recovered.urls)}
                {row("Hashes",      sec.recovered.hashes)}
                {row("IOCs",        sec.recovered.iocs)}
            </Section>

            <Section title="Quality">
                {row("Avg OCR confidence", sec.quality.average_ocr_confidence.toFixed(2))}
                {row("OCR extracted",      sec.quality.ocr_commands_extracted)}
                {row("Canonicalized",      sec.quality.canonicalized_successfully)}
                {row("Classification %",   sec.quality.classification_success_rate + "%")}
            </Section>

            <Section title="Performance">
                {row("Processing ms",  sec.performance.processing_time_ms)}
                {row("Cache hits",     sec.performance.cache_hits)}
                {row("Cache misses",   sec.performance.cache_misses)}
            </Section>

            <Section title="Pipeline Stage Health">
                {[
                    ["HTML",          "html"],
                    ["Images",        "images"],
                    ["OCR",           "ocr"],
                    ["Canonicalizer", "canonicalizer"],
                    ["Classifier",    "classifier"],
                ].map(([label, key]) => {
                    const h = health[key] || { status: "not_available", detail: "" };
                    const badge = STATUS_STYLES[h.status] || STATUS_STYLES.not_available;
                    return (
                        <div key={key}
                                className="flex items-center justify-between text-sm py-0.5"
                                data-testid={`acq-health-${key}`}>
                            <span className="text-neutral-500">{label}</span>
                            <span className="flex items-center gap-2">
                                <span
                                    data-testid={`acq-health-${key}-status`}
                                    className={"px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wide "
                                                    + badge.className}
                                    title={h.detail}>
                                    {badge.icon} {h.status.replace(/_/g, " ")}
                                </span>
                            </span>
                        </div>
                    );
                })}
            </Section>
            </div>)}
        </div>
    );
}
