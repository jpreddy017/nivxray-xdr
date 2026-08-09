/**
 * P0.15C-3 · Acquisition Evidence List
 * ─────────────────────────────────────
 * Renders VEEE OCR-derived commands with a Jump-to-Source trigger
 * per row.  Consumes `acquisition_ocr_records` attached by
 * `routers/cases.py`.  Never mutates state.
 *
 * Tolerance rule (§0.2) — empty or missing list renders a friendly
 * placeholder, never an error.
 */
import React from "react";
import JumpToSource from "./JumpToSource";

export default function AcquisitionEvidenceList({ records }) {
    const rows = Array.isArray(records) ? records : [];

    if (rows.length === 0) {
        return (
            <div
                data-testid="acq-evidence-empty"
                className="text-xs text-neutral-500 italic p-3 border border-dashed rounded">
                No OCR-derived evidence for this case.
            </div>
        );
    }

    return (
        <div
            data-testid="acq-evidence-list"
            className="rounded-lg border border-neutral-200 bg-white p-4">
            <h3 className="text-sm font-semibold text-neutral-800 mb-3">
                OCR Evidence · {rows.length}
            </h3>
            <div className="space-y-2">
                {rows.map((rec, i) => (
                    <div
                        key={`${rec?.provenance?.image_sha256 || "rec"}-${i}`}
                        data-testid={`acq-evidence-row-${i}`}
                        className="flex items-start gap-3 text-sm border-b last:border-b-0 pb-2 last:pb-0">
                        <span className="text-[10px] text-neutral-400 font-mono w-6 flex-shrink-0 mt-0.5">
                            #{i + 1}
                        </span>
                        <div className="flex-1 min-w-0">
                            <div
                                data-testid={`acq-evidence-row-${i}-text`}
                                className="font-mono text-xs text-neutral-900 break-words">
                                {rec?.text || "(no text)"}
                            </div>
                            <div className="mt-1">
                                <JumpToSource record={rec} inline />
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
