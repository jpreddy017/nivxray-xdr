/**
 * P0.15C-3 · Jump-to-Source · Bounding-Box Overlay
 * ────────────────────────────────────────────────
 * Given a VEEE OCR record with complete provenance, renders the
 * source screenshot with the ``bounding_box`` region highlighted.
 *
 * Contract:
 *   Consumes existing `provenance.image_url` + `provenance.bounding_box`
 *   emitted by VEEE (P0.15B).  No backend changes, no OCR pipeline
 *   changes, no acquisition changes.
 *
 * Tolerance rule (§0.2):
 *   Missing/invalid provenance renders a friendly placeholder —
 *   never throws, never surfaces an error to the analyst.
 */
import React, { useState } from "react";

/** Compute overlay style from bounding_box + rendered image size. */
function bboxStyle(bbox, imgNaturalW, imgNaturalH, imgRenderedW, imgRenderedH) {
    if (!bbox || !imgNaturalW || !imgNaturalH || !imgRenderedW || !imgRenderedH) {
        return { display: "none" };
    }
    const sx = imgRenderedW / imgNaturalW;
    const sy = imgRenderedH / imgNaturalH;
    return {
        position: "absolute",
        left:   `${bbox.x * sx}px`,
        top:    `${bbox.y * sy}px`,
        width:  `${bbox.w * sx}px`,
        height: `${bbox.h * sy}px`,
        border: "2px solid #f59e0b",
        boxShadow: "0 0 0 9999px rgba(0,0,0,0.35)",
        pointerEvents: "none",
        transition: "all 120ms ease-out",
    };
}


/**
 * Renders a single OCR record as a "View Source" trigger; on click
 * expands to show the annotated screenshot.
 *
 * Props:
 *   record    · VEEE OCR record { text, provenance:{image_url, bounding_box, …} }
 *   inline    · when true, renders the image inline instead of in a modal
 */
export default function JumpToSource({ record, inline = false }) {
    const [open, setOpen] = useState(false);
    const [dims, setDims] = useState({ natW: 0, natH: 0, renW: 0, renH: 0 });

    const prov = (record && record.provenance) || {};
    const bbox = prov.bounding_box || null;
    const imgUrl = prov.image_url || "";

    const hasProvenance = Boolean(imgUrl && bbox
        && ["x", "y", "w", "h"].every(k => typeof bbox[k] === "number"));

    if (!hasProvenance) {
        return (
            <span
                data-testid="jump-to-source-unavailable"
                className="text-xs text-neutral-400 italic">
                (no source image)
            </span>
        );
    }

    const onImgLoad = (e) => {
        const img = e.target;
        setDims({
            natW: img.naturalWidth,
            natH: img.naturalHeight,
            renW: img.width,
            renH: img.height,
        });
    };

    const overlay = (
        <div
            data-testid="jump-to-source-overlay"
            className="relative inline-block max-w-full">
            <img
                data-testid="jump-to-source-image"
                src={imgUrl}
                alt="Source screenshot"
                onLoad={onImgLoad}
                className="block max-w-full h-auto rounded border border-neutral-300"
            />
            <div
                data-testid="jump-to-source-bbox"
                style={bboxStyle(bbox, dims.natW, dims.natH, dims.renW, dims.renH)}
            />
        </div>
    );

    // Inline: render toggle + region inline (used when embedded in a
    // list where the analyst wants to peek without leaving context).
    if (inline) {
        return (
            <div data-testid="jump-to-source-inline" className="my-2">
                <button
                    data-testid="jump-to-source-toggle"
                    onClick={() => setOpen(o => !o)}
                    className="text-xs font-medium text-blue-700 hover:text-blue-900 underline underline-offset-2">
                    {open ? "Hide source" : "View source"}
                </button>
                {open && (
                    <div className="mt-2 p-2 border rounded bg-neutral-50">
                        <div className="text-[10px] text-neutral-500 mb-1 font-mono break-all">
                            {imgUrl}
                        </div>
                        {overlay}
                        <div className="mt-1 text-[10px] text-neutral-500 font-mono">
                            bbox: x={bbox.x} · y={bbox.y} · w={bbox.w} · h={bbox.h}
                            {typeof prov.ocr_confidence === "number" && (
                                <span> · conf={prov.ocr_confidence.toFixed(2)}</span>
                            )}
                        </div>
                    </div>
                )}
            </div>
        );
    }

    // Modal: default mode; overlay panel rendered above the page.
    return (
        <>
            <button
                data-testid="jump-to-source-open"
                onClick={() => setOpen(true)}
                className="text-xs font-medium text-blue-700 hover:text-blue-900 underline underline-offset-2">
                View source
            </button>
            {open && (
                <div
                    data-testid="jump-to-source-modal"
                    role="dialog"
                    aria-label="Jump to source"
                    className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
                    onClick={() => setOpen(false)}>
                    <div
                        className="max-w-3xl w-full bg-white rounded-lg shadow-xl p-4"
                        onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-3">
                            <div>
                                <h4 className="text-sm font-semibold">Jump to Source</h4>
                                <div className="text-[10px] text-neutral-500 font-mono break-all mt-0.5">
                                    {imgUrl}
                                </div>
                            </div>
                            <button
                                data-testid="jump-to-source-close"
                                onClick={() => setOpen(false)}
                                className="text-neutral-400 hover:text-neutral-700 text-xl leading-none">
                                ×
                            </button>
                        </div>
                        {overlay}
                        <div className="mt-3 text-xs font-mono text-neutral-600 border-t pt-2">
                            <div>text: <span className="text-neutral-900">{record.text || ""}</span></div>
                            <div>bbox: x={bbox.x} · y={bbox.y} · w={bbox.w} · h={bbox.h}</div>
                            {typeof prov.ocr_confidence === "number" && (
                                <div>confidence: {prov.ocr_confidence.toFixed(3)}</div>
                            )}
                            {prov.image_sha256 && (
                                <div className="break-all">sha256: {prov.image_sha256}</div>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
