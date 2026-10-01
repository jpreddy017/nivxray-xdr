/**
 * WorkspaceDecodeFailureCard
 * -----------------------------------------------------------------
 * Rendered in the Analyst Workspace whenever the deterministic
 * PowerShell -EncodedCommand recovery chain fails. Replaces the
 * OUTPUT panel's "DECODED OUTPUT" block that previously rendered
 * binary garbage from a latin-1 fallback of corrupted UTF-16LE
 * bytes.
 *
 * Contract (locked with SOC user 2026-07-25):
 *   ✓ Base64 decoded  (with byte count)
 *   ✗ UTF-16LE validation failed (with byte offset + reason)
 *   • Hex preview (bytes rendered as hex, never as chars)
 *   • Possible causes (corrupted / truncated / nested / non-PS)
 *   • Recovery attempts (deterministic order, per-decoder status + reason)
 *   • "Semantic analysis intentionally halted" footer
 */
import React from "react";

const CARD_BG   = "border border-red-500/60 bg-red-950/25 rounded p-3 mb-2";
const HDR       = "text-[10px] tracking-[0.24em] font-bold uppercase";
const SUB_HDR   = "text-[9px] uppercase tracking-widest text-slate-500 mb-1";
const STATUS = {
  succeeded: "border-emerald-500/60 text-emerald-200 bg-emerald-500/10",
  applied:   "border-emerald-500/60 text-emerald-200 bg-emerald-500/10",
  skipped:   "border-slate-600/60 text-slate-300 bg-slate-500/10",
  failed:    "border-red-500/60 text-red-200 bg-red-500/10",
};


export default function WorkspaceDecodeFailureCard({ err }) {
  if (!err || !err.status) return null;
  const confTone = {
    high:   "border-emerald-500/60 text-emerald-100 bg-emerald-500/15",
    medium: "border-amber-500/60 text-amber-100 bg-amber-500/15",
    low:    "border-sky-500/60 text-sky-100 bg-sky-500/15",
    none:   "border-red-500/60 text-red-100 bg-red-600/15",
  }[err.confidence_band] || "border-slate-600 text-slate-300";
  return (
    <div className={CARD_BG} data-testid="workspace-decode-error-card">
      <div className="flex flex-wrap items-baseline gap-2 mb-2">
        <span className={`${HDR} text-red-200`}>
          Decode Failure · analysis halted
        </span>
        <span className={`px-2 py-0.5 rounded-full border text-[10px] uppercase tracking-widest font-bold ${confTone}`}
              data-testid="workspace-decode-error-confidence"
              title={err.confidence_reason || ""}>
          confidence · {err.confidence_band || "none"}
        </span>
        <span className="px-2 py-0.5 rounded-full border border-slate-600 text-slate-300 text-[10px] uppercase tracking-widest font-mono"
              data-testid="workspace-decode-error-layers">
          {err.recovered_layers || "0/0"} layers
        </span>
        <span className="ml-auto px-2 py-0.5 rounded-full border border-red-500/70
                         bg-red-600/30 text-red-100 text-[10px] uppercase tracking-widest font-bold">
          verdict · Undetermined
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-2 text-[11px]">
        <div className="flex items-baseline gap-2"
             data-testid="workspace-decode-error-b64">
          <span className={`w-4 text-[13px] font-bold ${
            err.b64_status === "succeeded" ? "text-emerald-400" : "text-red-400"
          }`}>{err.b64_status === "succeeded" ? "✓" : "✗"}</span>
          <span className="text-slate-200 font-bold">Base64 decoded</span>
          <span className="text-slate-500">·</span>
          <span className="text-slate-400 font-mono">{err.b64_reason}</span>
        </div>
        <div className="flex items-baseline gap-2"
             data-testid="workspace-decode-error-utf16">
          <span className="w-4 text-[13px] font-bold text-red-400">✗</span>
          <span className="text-slate-200 font-bold">UTF-16LE validation failed</span>
          {err.first_invalid_offset != null && (
            <span className="text-slate-400 font-mono">
              at byte {err.first_invalid_offset}
            </span>
          )}
        </div>
      </div>

      {err.invalid_reason && (
        <div className="text-[11px] text-slate-300 mb-2 pl-6">
          <span className="text-slate-500 uppercase text-[9px] tracking-widest mr-2">Reason</span>
          <span className="font-mono">{err.invalid_reason}</span>
        </div>
      )}

      {err.confidence_reason && (
        <div className="text-[11px] text-slate-300 mb-2 pl-6"
             data-testid="workspace-decode-error-confidence-reason">
          <span className="text-slate-500 uppercase text-[9px] tracking-widest mr-2">Confidence</span>
          <span>{err.confidence_reason}</span>
        </div>
      )}

      {/* Partial recovery — best-effort, clearly labeled */}
      {err.partial_recovery && err.partial_recovery.prefix_text && (
        <div className="mb-3 p-2 rounded border border-sky-500/40 bg-sky-950/25"
             data-testid="workspace-decode-error-partial">
          <div className="flex flex-wrap items-baseline gap-2 mb-1">
            <span className="text-[10px] uppercase tracking-widest font-bold text-sky-300">
              Partial Recovery · diagnostic only
            </span>
            <span className="text-[10px] font-mono text-slate-400 ml-auto">
              {err.partial_recovery.prefix_bytes} bytes recovered · {err.partial_recovery.corrupted_bytes} bytes corrupted
            </span>
          </div>
          <pre className="px-2 py-1 bg-slate-950/80 border border-slate-800 rounded text-[11px]
                          font-mono text-emerald-200 whitespace-pre-wrap break-all leading-snug"
               data-testid="workspace-decode-error-partial-text">
            {err.partial_recovery.prefix_text}
          </pre>
          <div className="text-[10px] text-slate-400 italic mt-1">
            {err.partial_recovery.confidence_note}
          </div>
        </div>
      )}

      {err.hex_preview && (
        <div className="mb-2">
          <div className={SUB_HDR}>
            Hex preview (bytes are shown as HEX — not as characters)
          </div>
          <pre className="px-2 py-1 bg-slate-950/80 border border-slate-800 rounded text-[10px]
                          font-mono text-amber-200 whitespace-pre-wrap break-all leading-snug"
               data-testid="workspace-decode-error-hex">
            {err.hex_preview.replace(/(.{2})/g, "$1 ").trim()}
          </pre>
        </div>
      )}

      {(err.possible_causes || []).length > 0 && (
        <div className="mb-2">
          <div className={SUB_HDR}>Possible causes</div>
          <ul className="text-[11px] text-slate-300 space-y-0.5"
              data-testid="workspace-decode-error-causes">
            {err.possible_causes.map((c, i) => (
              <li key={i} className="flex gap-1.5">
                <span className="text-red-400 mt-0.5">▸</span>
                <span>{c}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {(err.attempts || []).length > 0 && (
        <div>
          <div className={SUB_HDR}>
            Recovery attempts ({err.attempts.length})
          </div>
          <div className="space-y-1" data-testid="workspace-decode-error-attempts">
            {err.attempts.map((a, i) => (
              <div key={i}
                   data-testid={`workspace-decode-error-attempt-${i}`}
                   className={`flex flex-wrap items-baseline gap-2 text-[10.5px] px-2 py-1 rounded border ${
                     STATUS[a.status] || "border-slate-700 text-slate-300"
                   }`}>
                <span className="font-mono font-bold text-slate-200">{a.decoder}</span>
                <span className={`px-1.5 py-0 rounded text-[9px] uppercase tracking-widest font-bold border ${
                  STATUS[a.status] || "border-slate-600 text-slate-300"
                }`}>{a.status}</span>
                <span className="text-slate-400 font-mono flex-1 min-w-0 break-words">
                  {a.reason}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mt-2 pt-2 border-t border-red-500/20 text-[10.5px] text-slate-400 italic">
        Verdict intentionally left as <b>Undetermined</b> — a decode failure is not
        the same as "safe." Semantic analysis halted; xor-brute and other legacy
        decoders were skipped on purpose. Never rendered binary garbage.
      </div>
    </div>
  );
}
