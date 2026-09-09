/**
 * AttackStoryTab — Deterministic incident narrative.
 *
 * Reads `investigation.story` (produced by the backend attack-story
 * generator from the IKG). Each sentence carries `frame_iids` and
 * `process_iids` so clicking a sentence deep-links back to the
 * Trajectory tab with the target event focused
 * (`?tab=trajectory&focus=<frame_iid>`).
 */
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { T } from "../theme";
import { useSelection } from "./SelectionContext";

const TACTIC_LABELS = {
  initial_access:      "Initial Access",
  execution:           "Execution",
  persistence:         "Persistence",
  privilege_escalation:"Priv Escalation",
  defense_evasion:     "Defense Evasion",
  credential_access:   "Credential Access",
  discovery:           "Discovery",
  lateral_movement:    "Lateral Movement",
  collection:          "Collection",
  command_and_control: "Command & Control",
  exfiltration:        "Exfiltration",
  impact:              "Impact",
};

const SEV_TONES = {
  low:      "#7DB1D6",
  medium:   "#D4C069",
  high:     "#F5A34C",
  critical: "#FCA5A5",
};

export default function AttackStoryTab({ inv }) {
  const story = inv?.story || [];
  const navigate = useNavigate();
  const { caseId } = useParams();
  const [searchParams] = useSearchParams();
  const { setSelection } = useSelection();

  const jumpToTrajectory = (frameIid, processIid) => {
    // Global selection first — Evidence Card + other views pick it up
    // immediately, even before the URL change re-renders.
    setSelection({
      kind: "event", id: frameIid, frame_iid: frameIid,
      process_iid: processIid || null, source: "story",
    });
    const params = new URLSearchParams(searchParams);
    params.set("tab", "trajectory");
    if (frameIid) params.set("focus", frameIid);
    navigate(`/v2/case/${encodeURIComponent(caseId)}?${params.toString()}`);
  };

  const focusOnly = (frameIid, processIid) => {
    // Same selection push but stay on the Story tab — Evidence Card
    // opens beside the sentence without leaving the narrative.
    setSelection({
      kind: "event", id: frameIid, frame_iid: frameIid,
      process_iid: processIid || null, source: "story",
    });
  };

  if (story.length === 0) {
    return (
      <div className="p-12 text-center" style={{ color: T.inkFaint }}
           data-testid="attack-story-empty">
        No attack story generated. The device may be benign or lacks
        enough evidence for the deterministic narrator.
      </div>
    );
  }

  return (
    <div data-testid="attack-story-tab" className="max-w-4xl mx-auto py-8 px-6 space-y-6">
      <div>
        <div className="text-[10px] tracking-[2px] font-bold mb-1"
             style={{ color: T.inkMute }}>ATTACK STORY</div>
        <div className="text-[22px] font-bold" style={{ color: T.ink }}>
          Deterministic incident narrative
        </div>
        <div className="text-[12px] mt-1" style={{ color: T.inkDim }}>
          Every sentence is derived from the Investigation Knowledge Graph.
          Click a sentence to jump to the exact evidence on the Trajectory tab.
          No LLM · same input → same story.
        </div>
      </div>

      <ol className="space-y-3" data-testid="attack-story-list">
        {story.map((s, idx) => {
          const tone = SEV_TONES[s.severity] || T.emerald;
          const firstFrame = s.frame_iids?.[0];
          const firstProc  = s.process_iids?.[0];
          return (
            <li key={idx}
                data-testid={`story-sentence-${idx}`}
                className="rounded-md p-3 hover:bg-white/5 transition-colors cursor-pointer"
                onClick={() => firstFrame && focusOnly(firstFrame, firstProc)}
                style={{ background: T.paper2, border: `1px solid ${T.line}` }}>
              <div className="flex items-start gap-3">
                <div className="text-[11px] font-mono font-bold"
                     style={{ color: T.inkMute, minWidth: 24 }}>
                  {String(idx + 1).padStart(2, "0")}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-[9px] tracking-[1.4px] font-bold px-1.5 py-0.5 rounded"
                          style={{ background: T.paper, color: tone,
                                   border: `1px solid ${tone}44` }}>
                      {TACTIC_LABELS[s.tactic] || s.tactic}
                    </span>
                    <span className="text-[9px] tracking-[1.3px] font-bold"
                          style={{ color: tone }}>
                      {s.severity.toUpperCase()}
                    </span>
                    {s.signals && s.signals.slice(0, 3).map(sig => (
                      <span key={sig}
                            className="text-[9px] font-mono px-1 py-0.5 rounded"
                            style={{ background: T.paper, color: T.inkMute,
                                     border: `1px solid ${T.line}` }}>
                        {sig}
                      </span>
                    ))}
                  </div>
                  <div className="text-[13px] leading-relaxed"
                       style={{ color: T.ink }}>
                    {s.text}
                  </div>
                  <div className="mt-2 flex items-center gap-3 text-[10px]"
                       style={{ color: T.inkFaint }}>
                    <span className="font-mono">
                      evidence · {s.evidence_ref}
                    </span>
                    <span className="font-mono">
                      {s.frame_iids?.length || 0} event(s) ·
                      {" "}{s.process_iids?.length || 0} process(es)
                    </span>
                    {firstFrame && (
                      <button
                        data-testid={`story-jump-${idx}`}
                        onClick={(e) => { e.stopPropagation(); jumpToTrajectory(firstFrame, firstProc); }}
                        className="ml-auto text-[10px] px-2 py-0.5 rounded font-mono
                                   hover:opacity-80 transition-opacity"
                        style={{ background: T.paper, color: T.emerald,
                                 border: `1px solid ${T.emerald}44` }}>
                        show on trajectory →
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </li>
          );
        })}
      </ol>

      <div className="text-[10px] font-mono pt-4 border-t"
           style={{ color: T.inkFaint, borderColor: T.line }}
           data-testid="attack-story-footer">
        {story.length} sentence(s) · deterministic · reconstructed from IKG
      </div>
    </div>
  );
}
