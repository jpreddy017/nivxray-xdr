/**
 * E2E-UX0 · Attack Story tab (blueprint §3.3).
 *
 * The anti-debug-console surface. One card per stage, and each card is
 * CLAIM (prose) · BASIS (source) · PROOF (chips that open a flyout).
 * No JSON, no log dump, no uniform card grid.
 */
import React, { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { NxProvenanceChip, NxVerdict } from "@/xdr/nx";
import { Panel, StageRail } from "./Ux0Parts";

export default function Ux0AttackStory({ stages, claims, onProof }) {
  const [active, setActive] = useState("execution");
  const [open, setOpen] = useState(
    () => Object.fromEntries(claims.map((c) => [c.stage, !!c.open])),
  );
  const toggle = (k) => setOpen((o) => ({ ...o, [k]: !o[k] }));

  return (
    <div style={{ marginTop: 18, display: "flex", flexDirection: "column", gap: 14 }}>
      <Panel title="Attack progression" testid="ux0-story-rail"
             right={<span style={{ fontSize: 11, color: "var(--nx-muted)" }}>
               5 stages · 2 observed · 1 decoded · 2 pending
             </span>}>
        <StageRail stages={stages} active={active} onSelect={setActive} />
      </Panel>

      <div data-testid="ux0-story-claims">
        {claims.map((c, i) => (
          <article key={c.stage}
                   className={`ux0-claim ux0-rise${open[c.stage] ? " is-open" : ""}`}
                   style={{ animationDelay: `${i * 60}ms` }}
                   data-testid={`ux0-claim-${i}`}>
            <button type="button" className="ux0-claim__h"
                    onClick={() => toggle(c.stage)}
                    data-testid={`ux0-claim-toggle-${i}`}>
              {open[c.stage] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <span className="ux0-sevdot" data-sev={c.severity} />
              <span className="ux0-claim__stage">Stage {i + 1} · {c.stage}</span>
              <span className="ux0-claim__n">{c.claim}</span>
              <span style={{ fontSize: 11, color: "var(--nx-muted)", flexShrink: 0 }}>
                {c.evidence} evidence
              </span>
            </button>
            {open[c.stage] && (
              <div className="ux0-claim__b">
                <div className="ux0-kv">
                  <span className="ux0-kv__k">Claim</span>
                  <span className="ux0-kv__v">{c.claim}</span>
                  <span className="ux0-kv__k">Basis</span>
                  <span className="ux0-kv__v"><code>{c.basis}</code></span>
                  <span className="ux0-kv__k">Proof</span>
                  <span className="ux0-kv__v">
                    {c.proof.map((p) => (
                      <button key={p.label} type="button" className="ux0-proof"
                              onClick={() => onProof(p)}
                              data-testid={`ux0-proof-${p.kind}-${i}`}>
                        {p.label} ▸
                      </button>
                    ))}
                  </span>
                </div>
                <div className="ux0-chiprow" style={{ marginTop: 12 }}>
                  <NxProvenanceChip provenance={c.provenance} />
                  <NxVerdict value={c.severity === "critical" ? "malicious"
                                    : c.severity === "high" ? "suspicious" : "unknown"} />
                </div>
              </div>
            )}
          </article>
        ))}
      </div>
    </div>
  );
}
