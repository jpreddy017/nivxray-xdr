/**
 * DT2-3c · INDICATIONS OF COMPROMISE.
 *
 * Presents what an AUTHORITY concluded, in its own words: the indicator,
 * its description, the MITRE attribution it actually carried, the
 * observations it PROVED contributed, and any reference it named that
 * could not be resolved. Nothing here is derived from the trajectory's
 * shape.
 *
 * When no authoritative compromise exists the panel says exactly that.
 * `NO_AUTHORITATIVE_COMPROMISE_OBSERVED` is a real result and is never
 * presented as "clean".
 */
import React from "react";

import { C } from "./ampModel";
import { mitreOf } from "./dt2/compromise";

const Chip = ({ children, tone, testid }) => (
  <span data-testid={testid}
        style={{ display: "inline-block", padding: "1px 7px",
                 borderRadius: 999, fontSize: 11, fontWeight: 600,
                 marginRight: 6, marginTop: 4,
                 color: tone, border: `1px solid ${tone}`,
                 background: "transparent" }}>
    {children}
  </span>
);

export const AmpCompromisePanel = ({ compromise, selectedId, onSelect }) => {
  if (!compromise) return null;
  if (!compromise.observed) {
    return (
      <div data-testid="dt2-ioc-panel"
           data-ioc-state={compromise.state}
           style={{ padding: "8px 12px", borderBottom: `1px solid ${C.grid}`,
                    background: C.paperAlt, fontSize: 12, color: C.inkDim }}>
        <strong style={{ color: C.ink, fontWeight: 700 }}>
          Indications of compromise
        </strong>
        <span data-testid="dt2-ioc-not-observed" style={{ marginLeft: 10 }}>
          none — no authoritative compromise has been recorded for this
          endpoint. Absence of a compromise is not a clean verdict.
        </span>
      </div>
    );
  }
  return (
    <div data-testid="dt2-ioc-panel"
         data-ioc-state={compromise.state}
         data-ioc-count={compromise.events.length}
         style={{ borderBottom: `1px solid ${C.grid}`,
                  background: C.paperAlt }}>
      {compromise.events.map((c) => {
        const mitre = mitreOf(c);
        const sel = c.compromise_event_id === selectedId;
        return (
          <div key={c.compromise_event_id}
               data-testid={`dt2-ioc-entry-${c.compromise_event_id}`}
               data-ioc-authority={c.authority}
               data-ioc-contributors={c.contributorIds.length}
               data-ioc-unresolved={c.unresolved.length}
               data-ioc-mitre-state={mitre.state}
               onClick={() => onSelect?.(c)}
               style={{ padding: "7px 12px", cursor: "pointer",
                        borderLeft: `3px solid ${sel ? C.ioc
                          : "transparent"}`,
                        background: sel ? C.iocBand : "transparent" }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
              <span style={{ color: C.ioc, fontWeight: 800, fontSize: 12 }}>
                ◆ IOC
              </span>
              <span data-testid={`dt2-ioc-indicator-${c.compromise_event_id}`}
                    style={{ color: C.ink, fontWeight: 700, fontSize: 12 }}>
                {c.indicator_id}
              </span>
              <span style={{ color: C.inkFaint, fontSize: 11 }}>
                {c.observed_at || "time not recorded"}
              </span>
            </div>
            <div data-testid={`dt2-ioc-description-${c.compromise_event_id}`}
                 style={{ color: C.inkDim, fontSize: 12, marginTop: 2 }}>
              {c.description}
            </div>
            <div>
              <Chip tone={C.inkDim}
                    testid={`dt2-ioc-authority-${c.compromise_event_id}`}>
                {c.authority}
              </Chip>
              {mitre.tactics.map((t) => (
                <Chip key={t} tone={C.suspicious}
                      testid={`dt2-ioc-tactic-${t}`}>{t}</Chip>
              ))}
              {mitre.techniques.map((t) => (
                <Chip key={t} tone={C.suspicious}
                      testid={`dt2-ioc-technique-${t}`}>{t}</Chip>
              ))}
              {mitre.state === "NO_MITRE_ATTRIBUTION_CARRIED" ? (
                <Chip tone={C.inkFaint}
                      testid={`dt2-ioc-no-mitre-${c.compromise_event_id}`}>
                  no MITRE attribution carried
                </Chip>
              ) : null}
              {c.contributorsProven ? (
                <Chip tone={C.contributor}
                      testid={`dt2-ioc-contributors-${c.compromise_event_id}`}>
                  {c.contributorIds.length} proven contributor
                  {c.contributorIds.length === 1 ? "" : "s"}
                </Chip>
              ) : (
                <Chip tone={C.inkFaint}
                      testid={`dt2-ioc-no-contributors-${
                        c.compromise_event_id}`}>
                  contributors not proven by the authority
                </Chip>
              )}
              {c.unresolved.length ? (
                <Chip tone={C.inkFaint}
                      testid={`dt2-ioc-unresolved-${c.compromise_event_id}`}>
                  {c.unresolved.length} reference
                  {c.unresolved.length === 1 ? "" : "s"} unresolved in this
                  projection
                </Chip>
              ) : null}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default AmpCompromisePanel;
