/**
 * NxTimeline · the temporal representation, for when a table would destroy
 * the thing the analyst is reading: sequence and gaps.
 *
 * Time is never invented. An entry with no timestamp is grouped under
 * "Time not established" rather than being placed somewhere plausible, and
 * the basis of the clock (`time_basis`) travels with the entry, because an
 * event stamped by an endpoint and one stamped at ingest are not the same
 * claim.
 */
import React from "react";
import NxEntityIcon from "./NxEntityIcon";
import NxState from "./NxOpsState";
import "./nx-ops.css";

const dayOf = (iso) => (iso ? String(iso).slice(0, 10) : null);
const timeOf = (iso) => (iso ? String(iso).slice(11, 19) : "—");

/**
 * @param entries [{ id, at, title, detail?, kind?, state?, basis?, meta? }]
 */
export default function NxTimeline({ entries = [], selectedId = null,
                                     onSelect = null, emptyTitle =
                                       "No event is recorded for this window",
                                     testid = "nx-timeline" }) {
  if (!entries.length) {
    return (
      <p className="nx-sec-note" data-testid={`${testid}-empty`}>
        {emptyTitle}. An empty window is an empty window — nothing is
        back-filled to make the story continuous.
      </p>
    );
  }

  const groups = [];
  for (const e of entries) {
    const day = dayOf(e.at);
    const last = groups[groups.length - 1];
    if (!last || last.day !== day) groups.push({ day, items: [e] });
    else last.items.push(e);
  }

  return (
    <div className="nx-tl" data-testid={testid}>
      {groups.map((g) => (
        <section className="nx-tl-group" key={g.day || "unknown"}>
          <header className="nx-tl-day">
            {g.day || "Time not established"}
          </header>
          <ol className="nx-tl-items">
            {g.items.map((e) => (
              <li className={`nx-tl-item${selectedId === e.id ? " is-selected" : ""}`}
                  key={e.id} data-testid={`${testid}-item-${e.id}`}
                  onClick={() => onSelect && onSelect(e)}>
                <span className="nx-tl-time nx-mono" title={e.basis || undefined}>
                  {timeOf(e.at)}
                </span>
                <span className="nx-tl-dot" aria-hidden="true" />
                <span className="nx-tl-body">
                  <span className="nx-tl-title">
                    {e.kind && <NxEntityIcon kind={e.kind} />}
                    {e.title}
                    {e.state && <NxState value={e.state} size="sm" />}
                  </span>
                  {e.detail && <span className="nx-tl-detail">{e.detail}</span>}
                  {e.basis && (
                    <span className="nx-tl-basis">clock: {e.basis}</span>
                  )}
                </span>
              </li>
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}
