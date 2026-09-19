/**
 * Windows console · the small set of primitives that are genuinely
 * Windows-specific.
 *
 * Everything else now composes `@/xdr/nx`. The page-local `wx-*` design
 * system (its own chips, tables, sections, facts, buttons and a dark-only
 * palette that was unreadable in light mode) has been deleted: there is
 * ONE design language in NivXRay XDR and it lives in `nx/`.
 */
import React from "react";
import { ChevronRight } from "lucide-react";
import { NxSection, NxState } from "@/xdr/nx";

/**
 * `Acquired → Understood → Detectable`.
 *
 * It computes NOTHING: every stage, its reached flag and its detail come
 * from the server, and clicking a stage drills into the authoritative
 * dimension it stands on.
 */
export const StageBar = ({ stages = [], onDrill = null,
                           testid = "wx-stages" }) => (
  <div className="wxs" data-testid={testid}>
    {stages.map((s, i) => (
      <React.Fragment key={s.stage}>
        <button type="button" className="wxs-stage" title={s.detail}
                data-reached={s.reached ? "true" : "false"}
                data-testid={`wx-stage-${s.stage.toLowerCase()}`}
                onClick={() => onDrill && onDrill(s.drill)}>
          <span className="wxs-name">{s.stage}</span>
          <NxState value={s.state} size="sm" />
        </button>
        {i < stages.length - 1 && (
          <ChevronRight size={12} className="wxs-arrow" aria-hidden="true" />
        )}
      </React.Fragment>
    ))}
  </div>
);

/** Fail-closed tenant scope, stated as an instruction rather than a fault. */
export const SelectCustomerNotice = ({ testid = "wx-select-customer" }) => (
  <NxSection variant="card" title="Select a customer to compute this view"
             testid={testid}
             note="Windows channel, device and coverage truth is tenant-scoped.
                   A cross-tenant principal must name the customer it is
                   operating in — the platform refuses to guess a default,
                   because a coverage claim attributed to the wrong customer
                   is worse than no claim.">
    <NxState value="NOT_AVAILABLE" reason="no customer named" />
  </NxSection>
);

/* ── Renamed, not re-implemented ───────────────────────────────────
 * The Windows tabs were written against `StateChip` / `Fact` / `Section`.
 * Those are now thin renames of the platform primitives so there is ONE
 * implementation of each concept; the local names are kept only where the
 * prop signature is identical. */
export { NxKeyFact as Fact, NxSection as Section } from "@/xdr/nx";

export const StateChip = ({ value, title }) => (
  <NxState value={value} reason={title} />
);
