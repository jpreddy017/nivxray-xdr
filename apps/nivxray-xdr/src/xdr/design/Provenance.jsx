/**
 * <Provenance> — Round 24.9 primitive.
 *
 * Renders a derivation chain.  Each layer is either PRESENT with
 * its own value, or explicitly `present=false` — never fabricated
 * and never hidden.  A missing layer renders as `—` in muted mono.
 *
 *   <Provenance chain={[
 *     { layer: "telemetry",  value: "syslog:cortex", present: true },
 *     { layer: "canonical",  value: "xdr.event",     present: true },
 *     { layer: "correlate",  value: null,            present: false },
 *     { layer: "mapping",    value: "T1059.003",     present: true },
 *   ]} />
 */
import React from "react";

const LAYER_LABELS = {
  telemetry: "Telemetry",
  canonical: "Canonical",
  correlate: "Correlation",
  mapping:   "Mapping",
  graph:     "Graph",
};

export default function Provenance({ chain, testid }) {
  return (
    <span className="evops-provenance" data-testid={testid}>
      {chain.map((layer, idx) => (
        <React.Fragment key={`${layer.layer}-${idx}`}>
          {idx > 0 && (
            <span className="evops-provenance__sep" aria-hidden>›</span>
          )}
          <span className="evops-provenance__layer" data-layer={layer.layer}>
            <span className="evops-provenance__label">
              {LAYER_LABELS[layer.layer] || layer.layer}
            </span>
            <span
              className="evops-provenance__value"
              data-present={layer.present !== false ? "true" : "false"}
            >
              {layer.present !== false && layer.value != null
                ? layer.value
                : "not present"}
            </span>
          </span>
        </React.Fragment>
      ))}
    </span>
  );
}

