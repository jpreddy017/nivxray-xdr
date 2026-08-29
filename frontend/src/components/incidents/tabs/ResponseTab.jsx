/**
 * ResponseTab · placeholder shell for Slice 3.
 *
 * Slice 3 (owner spec) will introduce the Response Task workflow
 * (Approval → Execution → Verification → Audit) plus the IOC
 * blocklist.  Until that lands, this tab is an HONEST empty state —
 * NOT a fake set of buttons that look real.
 */
import React from "react";
import { Lock } from "lucide-react";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

export default function ResponseTab() {
  return (
    <section
      data-testid={T.responsePane}
      style={{
        padding: 22,
        border: "1px dashed rgba(148,163,184,0.20)",
        borderRadius: 10,
        background: "rgba(2,6,23,0.42)",
        display: "flex", flexDirection: "column", gap: 8,
      }}
    >
      <div style={{
        display: "inline-flex", alignItems: "center", gap: 8,
        color: "rgba(148,163,184,0.85)",
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 10, letterSpacing: "0.18em", textTransform: "uppercase",
      }}>
        <Lock size={12} /> Reserved · Slice 3
      </div>
      <div style={{ fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>
        Response tasks land in the next slice
      </div>
      <div style={{ fontSize: 12, color: "rgba(203,213,225,0.75)",
                      lineHeight: 1.5, maxWidth: 640 }}>
        The Response tab will host the operational task workflow
        (Approval · Execution · Verification · Audit) plus the IOC
        blocklist.  We intentionally do not surface fake buttons here —
        every response action must be backed by a real audit trail
        before it appears in the UI.
      </div>
    </section>
  );
}
