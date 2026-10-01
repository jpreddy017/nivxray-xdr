/**
 * ResponseTab · XDR skin.
 *
 * Slice 3 will introduce the Response Task workflow (Approval,
 * Execution, Verification, Audit) plus IOC blocklist.  For Slice 1
 * this tab is an HONEST reserved state — no fake buttons.
 */
import React from "react";
import { Lock } from "lucide-react";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

export default function ResponseTab() {
  return (
    <div className="x-reserved" data-testid={T.responsePane}>
      <div className="lock"><Lock size={11} /> Reserved · Slice 3</div>
      <div className="title">Response tasks land in the next slice</div>
      <div className="body">
        The Response tab will host the operational task workflow —
        Approval · Execution · Verification · Audit — plus the IOC
        blocklist.  We intentionally do not surface fake buttons here:
        every response action must be backed by a real audit trail
        before it appears in the UI.
      </div>
    </div>
  );
}
