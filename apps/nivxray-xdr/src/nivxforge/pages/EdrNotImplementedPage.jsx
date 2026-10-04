/**
 * The ONE honest surface for a navigation destination that exists in the
 * permanent NivXForge information architecture but is not implemented in
 * this wave. It states the capability, why it is unavailable, and what
 * would make it real — and offers no control that cannot act.
 */
import React from "react";
import { Construction } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import "@/nivxforge/nvf-ops.css";

export function NotImplementedBody({ heading, body, why, testid }) {
  return (
    <div className="ni" data-testid={testid || "edr-not-implemented"}
         data-state="NOT_IMPLEMENTED">
      <span className="tag"><Construction size={10} /> Not implemented</span>
      <div className="h">{heading}</div>
      <div className="b">{body}</div>
      <div className="why">{why}</div>
    </div>
  );
}

export default function EdrNotImplementedPage({ navKey, heading, body, why }) {
  return (
    <NivXForgeConsole activeTab={navKey}>
      <div className="ops-head">
        <div>
          <span className="eyebrow">NivXForge EDR</span>
          <h1 className="ttl">{heading}</h1>
          <div className="sub">
            This destination is part of the permanent product information
            architecture. It is shown so the console never hides the shape of
            the product — and it is disabled rather than filled with a page
            that looks functional.
          </div>
        </div>
      </div>
      <NotImplementedBody heading={heading} body={body} why={why}
                          testid={`edr-not-implemented-${navKey}`} />
    </NivXForgeConsole>
  );
}
