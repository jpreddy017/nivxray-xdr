/**
 * ParsersBody — authoritative Parsers admin surface.
 * Data: /api/admin/content-supply-chain/engines/list?role=PARSER
 * + contract statuses from /contracts?classification=PARSER
 */
import React from "react";
import { Filter } from "lucide-react";
import EngineRoleAdminBody from "@/xdr/admin/EngineRoleAdminBody";


export default function ParsersBody() {
  return <EngineRoleAdminBody
    role="PARSER"
    eyebrow="Admin › Data Plane › Parsers"
    title="Parser Registry"
    subtitle={<>
      Every parser is a real Python implementation discovered by the
      Engine Classifier at import-time. A parser reads raw artifacts
      (bytes, script text, log lines) and emits <b>parsed evidence</b>,
      which the Normalizer stage then lifts into canonical evidence.
      NivXRay does not use a monolithic vendor "DSM" — parsing and
      normalization are two distinct, independently-composable stages.
    </>}
    icon={Filter}
    testid="admin-parsers"
    emptyCopy="No parsers have been classified yet — re-run engine discovery."
  />;
}
