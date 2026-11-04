/**
 * NormalizationBody — authoritative Normalizers admin surface.
 * Real data via GET /api/admin/content-supply-chain/engines/list?role=NORMALIZER
 */
import React from "react";
import { Shuffle } from "lucide-react";
import EngineRoleAdminBody from "@/xdr/admin/EngineRoleAdminBody";


export default function NormalizationBody() {
  return <EngineRoleAdminBody
    role="NORMALIZER"
    eyebrow="Admin › Data Plane › Normalization"
    title="Normalization Registry"
    subtitle={<>
      Normalizers transform parsed evidence into canonical evidence —
      the tenant-invariant schema every downstream engine (analyzer,
      correlator, verdict) consumes.  Field-mapping ambiguity is
      resolved here, not upstream at the parser stage.
    </>}
    icon={Shuffle}
    testid="admin-normalization"
    emptyCopy="No normalizers have been classified yet — re-run engine discovery."
  />;
}
