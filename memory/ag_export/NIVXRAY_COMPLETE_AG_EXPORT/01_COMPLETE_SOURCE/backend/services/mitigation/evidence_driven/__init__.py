"""Evidence-Driven Response Recommendation Engine — ISOLATED.

Hard architectural constraint (per user directive, 2026-02-04):

    The existing Workspace must not change.
    This engine is a DOWNSTREAM consumer of the SSOT / decode
    result — never a mutator.  It ships behind a feature flag so
    it can be disabled without affecting the Workspace at all.

Existing contracts preserved:
    · ``services.mitigation.derive_mitigations``   ← DO NOT MODIFY
    · ``POST /api/decode/mitigations``              ← DO NOT MODIFY
    · ``mitigation.schema_version = 1``             ← DO NOT BUMP

Everything below sits under ``services.mitigation.evidence_driven``
and never imports the legacy path in reverse — legacy code has no
knowledge of this engine's existence.

Design axioms
─────────────
1. **Evidence is the primary driver.**  MITRE / malware intel /
   APT intel / LOLBAS *enrich* the decision — they never *invent*
   a recommendation on their own.
2. **Trigger-conditioned rules.**  Every rule declares an explicit
   trigger predicate over the 12 evidence dimensions.  If the
   trigger doesn't fire, the rule emits NOTHING.
3. **No generic checklist.**  The engine produces the actions
   justified by *this* case's evidence, and only those.
4. **Every recommendation carries provenance.**  ``trigger``,
   ``evidence``, ``confidence``, ``mitre``, ``scope``,
   ``requires_confirmation`` — enough for an analyst to audit
   *why* each action was proposed.

Twelve evidence dimensions consumed
───────────────────────────────────
    1. observed_evidence      · files / processes / commands / registry
                                / network / users / hosts / artifacts
    2. detection_type         · signature / heuristic / behavioural /
                                anomaly / pattern / correlation
    3. behavior               · execution / persistence / C2 / cred_access
                                / discovery / lateral / impact
    4. mitre_attack           · techniques + sub-techniques supported
                                by evidence
    5. malware_intel          · family / capability / TTPs
    6. apt_intel              · actor-associated TTPs (only w/ confidence)
    7. lolbas_intel           · abuse of legitimate binaries
    8. iocs                   · IPs / domains / URLs / hashes /
                                filenames / mutexes / certs
    9. attack_pattern         · multi-stage chains + relationships
   10. impact                 · encryption / destruction / cred exposure
                                / data theft / service disruption
   11. scope                  · affected hosts / users / privileged /
                                business-critical assets
   12. confidence             · corroboration / authorized-activity /
                                false-positive indicators
"""
