# Decoded-artifact acknowledgement repair — 2026-10-31

Current EDR source baseline: jpreddy017/nivxray-xdr,
phase2/edr-production at 35d47cc96352f492bd4c603a2f2f1b65afb4119f.
This is the observed GitHub source branch, not proof of the deployed server SHA.
Source blob: f62001fa9a4cf780fd9ad4987333f5c8b7a00fd9.
Independent-copy parent: 5e95238e1df0cec4ca277a4784784ac755f3a26b.

## Defect and bounded repair

The legacy v2 decoded-artifact writer caught every insert exception as a
duplicate and ignored the fallback update result. A validator rejection or
other failure could therefore report a cache hit with no persisted artifact.
Cache-hit updates also ignored missing records and acknowledgement.

Only DuplicateKeyError now enters the race-recovery path. Other driver errors
propagate. Inserts require acknowledgement; updates require acknowledgement and
exactly one matched record. Successful return shape and report immutability are
unchanged. No schema, tenant, pipeline-version, hash or collection migration is
part of this repair. The independent edr_decode store already enforces its own
write-confirmation contract; this patch fixes the preserved legacy writer too.

## Verification

Nine focused tests execute the actual module with only deps.db substituted by
controlled doubles, avoiding shared startup/credentials. Six fail on the frozen
baseline; all nine pass on the candidate. Independent suite: 51 passed, including
its real-MongoDB tests. The new legacy writer regression tests themselves use
controlled doubles, not MongoDB. The portable test locates either repository's
backend automatically; a separate rerun confirmed that discovery works.

No full current-product suite, HTTP failure mapping, deployed invocation or
production smoke test was performed. These remain required before promotion.
Caller exception handling may still suppress errors and requires a separate
trace; this repair guarantees the writer itself cannot falsely acknowledge these
cases. Global hash keys, stale replacement and tenant/version semantics in the
legacy path remain open and are not safe to change without consumer migration.

User authorized repairs in both codebases. Changes are confined to repair and
engineering branches. No main/production/preservation ref moves or deployment.
This is author validation, not independent G3 approval. Release remains HOLD.
