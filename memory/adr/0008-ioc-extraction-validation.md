# ADR-0008 — IOC Extraction Validation

- **Status:** Proposed
- **Date:** 2026-02-28
- **Deciders:** Operator (product owner) · Emergent (proposer)
- **Threshold met:** 4 independent real-world observations (P-IOC-VALIDATION)

## 1 · Evidence supporting this proposal

Four independent workspace_cases exhibit IOC extraction that produces invalid or
false-positive artifacts:

| Case | Extracted "IOC" | Actual source | Defect |
|---|---|---|---|
| 0007 | domain `stem.ma` | Substring of `System.Management.Automation` reconstruction fragment `stem.Ma`+`na{1}`+`e`+`ment.` | Domain regex has no context awareness; grabs any `xxx.yy` pattern |
| 0011 | ip `1.0.0.721` | Extraction from RTF content | IP regex accepts octets > 255 |
| 0012 | ip `6.94.002.01` | Substring of some text region | IP regex accepts leading-zero octets |
| 0014 | domain `stem.ma` | Same `System.Management.Automation` fragment as Case 0007 | Same regex issue observed independently |

**Common thread:** the IOC-extraction regexes for `ipv4` and `domain` are purely
pattern-shape (four dotted numeric groups; two labels separated by a dot with
TLD-length-shape). They do NOT:
- Validate that each IPv4 octet ∈ [0, 255].
- Reject IPv4 octets with leading zeros (RFC 6943 §3.1.1).
- Reject domains whose left-context is `.` on a word boundary of a longer
  identifier (e.g. `System.Management` produces `stem.Ma` — the extractor
  should reject if the left-most label appears mid-word in the source).

## 2 · Proposed governance rule

The IOC extractor MUST apply a two-stage pipeline:

1. **Regex extract** (current behaviour).
2. **Validation gate** — an extracted candidate is only emitted if:
   - **IPv4:** every octet parses as integer in `[0, 255]` AND no octet has a
     leading zero unless the octet is exactly `0`.
   - **Domain:** the left character preceding the match is not `[A-Za-z0-9]`
     (i.e. the extractor requires a word-boundary-left context — not a
     mid-identifier substring).
   - **All types:** confidence/provenance metadata records which of the two
     stages allowed the candidate through (so an analyst can filter).

## 3 · Explicit non-goals

- Not proposing changes to which IOC types are extracted.
- Not proposing threat-intelligence enrichment changes.
- Not proposing changes to the verdict engine (Verdict-side use of IOCs is
  governed by ADR-0007 separately).

## 4 · Scope

- Backend IOC-extractor path only.
- Zero changes to NivXForge frontend or the analyst API contract.
- Response shape for `iocs` field stays the same; the field simply contains
  fewer (but higher-quality) entries after the gate.

## 5 · Testing before Accepted

Before promotion from Proposed → Accepted, the operator MUST review:

1. Each of Cases 0007, 0011, 0012, 0014 would drop the specific invalid extract
   under the proposed gate.
2. A representative valid-IOC case (e.g. Case 0009 — real domain
   `georgeprapas.com`; Case 0012 — real IP `10.200.49.6`) would remain
   extracted unchanged.
3. Regression: full nivxforge test suite must remain 49/49 PASS.

## 6 · Approval gate

Do NOT implement until this ADR is marked **Accepted** by the operator and a
Phase-1a scope is defined.

## 7 · Relationship to ADR-0007

ADR-0007 and ADR-0008 are **independent**. Either can be accepted / rejected
without affecting the other. However, if both are accepted, ADR-0008 SHOULD
land first — cleaner IOCs improve the fidelity of the content-source
indicators that ADR-0007 depends on.
