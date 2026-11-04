# D14 — NORMALIZER TENANT HARDENING (owner review gate)

Date: 2026-09-14 · **PREVIEW ONLY — no production deployment, no merge.**

```
cd /app/backend && python -m pytest tests/test_d14_tenant_authority.py -q
cd /app          && python scripts/p0_d14_tenant_authority_live_proof.py
```

---

## CHANGED

| File | Δ | What |
|---|---|---|
| `backend/services/tenant_authority.py` | **NEW**, 135 | The single answer to "whose evidence is this?" — `resolve()`, `payload_claims()`, `record()` |
| `linux_auditd_dsm.py` | −7/+5 | payload-first precedence removed; tenant no longer reachable by payload for D10 identity material |
| `windows_security_dsm.py` | −7/+4 | same |
| `aws_cloudtrail_dsm.py` | −7/+4 | same |
| `cef_leef_dsm.py` | −7/+4 | same |
| `sysmon_dsm.py` | −7/+4 | routed through the shared helper (D13's local fix replaced) |
| `nivxforge_sensor_dsm.py` | −4/+7 | same, plus the `"default"` signature default removed |
| `tests/test_phase2_telemetry_normalization.py` | 4 call sites | now pass the authenticated tenant explicitly — **not** repaired by restoring a default |
| `tests/test_d14_tenant_authority.py` | **NEW**, 76 tests | |
| `scripts/p0_d14_tenant_authority_live_proof.py` | **NEW** | 26/26 PASS in preview over real HTTP |

Signature defaults removed everywhere: `tenant_id: Optional[str] = "default"`
→ `= None` in `linux-auditd`, `windows-security-evd`, `aws-cloudtrail`,
`cef-leef`, and `nivxforge-linux-sensor`. `None`, `""`, whitespace-only,
absent, a payload fallback and `"default"` can no longer establish tenant
authority. Non-`str` types are refused too, so `0` and `False` cannot become
`"0"`/`"False"` and pass for an established identity.

The authenticated ingest guards themselves were **not** touched — only what
happens downstream of them.

## SECURITY INVARIANT

```
authenticated delivery tenant  ->  authoritative tenant  ->  normalizer
```

Enforced in one place. A payload-named tenant survives only as:

```
tenant_claim = {state: UNTRUSTED_SOURCE_CLAIM,
                claimed_tenant_id: …, claim_source: …,
                used: false, agrees_with_authenticated: …,
                reason: "recorded as evidence of what the payload asserted;
                         the authenticated delivery tenant is authoritative
                         and this value influenced nothing — not ownership,
                         not canonical identity, not partitioning"}
```

It cannot override, select, or serve as a fallback. Untrusted tenant
material reaches neither the D10 canonical `event_id`, nor evidence
ownership, nor persistence partitioning.

**A dishonest label caught and fixed mid-gate.** The first implementation
recorded `raw.tenant_id` as the claim. On a NivX-assembled LINE event that
field is *our own* authenticated tenant (the collector payload sits nested
one level deeper), so the live proof showed
`claim=t-d14-owner-b, agrees_with_authenticated=True` — NivX's own answer
echoing back labelled as an untrusted source claim. `payload_claims()` now
distinguishes the three shapes a normalizer can be handed (DOCUMENT with
`_nivx`, NivX-assembled LINE with nested `raw`, or the payload itself) and
only ever reports what a **source or collector** actually supplied.

## ADVERSARIAL PROOF — 76 tests

Every applicable DSM (`linux-auditd`, `windows-security-evd`,
`aws-cloudtrail`, `microsoft-sysmon`, `cef-leef`,
`nivxforge-linux-sensor`) held to the same answer. `snort-eve` is excluded
deliberately and reported: its normalizer takes no tenant argument at all,
so there is no contract there to attack.

| Attack | Result |
|---|---|
| authenticated B + payload A | tenant = **B**, never A · 6/6 DSMs |
| the A claim | `UNTRUSTED_SOURCE_CLAIM`, `used: false`, `agrees_with_authenticated: false`, source named · 6/6 |
| a clean event | **no** claim recorded at all · 6/6 |
| authenticated `None` / `""` / `"   "` / `"\t\n"` | refused, `NO tenant fallback` · 24/24 |
| payload claim + missing authenticated tenant | refused — a claim cannot rescue it · 18/18 |
| signature defaults | no DSM defaults its tenant; `"default"` is gone · 7/7 incl. a sweep over the whole registry |
| the claimed tenant as an owner field | appears nowhere outside the claim record and preserved raw evidence · 6/6 |

Identity, per your requirement:

* `test_a_payload_claim_cannot_move_the_deterministic_event_id` — the same
  auditd event with and without a payload tenant yields the **same**
  `event_id` and the same `event_id_basis`.
* `test_a_real_change_of_authenticated_tenant_still_changes_identity` — a
  legitimate B→C change **does** move it, because tenant-scoped identity is
  the D10 contract.

## LIVE PROOF — 26/26 PASS, preview, real HTTP

Five envelopes in one authenticated delivery, **all signed with tenant B's
own key**, every payload claiming tenant A:

| Source | Shape | Landed | Claim recorded | used |
|---|---|---|---|---|
| Windows Security | DOCUMENT | `t-d14-owner-b` | `t-d14-victim-a` | false |
| CloudTrail | DOCUMENT | `t-d14-owner-b` | `t-d14-victim-a` | false |
| Sysmon | DOCUMENT | `t-d14-owner-b` | `t-d14-victim-a` | false |
| auditd | LINE | `t-d14-owner-b` | `t-d14-victim-a` | false |
| CEF | LINE | `t-d14-owner-b` | `t-d14-victim-a` | false |

* tenant A canonical evidence: **before 0, after 0**.
* tenant A rows delivered by tenant B's collector: **0**.
* a delivery with a blank tenant: **HTTP 401**, zero canonical evidence.
* the same auditd event with and without the claim: **1** distinct
  `event_id` across 2 deliveries.

## REGRESSION DELTA

| Suite | Result |
|---|---|
| D14 + D13 + D12 + D11 + D2/D3/D10 + D4 + D8 + phase2 normalization + phase2.1 adversarial + telemetry adapters + round11 pipeline | **291 passed** |
| D11 / D12 / D13 live proofs | 30/30 · 16/16 · 41/41 — all still PASS |

In-place baseline (a `git worktree` cannot isolate suites that
`from server import app`), 7 server-importing suites:

| | Baseline (HEAD, D14 reverted) | Patched |
|---|---|---|
| | 13 failed · 60 passed · 20 errors | 13 failed · 60 passed · 20 errors |
| `diff` of failure sets | — | **empty — identical, 33/33** |

Same documented pre-existing families: 4 consolidation, 6
`ACCESS_DENIED … unauthenticated` (Work Mode's auth track), 3
`KeyError: 'proc_root'`, 20 data-sources setup errors from the same auth
track.

## PERFORMANCE

One dict lookup chain and at most two `strip()` calls per event, replacing
the previous inline `or` chain — no measurable change. `tenant_claim` adds
~380 B to a canonical event **only when a payload actually claimed a
tenant**; a clean event carries nothing. No index, no query path, no schema
change.

## REMAINING GAPS

1. **`snort-eve` has no tenant contract.** Its normalizer takes no tenant
   argument and its projection has no `tenant_id` field; the persisted row
   carries the tenant, the projection does not. It therefore cannot be
   attacked *or* hardened at the normalizer. Pre-existing (flagged in D13),
   and the one DSM this invariant does not yet cover.
2. The tenant claim is recorded in `additional_fields`, i.e. inside the
   evidence document. There is no index on it, so "show me every delivery
   that claimed a tenant it did not own" is a collection scan today.
3. This gate hardens the **evidence layer**. Establishing the authenticated
   tenant remains the ingest guards' job and Work Mode's domain; nothing
   there was modified or re-verified beyond observing that a blank tenant is
   refused with 401.
4. `payload_claims()` infers the shape it was handed from structure
   (`_nivx` present / nested `raw` / neither). A future caller that invents
   a fourth shape would get no claim recorded rather than a wrong one —
   fail-quiet on the *reporting* side, never on the authority side.

## PASS/PARTIAL/FAIL

**PASS for preview scope.** Transport/evidence-layer tenant authority
proven; `snort-eve` remains outside the invariant. No real source is
connected, nothing deployed, no merge.

---

## STOP — next already-authorized gate: Declared Source Routing.
