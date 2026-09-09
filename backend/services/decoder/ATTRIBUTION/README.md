# Universal Decoder Engine · Attribution

**XDR-OWNED clean-room engine.** This folder records every
external source whose *knowledge* or *test vectors* informed the
implementation. Per owner rule and `P0_1B_SCOPE.md`:

- **NO source code copied** from external projects at Gate 2A.
- Every file in `services/decoder/` is clean-room-written from
  documented behaviour + our own test vectors.
- Where a source's licence permits code re-use (Apache/MIT/BSD)
  and we adopt an algorithm shape, the corresponding attribution
  file below is populated per the template in
  `UNIVERSAL_DECODER_LICENSE_MATRIX.md`.

## Sources influencing Gate 2A (CMD Plane-B)

| Source | Licence | Role in Gate 2A |
|---|---|---|
| CMD-DeObfuscator (bobbystacksmash) | BSD 3-Clause | Two-mode design (`delayed_expansion` / `expand_inline`) — reimplemented independently. No code copied. |
| batch_deobfuscator (DissectMalware et al.) | MIT | Behavioural reference for `SET` reassembly and `%VAR%` substitution. No code copied. |
| Invoke-DOSfuscation (Daniel Bohannon) | Apache-2.0 | Technique catalogue (caret / delayed-expansion / SET-reassembly) as inverse targets. Used as documentation only at Gate 2A; corpus regeneration deferred to Gate 2F. |
| LOLBAS Project | CC BY-SA-4.0 | Binary registry knowledge in `services/die/lolbas.py`. Used privately (no public redistribution ⇒ share-alike not triggered). |

## Gate 2A trademark hygiene

No feature is marketed as "CyberChef-compatible",
"batch_deobfuscator-compatible", or "PowerDecode-compatible" in a
way that implies endorsement. Compatibility is claimed only by
test-vector regression parity, never by endorsement framing.
