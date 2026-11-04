# §13 KPI Trend Register

> Append-only ledger of the eight §13 KPIs, one row per release.
> Populated from each `/app/docs/releases/<RELEASE>-<date>.md`.
> Purpose: track **direction over time**, not release snapshots.
>
> This is engineering hygiene — NOT an architectural artefact.
> Does not modify the Constitution.
> **Once P1-01 · Live OSINT Wiring** ships, the first row is filled in
> and the Constitution v1.0 officially freezes.

## Direction guide

| KPI | Desired direction | Target |
|-----|-------------------|--------|
| Adapter detection accuracy         | ↑ Higher | ≥ 99 %  |
| Normalisation correctness          | ↑ Higher | ≥ 95 %  |
| Cross-vendor equivalence pass rate | ↑ Higher | 100 %   |
| Investigation replay determinism   | ↑ Higher (stable at 100 %) | 100 %   |
| Verdict parity                     | ↑ Higher (stable at 100 %) | 100 %   |
| E2E investigation latency P95      | ↓ Lower  | ≤ 4 s   |
| Deep-command investigation success | ↑ Higher | ≥ 90 %  |
| Golden-corpus coverage             | ↑ Higher | ≥ 95 %  |

## Trend table

| Release | Date | Detection | Normalisation | X-vendor eq. | Replay det. | Verdict parity | Latency P95 | Deep-cmd success | Corpus cov. | Direction summary |
|---------|------|-----------|---------------|--------------|-------------|----------------|-------------|------------------|-------------|-------------------|
| RC-P1-01 (Live OSINT Wiring) | 2026-02-01 | n/a | n/a | n/a | 100 % | 100 % | ~2.4 s | n/a | n/a | = = = = = ↑ = = (OSINT lens now live · 11-field cards) |
| RC-P1-02b (Tiered Verdict Fold) | 2026-02-01 | n/a | n/a | n/a | 100 % | 100 % | ~2.4 s | n/a | n/a | = = = = = = = = (Verdict recall +24 pp · false-positives −8 pp · explainability 100 %) |
| RC-P1-02c (Verdict Polish + Shellcode Parity) | 2026-02-01 | n/a | n/a | n/a | 100 % | 100 % | ~2.6 s | shellcode-chain 100 % | n/a | = = = = = = ↑ = (topology + temporal + entity + negative-evidence signals · confidence breakdown + timeline · Verdict Explanation Card · shellcode banner reaches parity with Workspace) |
| RC-P1-02d (Truth Model + Quality Benchmark) | 2026-02-01 | n/a | n/a | n/a | 100 % | 100 % | ~1 ms (bench) · ~2.6 s (live) | 100 % | 80 % label · 100 % conf · 100 % IOC · 100 % rules · 100 % shellcode · 100 % no over-promotion | = = = = = = ↑ ↑ (canonical Observation→…→Recommendation projection · 10-entry regression corpus · 8 KPIs above threshold · zero drift between Workspace/X-Lab/Report Composer/Timeline/Ledger) |

## Usage rules

- Append-only. Never edit historical rows.
- One row per Release Validation Report.
- "Direction summary" is one word per KPI: `↑ ↓ =` — nothing more.
- Regressions on `Verdict parity`, `Replay determinism`, or
  `Cross-vendor equivalence` are treated as P0 bugs regardless of
  release size.
- Sustained downward trend on any other KPI triggers a review in the
  following sprint — see `/app/docs/BACKLOG.md` request lanes.
