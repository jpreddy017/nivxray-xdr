# 01 · X-Lab Constitution

## The equation
```
Current Lab (brain)  +  Lab 2.0 (face)  +  Future Investigation Features  =  X-Lab
```

## Golden Rule
> **Current Lab = Brain. Lab 2.0 = Face. X-Lab = Product.**
> There must never be two investigation workspaces.

## What migrates from the legacy Lab
Engines · decoders · parsers · APIs · recipes · rules · YARA · Sigma · TI-HITS · LOLBAS · OSINT · investigation engine · report generation · MITRE mapping · IOC extraction · Evidence Graph · timeline data.

## What does NOT migrate
❌ Legacy Lab panels · layouts · CSS · Preview mode · feature flags · duplicate pages · legacy renderers.

## Navigation (locked)
`Workspace · Trajectory · Batch · Heatmap · X-Lab · Tools · Learn · Admin`
No `LAB` tab. No `Lab 2.0` tab. No Preview. No feature-flag surface.

## Route (locked)
```
/lab                            ─┐
/nivxforge/investigate          ─┼─→ redirect →  /nivxforge/x-lab
/nivxforge/investigate?lab2=1   ─┘
```
One route. One investigation experience.

## Migration Order (immutable)
1. Capability audit — enumerate every legacy Lab capability. (`/app/memory/xlab_parity_audit.md`)
2. Mirror every capability into X-Lab (backend/API only — no UI migration).
3. Parity CI — decoded output · verdict · confidence · ATT&CK · IOCs · Rules · LOLBAS · TI-HITS · OSINT · report must all be identical Workspace ↔ X-Lab.
4. Nav switch (`LAB` → `X-LAB`).
5. Redirect legacy routes to `/nivxforge/x-lab`.
6. Delete legacy Lab (routes · components · CSS · renderers · duplicate APIs · duplicate state · feature flags · preview code).

## Future Policy (permanent)
Every future investigation capability ships ONLY in X-Lab. Nothing investigation-related is ever added back to the legacy Lab.
