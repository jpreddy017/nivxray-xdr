# Device Trajectory UI release candidate

Scope: responsive wide grouped filter panel with timeline-compatible SVG symbols, retained tri-state group selection, per-group counts, collapse, reset, Apply/Cancel, and unavailable-type labels. Includes prior audit-only/dynamic-selection repair through 788933f1 and existing grouped-control checkpoint fa152785. No data or production changes.

Validation: AMP component/model suite 82 passed, 0 failed (6 files). Vite production-mode build with VITE_E3_DT_V3=1 succeeded in 4.82 seconds. Output /tmp/nivx-ui-release-20261102. git diff --check clean. Workspace 2.4 GB free (77% used); build on separate overlay storage.

Release HOLD: browser preview reaches login; authenticated visual and end-to-end checks are not complete. Existing live preview uses a separate /root/rcapp build: this candidate has NOT replaced it. Production 504 root cause and managed database upgrade remain unverified. No claim of full EDR repair or Cisco compatibility certification.

For a single release, build the exact candidate revision with the target environment's API origin and VITE_E3_DT_V3=1. The staged build uses the PREVIEW API origin and must not be promoted unchanged to production. Verify authenticated Device Trajectory at desktop and narrow widths, filter Apply/Cancel/reset and dynamic types against actual data, then record target backend revision and rollback artifact before promotion. Do not combine unrelated dirty files.
