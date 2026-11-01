# Computer-specific Device Trajectory renderer parity

User reference: the main Device Trajectory tab is correct; entering trajectory
from a selected computer is different/wrong. Preserve the reference renderer.

Confirmed source routing: App.jsx mounts DeviceTrajectoryEntry for
/edr/device-trajectory; Computers opens /edr/computers/:endpointId/trajectory.
EdrDevicePage previously imported the legacy EdrDeviceTrajectoryPage directly,
bypassing the shared V3/preview feature selection. Both repositories have identical
pre-repair component blobs: EdrDevicePage f7f565e6ee8df242eca7af9cf76eec15b6a2159a;
V3 wrapper 93664e96486e6cdc63fbf7e9c5046cbb558d17bf.

Repair: use DeviceTrajectoryEntry in the computer workspace. The V3 wrapper now
accepts embedded/device props; the explicit endpoint overrides the query-string
device and carries through legacy switching. Embedded mode avoids a second
console shell. Device keys reset local renderer state when endpoints change.
Top-level tab selection and build flags are unchanged. No API, backend permission,
response-action, dataset or canvas-model change is included.

Validation: real React components rendered through react-test-renderer with mocked
router, API and canvas dependencies. Checks cover V3 selection from the workspace,
path identity over conflicting query identity, single shell, legacy scope,
endpoint change reset and unchanged top-tab query selection. Original workspace
fails the first parity assertion; repaired components pass. Dependencies for this
standalone harness: react/react-test-renderer 18.3.1 and esbuild 0.25.0. Run with
NODE_PATH pointing to their installation: node tools/test-trajectory-navigation.cjs.

Limits: this is component contract validation, not live browser screenshots,
full frontend build, actual telemetry API validation or independent G3 review.
Actual deployed flags/revision remain unverified. Preview mode and existing
query/filter/time-window behavior remain separate verification work. Production
release remains HOLD. Repairs are only on current-product repair and independent
engineering branches; main, production and preservation remain unchanged.
