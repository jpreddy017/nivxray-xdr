// AMP-parity palette as CSS variables (dark default, light keeps working via [data-nx-theme="light"]).
export const C = {
  page: "var(--v3-page)", panel: "var(--v3-panel)", nav: "var(--v3-nav)", inset: "var(--v3-inset)", band: "var(--v3-band)",
  line: "var(--v3-line)", text: "var(--v3-text)", label: "var(--v3-label)", muted: "var(--v3-muted)", accent: "var(--v3-accent)",
  red: "var(--v3-red)", amber: "var(--v3-amber)", green: "var(--v3-green)", life: "var(--v3-life)", sel: "var(--v3-sel)",
  tip: "var(--v3-tip)", hatch: "var(--v3-hatch)",
};
export const FONT = 'Inter, "Segoe UI", system-ui, -apple-system, Helvetica, Arial, sans-serif';
export const ROW_H = 26, HDR_H = 78, LABEL_W = 260, PANEL_W = 400, ACT_H = 45, DAY = 86_400_000;

export const CSS = `
.v3amp{--v3-page:#1a1c20;--v3-panel:#24272c;--v3-nav:#2e3a4c;--v3-inset:#232d3b;--v3-band:#0f1012;--v3-line:#3a3d42;
--v3-text:#e8eaed;--v3-label:#c9cdd3;--v3-muted:#9aa1ab;--v3-accent:#6ea0ff;--v3-red:#e5534b;--v3-amber:#e3a33a;--v3-green:#3dba7a;
--v3-life:#8d939c;--v3-sel:rgba(110,160,255,.16);--v3-tip:#111316;--v3-hatch:rgba(150,156,166,.28);font-family:${FONT}}
[data-nx-theme="light"] .v3amp{--v3-page:#f3f4f6;--v3-panel:#ffffff;--v3-nav:#dfe6f0;--v3-inset:#cfd8e4;--v3-band:#e4e7eb;--v3-line:#d3d7dd;
--v3-text:#16181c;--v3-label:#30343a;--v3-muted:#636a74;--v3-accent:#2f6fe4;--v3-red:#c8352d;--v3-amber:#b7791f;--v3-green:#1f9a5a;
--v3-life:#7b828c;--v3-sel:rgba(47,111,228,.14);--v3-tip:#ffffff;--v3-hatch:rgba(100,106,116,.25)}
.v3amp button{font-family:inherit}
.v3amp .v3-btn{background:transparent;color:var(--v3-text);border:1px solid var(--v3-line);border-radius:4px;padding:6px 12px;font-size:13px;cursor:pointer;transition:background-color .15s,border-color .15s}
.v3amp .v3-btn:hover{border-color:var(--v3-accent)}
.v3amp .v3-btn-blue{background:var(--v3-accent);color:#0b1020;border:1px solid var(--v3-accent);font-weight:600}
.v3amp .v3-btn-outline{color:var(--v3-accent);border-color:var(--v3-accent)}
.v3amp .v3-sq{width:34px;height:34px;padding:0;display:inline-flex;align-items:center;justify-content:center}
.v3amp .v3-link{background:none;border:0;color:var(--v3-accent);cursor:pointer;font-size:14px;padding:0}
.v3amp .v3-link:hover{text-decoration:underline}
.v3amp input[type=checkbox]{accent-color:var(--v3-accent);width:14px;height:14px;border-radius:2px}
.v3amp .v3-scroll::-webkit-scrollbar{height:10px;width:10px}.v3amp .v3-scroll::-webkit-scrollbar-thumb{background:#4a4f57;border-radius:6px}
.v3amp .v3-scroll::-webkit-scrollbar-track{background:transparent}
@keyframes v3spin{to{transform:rotate(360deg)}}
@keyframes v3in{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.nvf-console .sidebar{width:360px;flex:0 0 360px}
.nvf-console .sidebar .nav-item{font-size:14px;padding:10px 22px;gap:14px}
.nvf-console .sidebar .nav-item .ic{width:18px}
.nvf-console .sidebar .nav-title{padding:18px 22px 6px}
`;
