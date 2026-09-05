/**
 * data-testid map for the L4 Analyst Workspace shell.
 *
 * ARB Governance (post-PR-2 review): every interactive element and
 * every element showing user-facing info in a UI PR must carry a
 * unique, kebab-case `data-testid`. This module is the single source
 * of truth so tests and the shell agree on selectors.
 *
 * New IDs added in future PRs must extend this map (never overload
 * existing IDs).
 */

// ── Shell chrome ─────────────────────────────────────────────────────
export const TID_SHELL_ROOT             = "workspace-shell-root";
export const TID_SHELL_HEADER           = "workspace-shell-header";
export const TID_SHELL_SIDEBAR          = "workspace-shell-sidebar";
export const TID_SHELL_MAIN             = "workspace-shell-main";
export const TID_SHELL_FOOTER           = "workspace-shell-footer";

// ── Case identity ────────────────────────────────────────────────────
export const TID_CASE_ID_LABEL          = "workspace-case-id";
export const TID_CASE_LOAD_ERROR        = "workspace-case-load-error";
export const TID_CASE_EMPTY             = "workspace-case-empty";
export const TID_CASE_LOADING           = "workspace-case-loading";
export const TID_CASE_RETRY_BTN         = "workspace-case-retry";

// ── State pill (Blueprint §8.1) ──────────────────────────────────────
export const TID_STATE_PILL             = "workspace-state-pill";
export const TID_STATE_PILL_VALUE       = "workspace-state-pill-value";
export const TID_STATE_TRANSITION_BTN   = (target) => `workspace-state-transition-${target}`;

// ── Mode selector (Blueprint §8.2) ───────────────────────────────────
export const TID_MODE_SELECT            = "workspace-mode-select";
export const TID_MODE_OPTION            = (mode) => `workspace-mode-option-${mode}`;

// ── Lens tabs (Blueprint §9) ─────────────────────────────────────────
export const TID_LENS_TABS              = "workspace-lens-tabs";
export const TID_LENS_TAB               = (lens) => `workspace-lens-tab-${lens}`;
export const TID_LENS_PANEL             = (lens) => `workspace-lens-panel-${lens}`;
export const TID_LENS_PLACEHOLDER       = (lens) => `workspace-lens-placeholder-${lens}`;

// ── Persistence indicator ────────────────────────────────────────────
export const TID_PERSIST_INDICATOR      = "workspace-persist-indicator";

// ── Global controls ──────────────────────────────────────────────────
export const TID_HOME_BREADCRUMB        = "workspace-home-breadcrumb";
export const TID_REFRESH_BTN            = "workspace-refresh";
export const TID_INVESTIGATION_FINGERPRINT = "workspace-investigation-fingerprint";

// ── Summary lens (Blueprint §9 · PR-4) ───────────────────────────────
export const TID_SUMMARY_LENS             = "workspace-summary-lens";
export const TID_SUMMARY_LOADING          = "workspace-summary-loading";
export const TID_SUMMARY_ERROR            = "workspace-summary-error";
export const TID_SUMMARY_VERDICT          = "workspace-summary-verdict";
export const TID_SUMMARY_RISK             = "workspace-summary-risk";
export const TID_SUMMARY_RISK_SCORE       = "workspace-summary-risk-score";
export const TID_SUMMARY_FAMILY           = "workspace-summary-family";
export const TID_SUMMARY_TECHNIQUE        = "workspace-summary-technique";
export const TID_SUMMARY_CANONICAL        = "workspace-summary-canonical";
export const TID_SUMMARY_TOP_IOCS         = "workspace-summary-top-iocs";
export const TID_SUMMARY_TOP_IOC          = (id) => `workspace-summary-top-ioc-${id}`;
export const TID_SUMMARY_TOP_ACTIONS      = "workspace-summary-top-actions";
export const TID_SUMMARY_ACTION           = (id) => `workspace-summary-action-${id}`;
export const TID_SUMMARY_BULLETS          = "workspace-summary-bullets";
export const TID_SUMMARY_BULLET           = (id) => `workspace-summary-bullet-${id}`;

// ── Story lens (Blueprint §9 · PR-4) ─────────────────────────────────
export const TID_STORY_LENS               = "workspace-story-lens";
export const TID_STORY_LOADING            = "workspace-story-loading";
export const TID_STORY_ERROR              = "workspace-story-error";
export const TID_STORY_NARRATIVE          = "workspace-story-narrative";
export const TID_STORY_CHAPTERS           = "workspace-story-chapters";
export const TID_STORY_CHAPTER            = (name) => `workspace-story-chapter-${name}`;
export const TID_STORY_EVENTS             = "workspace-story-events";
export const TID_STORY_EVENT              = (id) => `workspace-story-event-${id}`;
export const TID_STORY_EVENT_ANCHOR       = (id) => `workspace-story-event-anchor-${id}`;
export const TID_STORY_EMPTY              = "workspace-story-empty";


export const LENSES = ["summary", "story", "timeline", "evidence", "analysis", "exports"];
export const MODES  = ["quick_triage", "investigation", "deep_analysis"];
export const STATES = ["new", "collecting", "correlating", "reviewing", "completed", "reported", "reopened"];

export default {
  TID_SHELL_ROOT,
  TID_SHELL_HEADER,
  TID_SHELL_SIDEBAR,
  TID_SHELL_MAIN,
  TID_SHELL_FOOTER,
  TID_CASE_ID_LABEL,
  TID_CASE_LOAD_ERROR,
  TID_CASE_EMPTY,
  TID_CASE_LOADING,
  TID_CASE_RETRY_BTN,
  TID_STATE_PILL,
  TID_STATE_PILL_VALUE,
  TID_STATE_TRANSITION_BTN,
  TID_MODE_SELECT,
  TID_MODE_OPTION,
  TID_LENS_TABS,
  TID_LENS_TAB,
  TID_LENS_PANEL,
  TID_LENS_PLACEHOLDER,
  TID_PERSIST_INDICATOR,
  TID_HOME_BREADCRUMB,
  TID_REFRESH_BTN,
  TID_INVESTIGATION_FINGERPRINT,
  LENSES,
  MODES,
  STATES,
};
