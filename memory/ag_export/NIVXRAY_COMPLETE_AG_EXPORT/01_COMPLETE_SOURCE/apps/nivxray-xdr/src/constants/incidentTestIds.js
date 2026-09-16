/**
 * Test IDs for the canonical Incident shell (Slice 1).
 *
 * Kept in a dedicated module so tests + UI never drift.  Every
 * interactive control and every element that surfaces an
 * incident-level fact carries one of these ids.
 */
export const INCIDENT_TESTIDS = {
  // List page
  listPage:            "incidents-list-page",
  listTable:           "incidents-list-table",
  listRow:             (id) => `incidents-list-row-${id}`,
  listEmptyState:      "incidents-list-empty",
  listLoading:         "incidents-list-loading",
  listError:           "incidents-list-error",
  listRefresh:         "incidents-list-refresh",

  // Shell
  shellPage:           "incident-shell-page",
  shellLoading:        "incident-shell-loading",
  shellError:          "incident-shell-error",
  header:              "incident-header",
  headerNumber:        "incident-header-number",
  headerName:          "incident-header-name",
  headerPriority:      "incident-header-priority",
  headerSeverity:      "incident-header-severity",
  headerVerdict:       "incident-header-verdict",
  headerAssignee:      "incident-header-assignee",

  // Lifecycle
  lifecycleBar:        "incident-lifecycle-bar",
  lifecycleStep:       (state) => `incident-lifecycle-step-${state}`,
  lifecycleTransition: (state) => `incident-lifecycle-transition-${state}`,

  // Top-level tabs
  topTabs:             "incident-top-tabs",
  topTab:              (key) => `incident-top-tab-${key}`,

  // Overview
  overviewPane:        "incident-tab-overview",
  domainCards:         "incident-overview-domain-cards",
  domainCard:          (dom) => `incident-overview-domain-card-${dom}`,
  domainLaunch:        (dom) => `incident-overview-domain-launch-${dom}`,

  // Investigation sub-tabs
  investigationPane:   "incident-tab-investigation",
  investigationSubtabs: "incident-investigation-subtabs",
  investigationSubtab: (key) => `incident-investigation-subtab-${key}`,
  investigationSubtabBody: (key) => `incident-investigation-subtab-body-${key}`,
  investigationLaunch: (key) => `incident-investigation-launch-${key}`,

  // Activity
  activityPane:        "incident-tab-activity",
  activityInventoryStatus: "incident-activity-inventory-status",

  // Response
  responsePane:        "incident-tab-response",
};
