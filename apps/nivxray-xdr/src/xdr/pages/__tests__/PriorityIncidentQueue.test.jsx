import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi, afterEach } from "vitest";
import PriorityIncidentQueue, { investigationHref, priorityQueueColumns, queueView } from "../PriorityIncidentQueue";
import SelectedIncidentContext from "../SelectedIncidentContext";
import NxDataTable from "../../nx/NxDataTable";

// An element-level interaction harness: exercise the shared table's real handlers
// and state transitions without adding a DOM dependency to this project.
const hooks = vi.hoisted(() => ({ active: false, values: [], index: 0 }));
vi.mock("react", async () => {
  const actual = await vi.importActual("react");
  return { ...actual,
    useState: (initial) => {
      if (!hooks.active) return actual.useState(initial);
      const i = hooks.index++;
      if (!(i in hooks.values)) hooks.values[i] = typeof initial === "function" ? initial() : initial;
      return [hooks.values[i], (next) => { hooks.values[i] = typeof next === "function" ? next(hooks.values[i]) : next; }];
    },
    useCallback: (fn, deps) => hooks.active ? fn : actual.useCallback(fn, deps),
    useMemo: (fn, deps) => hooks.active ? fn() : actual.useMemo(fn, deps),
    useEffect: (fn, deps) => { if (!hooks.active) actual.useEffect(fn, deps); },
  };
});
afterEach(() => { hooks.active = false; hooks.values = []; hooks.index = 0; });
const now = Date.now();
const row = { id: "INC-42", name: "Test incident", priority: "P1", state: "in_progress", detection_source: "sensor", assignee: "analyst", customer: "tenant-a", updated_at: new Date(now).toISOString() };
const response = (rows = [row], extra = {}) => ({ rows, generated_at: new Date(now).toISOString(), source: "workspace_cases.high_priority_lens", ...extra });
const html = (props) => renderToStaticMarkup(<PriorityIncidentQueue onNavigate={() => {}} {...props} />);
function elements(node, predicate) {
  if (!React.isValidElement(node)) return [];
  return [...(predicate(node) ? [node] : []), ...React.Children.toArray(node.props.children).flatMap((child) => elements(child, predicate))];
}
function run(Component, props) { hooks.active = true; hooks.index = 0; return Component(props); }

describe("Priority queue rendering and data states", () => {
  it("keeps snapshot limitations in a collapsed keyboard-accessible disclosure", () => {
    const output = html({ data: response() });
    expect(output).toContain('<details class="cc-pq__about"><summary>About this data');
    expect(output).toContain('analyst assignment and affected entity are not independently provided');
    expect(output).toContain('Search and sort apply to this snapshot only');
  });
  it("renders supported evidence fields, explicit missing entity, labeled search and investigation action", () => {
    const output = html({ data: response() });
    for (const text of ["Priority incident queue", "INC-42", "Test incident", "sensor", "tenant-a", "Reported owner", "Not available", "Open investigation", 'id="cc-pq-search"', 'for="cc-pq-search"']) expect(output).toContain(text);
    expect(output).toContain("submitting user");
    expect(output).not.toContain("Last observed");
  });
  it.each([
    [{ data: response(), loading: true }, "Loading priority incidents"],
    [{ data: { status: 401, error: "Unauthorized" } }, "Access denied"],
    [{ data: { status: 403, error: "Forbidden" } }, "Access denied"],
    [{ data: { status: 500, error: "failed" } }, "could not load"],
    [{ data: { error: "Network error" } }, "could not load"],
    [{ data: null }, "not available"],
    [{ data: response([], { source: "empty" }) }, "No authorized incident scope"],
  ])("hides records for loading, denied, error and unavailable states", (props, message) => {
    const output = html(props);
    expect(output).toContain(message);
    expect(output).not.toContain('data-testid="cc-priority-table"');
    expect(output).not.toContain("INC-42");
  });
  it("distinguishes a successful empty result from a scope failure", () => {
    expect(html({ data: response([]) })).toContain("No open P1/P2 incidents returned");
    expect(html({ data: response([]) })).not.toContain("No authorized incident scope");
  });
  it("keeps stale records visible with a warning and handles missing freshness", () => {
    const old = response([row], { generated_at: new Date(now - 360000).toISOString() });
    expect(queueView(old, false, now)).toBe("stale");
    expect(html({ data: old })).toContain("Stale snapshot");
    expect(html({ data: old })).toContain("INC-42");
    expect(html({ data: response([row], { generated_at: null }) })).toContain("freshness is not available");
    expect(queueView(response(), false, now)).toBe("ready");
  });
  it("does not silently infer absent fields", () => {
    const output = html({ data: response([{ id: null, name: null, detection_source: "unknown" }]) });
    expect(output).toContain('disabled=""');
    expect(output).not.toContain("Unassigned");
    expect(output).not.toContain("Invalid Date");
  });
});

describe("Priority queue interactions", () => {
  it("uses the authorized incident route and guards absent IDs", () => {
    expect(investigationHref({ id: "a/b" })).toBe("/xdr/incidents/a%2Fb");
    expect(investigationHref({})).toBeNull();
    const navigate = vi.fn();
    const tree = run(PriorityIncidentQueue, { data: response(), onNavigate: navigate });
    const table = elements(tree, (node) => node.type === NxDataTable)[0];
    table.props.onRowClick(row);
    expect(navigate).toHaveBeenCalledWith("/xdr/incidents/INC-42");
    navigate.mockClear();
    table.props.onRowClick({});
    expect(navigate).not.toHaveBeenCalled();
    const stopPropagation = vi.fn();
    elements(table.props.rowActions(row), (node) => node.type === "button" && node.props.children === "Open investigation")[0].props.onClick({ stopPropagation });
    expect(stopPropagation).toHaveBeenCalledOnce();
    expect(navigate).toHaveBeenCalledOnce();
  });
  it("previews without navigating or replacing the table, then closes back to the queue", () => {
    const navigate = vi.fn();
    const props = { data: response(), onNavigate: navigate };
    let tree = run(PriorityIncidentQueue, props);
    const table = elements(tree, (node) => node.type === NxDataTable)[0];
    const preview = elements(table.props.rowActions(row), (node) => node.type === "button" && node.props.children === "Preview")[0];
    const stopPropagation = vi.fn();
    preview.props.onClick({ stopPropagation });
    expect(stopPropagation).toHaveBeenCalledOnce(); expect(navigate).not.toHaveBeenCalled();
    tree = run(PriorityIncidentQueue, props);
    expect(elements(tree, (node) => node.type === NxDataTable)).toHaveLength(1);
    const context = elements(tree, (node) => node.type === SelectedIncidentContext)[0];
    expect(context.props.id).toBe(row.id);
    context.props.onClose();
    tree = run(PriorityIncidentQueue, props);
    expect(elements(tree, (node) => node.type === SelectedIncidentContext)).toHaveLength(0);
    expect(elements(tree, (node) => node.type === NxDataTable)).toHaveLength(1);
  });
  it("searches, sorts, paginates all returned records, and supports Enter navigation", () => {
    const navigate = vi.fn();
    const props = { rows: Array.from({ length: 14 }, (_, i) => ({ ...row, id: `INC-${i}`, priority: i % 2 ? "P1" : "P2" })), columns: priorityQueueColumns, pageSize: 7, onRowClick: navigate, testid: "queue" };
    let tree = run(NxDataTable, props);
    const byId = (id) => elements(tree, (node) => node.props["data-testid"] === id)[0];
    byId("queue-next").props.onClick();
    tree = run(NxDataTable, props);
    expect(byId("queue-row-INC-13")).toBeTruthy();
    byId("queue-search").props.onChange({ target: { value: "INC-3" } });
    tree = run(NxDataTable, props);
    expect(byId("queue-row-INC-3")).toBeTruthy();
    expect(byId("queue-row-INC-13")).toBeUndefined();
    byId("queue-row-INC-3").props.onKeyDown({ key: "Enter" });
    expect(navigate).toHaveBeenCalledWith(props.rows[3]);
    byId("queue-search").props.onChange({ target: { value: "" } });
    byId("queue-sort-priority").props.onClick();
    tree = run(NxDataTable, props);
    const renderedRows = elements(tree, (node) => node.type === "tr" && node.props["data-testid"]);
    expect(renderedRows).toHaveLength(7);
    expect(renderedRows[0].props["data-testid"]).toBe("queue-row-INC-1");
  });
});
