import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import SecurityOverviewKpis from "../SecurityOverviewKpis";

const ids = ["critical", "high_priority", "unassigned", "aging", "in_progress_mine", "high_fidelity"];
const data = (override = {}) => ({ groups: [{ tiles: ids.map((id, count) => ({
  id, count, count_source: "live", lens_href: `/xdr/incidents?lens=${id}`,
  description: `API description for ${id}`, ...override,
})) }] });
const render = (props) => renderToStaticMarkup(<SecurityOverviewKpis {...props} />);

describe("Security overview KPI rendering", () => {
  it("keeps compact-card definitions accessible in a native disclosure", () => {
    const html = render({ data: data() });
    expect(html).toContain('<details class="cc-kpi-definitions">');
    expect(html).toContain('<summary>Metric definitions</summary>');
    expect(html.match(/<dt>/g)).toHaveLength(6);
    expect(html).toContain('class="cc-attn__description cc-visually-hidden"');
    expect(html).toContain('aria-describedby="cc-kpi-critical-description"');
  });
  it("renders exactly six named cards, actual counts including zero, and API descriptions", () => {
    const html = render({ data: data() });
    expect(html.match(/<button /g)).toHaveLength(6);
    for (const [index, id] of ids.entries()) {
      expect(html).toContain(`data-testid="cc-attn-${id}-value">${index}</span>`);
      expect(html).toContain(`aria-describedby="cc-kpi-${id}-description"`);
      expect(html).toContain(`API description for ${id}`);
    }
    expect(html).toContain('aria-label="Critical: 0. Open queue"');
    expect(html).not.toContain('disabled=""');
  });
  it.each([
    [{ loading: true, data: data() }, "Loading"],
    [{ data: { status: 401, error: "Unauthorized" } }, "Access denied"],
    [{ data: { status: 403, error: "Forbidden" } }, "Access denied"],
    [{ data: { status: 500, error: "Server error" } }, "Error loading"],
    [{ data: { error: "Network error" } }, "Error loading"],
    [{ data: null }, "Not available"],
    [{ data: data({ count_source: "unavailable" }) }, "Not available"],
    [{ data: data({ count_source: "empty", count: 0 }) }, "No scope"],
  ])("renders unavailable states without false zeros or active links: %s", (props, state) => {
    const html = render(props);
    expect(html.match(/disabled=""/g)).toHaveLength(6);
    expect(html.match(/-value">—<\/span>/g)).toHaveLength(6);
    expect(html).toContain(`aria-label="Critical: ${state}."`);
    expect(html).not.toContain("Open queue");
  });
  it.each([undefined, null, "0", -1, NaN, Infinity])("does not coerce invalid count %s to zero", (count) => {
    expect(render({ data: data({ count }) })).toContain('aria-label="Critical: Not available."');
  });
  it("handles malformed and partial responses independently", () => {
    expect(render({ data: { groups: {} } })).toContain("Not available");
    const partial = { groups: [{ tiles: [data().groups[0].tiles[0]] }] };
    const html = render({ data: partial });
    expect(html).toContain('aria-label="Critical: 0. Open queue"');
    expect(html).toContain('aria-label="High: Not available."');
  });
  it("retains a measured count when its queue is unavailable", () => {
    expect(render({ data: data({ lens_href: null }) })).toContain('aria-label="Critical: 0. Queue not available"');
  });
  it("passes every API-provided queue href unchanged; loading and denied states cannot navigate", () => {
    const onNavigate = vi.fn();
    const buttons = (props) => SecurityOverviewKpis(props).props.children[1].props.children;
    buttons({ data: data(), onNavigate }).forEach((button) => button.props.onClick());
    ids.forEach((id, index) => expect(onNavigate).toHaveBeenNthCalledWith(index + 1, `/xdr/incidents?lens=${id}`));
    onNavigate.mockClear();
    for (const props of [{ data: data(), loading: true }, { data: { status: 403 } }, { data: data({ count_source: "empty" }) }]) {
      buttons({ ...props, onNavigate }).forEach((button) => button.props.onClick());
    }
    expect(onNavigate).not.toHaveBeenCalled();
  });
});
