import { describe, expect, it } from "vitest";
import { projectionState } from "../controlCenterState";

describe("Control Center response truth", () => {
  it("does not claim empty data while loading", () => {
    expect(projectionState(null)).toBe("loading");
  });
  it.each([401, 403])("keeps HTTP %s distinct from a successful zero", (status) => {
    expect(projectionState({ status, error: "Denied", rows: [] })).toBe("denied");
  });
  it.each([{ error: "Network error" }, { source: "unavailable", rows: [] }, {}, { rows: null }])(
    "does not convert an API failure or missing rows into empty data: %j", (body) => {
      expect(projectionState(body)).toBe("unavailable");
    });
  it("keeps an explicit empty scope separate from a query with no matches", () => {
    expect(projectionState({ source: "empty", rows: [], count: 0 })).toBe("no_scope");
    expect(projectionState({ source: "workspace_cases.live", rows: [], count: 0 })).toBe("empty");
  });
  it("accepts a successful incident-bearing tenant projection without claiming authorization", () => {
    expect(projectionState({ source: "workspace_cases.aggregate.tenant_id", rows: [] })).toBe("empty");
    expect(projectionState({ rows: [{ customer: "fixture-only" }] })).toBe("ready");
  });
});
