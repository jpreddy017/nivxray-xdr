import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import ObservableEntry, { OBSERVABLE_TYPES, observableError, evidenceSearchHref } from "../ObservableEntry";
import { startScopedRead } from "../scopedRead";
import { invalidateSecurity } from "@/lib/securityState";
import { readInvestigationCases } from "../XdrInvestigationsListPage";
import { readEvidenceSearch } from "../XdrHuntingPage";
import api from "@/lib/api";
const permission = vi.hoisted(() => ({ value: true }));
vi.mock("@/lib/api", () => ({ default: { get: vi.fn() } }));
vi.mock("@/xdr/access/AccessProvider", () => ({ useAccess: () => ({ can: () => permission.value }) }));
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return { promise, resolve, reject }; };
beforeEach(() => { vi.clearAllMocks(); permission.value = true; invalidateSecurity("scope"); });

it.each(OBSERVABLE_TYPES)("%s entry accepts a supported identifier", (type) => {
  expect(observableError(type, type === "sha256" ? "a".repeat(64) : "record-1")).toBeNull();
});
it.each(["", "   "])("empty input %j cannot become a search", term => {
  expect(observableError("hostname", term)).toContain("Enter an observable");
});
it.each(["url", "domain", "email", "identity", "vulnerability"])("unsupported %s is explicit", type => {
  expect(observableError(type, "value")).toContain("no supported search index");
});
it.each(["https://example.test/path", "name@example.test"])("unsupported value %s is explicit", term => {
  expect(observableError("hostname", term)).toContain("unavailable");
});
it("invalid SHA-256 is not silently searched", () => {
  expect(observableError("sha256", "abcd")).toContain("64 hexadecimal");
});
it("search deep link preserves reserved characters and cannot inject URL parameters", () => {
  const term = " proc_1 & tenant=foreign/#? ";
  const url = new URL(evidenceSearchHref(term), "https://example.test");
  expect(url.pathname).toBe("/xdr/hunting");
  expect([...url.searchParams]).toEqual([["q", term.trim()]]);
  expect(url.hash).toBe("");
});
it.each([true, false, null])("entry renders native labeled form controls with permission %s", allowed => {
  permission.value = allowed;
  const html = renderToStaticMarkup(<MemoryRouter><ObservableEntry /></MemoryRouter>);
  expect(html).toContain("<form"); expect(html).toContain('type="submit"');
  expect(html).toContain("Identifier type"); expect(html).toContain("Observable");
  expect(html).toContain('role="status"'); expect(html).toContain("Domain, URL, email");
  if (allowed === false) expect(html).toContain("requires Hunting access");
  if (allowed === null) expect(html).toContain("authorization is unavailable");
});
it.each(["scope", "session", "expired", "denied"])("%s fences delayed responses even if transport ignores abort", async reason => {
  const pending = deferred(), publish = vi.fn(); let signal;
  const task = startScopedRead(s => { signal=s; return pending.promise; }, publish);
  invalidateSecurity(reason); pending.resolve({ sensitive: "old" }); await task.done;
  expect(signal.aborted).toBe(true); expect(publish).not.toHaveBeenCalled(); task.cancel();
});
it("rapid search change publishes only the current response", async () => {
  const pending = deferred(), old = vi.fn(), current = vi.fn();
  const first = startScopedRead(() => pending.promise, old); first.cancel();
  const next = startScopedRead(async () => ({ query: "new" }), current); await next.done;
  pending.resolve({ query: "old" }); await first.done;
  expect(old).not.toHaveBeenCalled(); expect(current).toHaveBeenCalledWith({ data: { query: "new" }, error: null, loading: false }); next.cancel();
});
it("search errors publish no previous records", async () => {
  const error = { response: { status: 403 } }, publish = vi.fn();
  const request = startScopedRead(async () => { throw error; }, publish); await request.done;
  expect(publish).toHaveBeenCalledWith({ data: null, error, loading: false }); request.cancel();
});
it.each([401, 403, 500, 404])("search HTTP %s never requests enrichment or fallback", async status => {
  const error = { response: { status } }; api.get.mockRejectedValueOnce(error);
  await expect(readEvidenceSearch("host", new AbortController().signal)).rejects.toBe(error);
  expect(api.get).toHaveBeenCalledOnce(); expect(api.get.mock.calls[0][0]).toBe("/xdr/search");
});
it.each(["NO_MATCH", "NOT_AUTHORIZED", "NO_QUERY"])("search %s cannot carry actionable stale records", async state => {
  api.get.mockResolvedValueOnce({ data: { state, groups: [{ results: [{ id: "old" }] }] } });
  expect((await readEvidenceSearch("host")).groups).toEqual([]);
});
it.each([null, {}, { state: "RESULTS", groups: [{}] }])("malformed search response is unavailable", async data => {
  api.get.mockResolvedValueOnce({ data }); await expect(readEvidenceSearch("host")).rejects.toThrow("unsupported");
});
it("search forwards the exact trimmed identifier and abort signal", async () => {
  const signal = new AbortController().signal;
  const data = { state: "RESULTS", groups: [{ results: [{ id: "record", href: "/xdr/incidents/record" }] }] };
  api.get.mockResolvedValueOnce({ data }); expect(await readEvidenceSearch(" host ", signal)).toBe(data);
  expect(api.get).toHaveBeenCalledWith("/xdr/search", { params: { q: "host" }, signal });
});
it.each([{ response: { status: 500 } }, { response: { status: 404 } }, { code: "ERR_CANCELED" }, new Error("network")])("case list unknown failures cannot start incident fallback", async error => {
  api.get.mockRejectedValueOnce(error); await expect(readInvestigationCases()).rejects.toBe(error); expect(api.get).toHaveBeenCalledOnce();
});
it("empty case list retains the existing incident projection and real zero", async () => {
  api.get.mockResolvedValueOnce({ data: { cases: [] } }).mockResolvedValueOnce({ data: { incidents: [{ id: "test", incident_score: 0 }] } });
  const rows = await readInvestigationCases(); expect(rows[0].incident_score).toBe(0); expect(rows[0].verdict_band).toBeNull();
});
it("malformed case response cannot appear as an empty investigation", async () => {
  api.get.mockResolvedValueOnce({ data: {} }); await expect(readInvestigationCases()).rejects.toThrow("Invalid case list"); expect(api.get).toHaveBeenCalledOnce();
});
