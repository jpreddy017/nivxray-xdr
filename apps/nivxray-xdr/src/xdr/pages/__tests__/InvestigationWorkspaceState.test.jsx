import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { readEngineInvestigation, startInvestigationLoad, incidentInvestigation, investigationFailure } from "../investigationLoader";
import { InvestigationVerdictSummary } from "../XdrInvestigationWorkspacePage";
import { invalidateSecurity } from "@/lib/securityState";
vi.mock("@/lib/api", () => ({ default: { get: vi.fn() } }));
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return { promise, resolve, reject }; };
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
const setup = (api, extra = {}) => {
  const onPrimary = vi.fn(), onSecondary = vi.fn(), onInvalidate = vi.fn();
  return { onPrimary, onSecondary, onInvalidate, ...startInvestigationLoad({ api, caseId:"A-1", tenantId:"A", profile:"soc_balanced", onPrimary, onSecondary, onInvalidate, ...extra }) };
};
beforeEach(() => invalidateSecurity("scope"));
it.each([401,403,400,404,405,500,501,503])("status %s does not authorize an alternate incident or secondary request", async status => {
  const api = { get: vi.fn().mockRejectedValue({ response:{ status, data:{ detail:"case_not_found" } } }) };
  const load = setup(api); await load.done;
  expect(api.get).toHaveBeenCalledTimes(1); expect(load.onSecondary).not.toHaveBeenCalled();
  expect(load.onPrimary).toHaveBeenLastCalledWith([401,403].includes(status)?"denied":[404,405,501].includes(status)?"unavailable":"error", null); load.cancel();
});
it.each([{code:"ERR_CANCELED"}, {name:"AbortError"}, new Error("transport failure")])("cancellation/unknown failure never falls back", async error => {
  const api = { get:vi.fn().mockRejectedValue(error) }; const load=setup(api); await load.done;
  expect(api.get).toHaveBeenCalledOnce(); expect(load.onSecondary).not.toHaveBeenCalled(); load.cancel();
});
it("documented absent-route fallback preserves the incident identity and zero values", async () => {
  const api = { get:vi.fn().mockRejectedValueOnce({response:{status:404,data:{detail:"Not Found"}}}).mockResolvedValueOnce({data:{id:"A-1",incident_score:0,confidence:0}}) };
  const data = await readEngineInvestigation(api,"A-1","soc_balanced",new AbortController().signal);
  expect(data.header.incident_score).toBe(0); expect(data.header.verdict_band).toBeNull(); expect(api.get.mock.calls[1][0]).toBe("/incidents/A-1");
});
it("fallback denial stops all secondary requests", async () => {
  const api={get:vi.fn().mockRejectedValueOnce({response:{status:404,data:{detail:"Not Found"}}}).mockRejectedValueOnce({response:{status:403}})};
  const load=setup(api); await load.done; expect(api.get).toHaveBeenCalledTimes(2); expect(load.onSecondary).not.toHaveBeenCalled(); expect(load.onPrimary).toHaveBeenLastCalledWith("denied",null); load.cancel();
});
it.each([{id:"B-1"}, {}])("foreign/missing fallback identity fails closed", async data => {
  const api={get:vi.fn().mockRejectedValueOnce({response:{status:404,data:{detail:"Not Found"}}}).mockResolvedValueOnce({data})};
  const load=setup(api); await load.done; expect(load.onPrimary).toHaveBeenLastCalledWith("error",null); expect(load.onSecondary).not.toHaveBeenCalled(); load.cancel();
});
it.each([{case_id:"B-1"},{case_id:"A-1",tenant_id:"B"},null])("invalid primary context cannot start secondary evidence", async data => {
  const api={get:vi.fn().mockResolvedValue({data})}; const load=setup(api); await load.done;
  expect(load.onPrimary).toHaveBeenLastCalledWith("error",null); expect(api.get).toHaveBeenCalledOnce(); load.cancel();
});
it("empty primary results stay empty without evidence requests",async()=>{
  const api={get:vi.fn().mockResolvedValue({data:{}})}; const load=setup(api); await load.done;
  expect(load.onPrimary).toHaveBeenLastCalledWith("empty",null); expect(api.get).toHaveBeenCalledOnce(); load.cancel();
});
it("secondary loading, empty, denied, error and unavailable are distinct", async () => {
  const api={get:vi.fn().mockResolvedValueOnce({data:{case_id:"A-1",header:{}}}).mockResolvedValueOnce({data:{frames:[]}}).mockRejectedValueOnce({response:{status:403}}).mockRejectedValueOnce(new Error("failed")).mockResolvedValueOnce({data:{states:[]}})};
  const load=setup(api); await load.done;
  expect(load.onSecondary.mock.calls.filter(x=>x[1]==="loading")).toHaveLength(4);
  expect(load.onSecondary).toHaveBeenCalledWith("trajectory","empty",{frames:[]});
  expect(load.onSecondary).toHaveBeenCalledWith("process","denied",null);
  expect(load.onSecondary).toHaveBeenCalledWith("artifacts","error",null);
  expect(load.onSecondary).toHaveBeenCalledWith("security","empty",{states:[]}); load.cancel();
});
it("unsupported secondary schema is unavailable rather than empty", async () => {
  const api={get:vi.fn().mockResolvedValueOnce({data:{case_id:"A-1"}}).mockResolvedValue({data:{}})};
  const load=setup(api); await load.done; expect(load.onSecondary).toHaveBeenCalledWith("artifacts","unavailable",null); load.cancel();
});
it.each(["scope","session","denied"])("%s invalidation fences a delayed primary even when transport ignores cancellation",async reason=>{
  const pending=deferred(); const api={get:vi.fn().mockReturnValue(pending.promise)}; const load=setup(api);
  invalidateSecurity(reason); pending.resolve({data:{case_id:"A-1",tenant_id:"A"}}); await load.done;
  expect(load.onInvalidate).toHaveBeenCalledOnce(); expect(load.onPrimary).not.toHaveBeenCalled(); expect(api.get).toHaveBeenCalledOnce(); expect(api.get.mock.calls[0][1].signal.aborted).toBe(true); load.cancel();
});
it("rapid case/customer switching cannot commit the old response",async()=>{
  const a=deferred(); const apiA={get:vi.fn().mockReturnValue(a.promise)}; const old=setup(apiA); old.cancel();
  const apiB={get:vi.fn().mockResolvedValueOnce({data:{case_id:"B-2",tenant_id:"B"}}).mockResolvedValue({data:{}})};
  const next=setup(apiB,{caseId:"B-2",tenantId:"B"}); await next.done; a.resolve({data:{case_id:"A-1"}}); await old.done;
  expect(old.onPrimary).not.toHaveBeenCalled(); expect(next.onPrimary).toHaveBeenCalledWith("ready",{case_id:"B-2",tenant_id:"B"}); next.cancel();
});
it("logout invalidates already loaded evidence and pending secondary replies",async()=>{
  const pending=deferred(); const api={get:vi.fn().mockResolvedValueOnce({data:{case_id:"A-1"}}).mockReturnValue(pending.promise)};
  const load=setup(api); await tick(); const count=load.onSecondary.mock.calls.length;
  invalidateSecurity("session"); pending.resolve({data:{frames:[{id:"old"}],nodes:[],artifacts:[]}}); await load.done;
  expect(load.onInvalidate).toHaveBeenCalledOnce(); expect(load.onSecondary.mock.calls).toHaveLength(count); load.cancel();
});
it("secondary context mismatches do not enter rendered state",async()=>{
  const api={get:vi.fn().mockResolvedValueOnce({data:{case_id:"A-1"}}).mockResolvedValue({data:{case_id:"B-1",frames:[{}]}})};
  const load=setup(api); await load.done; expect(load.onSecondary).toHaveBeenCalledWith("trajectory","error",null); load.cancel();
});
it("missing customer context makes no request",async()=>{const api={get:vi.fn()};const load=setup(api,{tenantId:null});await load.done;expect(api.get).not.toHaveBeenCalled();expect(load.onPrimary).toHaveBeenCalledWith("unavailable",null);load.cancel();});
it("missing verdict and scores render unavailable, never benign or zero",()=>{
  const h=incidentInvestigation({id:"A-1"},"A-1").header;
  const html=renderToStaticMarkup(<InvestigationVerdictSummary header={h}/>);
  expect(html).toContain("UNAVAILABLE"); expect(html).toContain("Unavailable"); expect(html).not.toContain("BENIGN"); expect(html).not.toContain("0 / 100"); expect(html).not.toContain("0%");
});
it("legitimate zeros render as zero including zero risk with a nonzero device score",()=>{
  const html=renderToStaticMarkup(<InvestigationVerdictSummary header={{incident_score:0,device_score:99,confidence:0,verdict_band:"benign"}}/>);
  expect(html).toContain("0 / 100"); expect(html).toContain("0%"); expect(html).toContain("BENIGN");
});
it("profile values are encoded without modifying the canonical case destination",async()=>{
 const api={get:vi.fn().mockResolvedValue({data:{case_id:"A/1"}})};
 await readEngineInvestigation(api,"A/1","soc_balanced&x=1",new AbortController().signal);
 expect(api.get.mock.calls[0][0]).toBe("/v2/cases/A%2F1/investigation?limit=500&profile=soc_balanced%26x%3D1");
});
