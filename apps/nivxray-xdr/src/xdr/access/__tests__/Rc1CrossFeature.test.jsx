import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { StaticRouter } from "react-router-dom/server";
import { it, expect, vi, beforeEach } from "vitest";
import { Protected } from "@/App";
import { effectivePermission } from "../AccessProvider";
import { startInvestigationLoad } from "@/xdr/pages/investigationLoader";
import { invalidateSecurity } from "@/lib/securityState";
import { applyCustomerSelection } from "@/lib/customerSelection";
import { bindServerTenant, activeTenant } from "@/lib/tenant";
const authz=vi.hoisted(()=>({state:null,tenant:"A"}));
vi.mock("../AccessProvider", async original=>({...await original(),useAccess:()=>({loading:false,canAny:list=>{
 const results=list.map(p=>effectivePermission(authz.state,p,authz.tenant));
 return results.some(v=>v===true)?true:results.some(v=>v===null)?null:false;
},refresh:vi.fn()})}));
vi.mock("@/lib/auth",()=>({useAuth:()=>({user:{email:"synthetic"},loading:false})}));
vi.mock("@/lib/api",()=>({default:{get:vi.fn()}}));
vi.mock("@/xdr/XdrShell",()=>({default:({children})=>children}));
const projection=(tenant,permissions)=>({available:true,data:{tenant,permissions,cross_tenant:false}});
const render=()=>renderToStaticMarkup(<StaticRouter location="/xdr/investigations/A-1/_engine"><Protected><div>authorized sensitive engine</div></Protected></StaticRouter>);
beforeEach(()=>{invalidateSecurity("scope");authz.tenant="A";authz.state=projection("A",["console.soc.access","investigations.read"]);});
it("selected-customer projection gates the actual direct engine route",()=>{
 expect(render()).toContain("authorized sensitive engine");authz.tenant="B";
 expect(render()).not.toContain("authorized sensitive engine");expect(render()).toContain("route-unavailable");
 authz.state=projection("B",["console.soc.access"]);expect(render()).toContain("route-denied");
 authz.state=projection("B",["console.soc.access","investigations.read"]);expect(render()).toContain("authorized sensitive engine");
 authz.tenant="C";expect(render()).not.toContain("authorized sensitive engine");
});
it.each([401,403])("direct-route grant cannot turn engine %s into an alternate source",async status=>{
 expect(render()).toContain("authorized sensitive engine");const api={get:vi.fn().mockRejectedValue({response:{status}})};
 const primary=vi.fn(),secondary=vi.fn();const load=startInvestigationLoad({api,caseId:"A-1",tenantId:"A",profile:"soc_balanced",onPrimary:primary,onSecondary:secondary,onInvalidate:vi.fn()});
 await load.done;expect(api.get).toHaveBeenCalledOnce();expect(primary).toHaveBeenCalledWith("denied",null);expect(secondary).not.toHaveBeenCalled();load.cancel();
});
it("customer epoch invalidates an in-flight allowed investigation and its direct route",async()=>{
 let resolve;const api={get:vi.fn().mockReturnValue(new Promise(r=>resolve=r))};const primary=vi.fn(),cleared=vi.fn();
 const load=startInvestigationLoad({api,caseId:"A-1",tenantId:"A",profile:"soc_balanced",onPrimary:primary,onSecondary:vi.fn(),onInvalidate:cleared});
 authz.tenant="B";invalidateSecurity("scope");expect(render()).not.toContain("authorized sensitive engine");
 resolve({data:{case_id:"A-1",tenant_id:"A"}});await load.done;expect(primary).not.toHaveBeenCalled();expect(cleared).toHaveBeenCalledOnce();load.cancel();
});
it("server-bound customer cannot be relabelled by another selection",()=>{
 const prior=globalThis.window;const storage=new Map();
 globalThis.window={localStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},dispatchEvent:()=>{}};
 try {bindServerTenant("A",{switchable:false});expect(()=>applyCustomerSelection({authorized:true,tenant_ids:["B"]},"B")).toThrow("locked");expect(activeTenant()).toBe("A");}
 finally {bindServerTenant(null,{switchable:true});globalThis.window=prior;}
});
