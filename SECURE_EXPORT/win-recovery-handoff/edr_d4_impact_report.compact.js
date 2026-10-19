// READ ONLY. No delete/update/insert/drop verb appears in this file.
const DB_NAME="greeting-app-5782-test_database";
const TENANT="ten_e759b7288598bd882e3dcac49d";
const RAW="edr_raw_events";
const t=db.getSiblingDB(DB_NAME);
const has=c=>t.getCollectionNames().includes(c);
const n=x=>String(x).padStart(10);
const p=s=>String(s).padEnd(40);
print("=== D4 IMPACT REPORT (READ ONLY) "+new Date().toISOString());
print("db "+DB_NAME+"  tenant "+TENANT);
const eps=has("edr_endpoints")?t.edr_endpoints.find({tenant_id:TENANT},{endpoint_id:1,hostname:1,event_count:1,enrollment_state:1}).toArray():[];
print("\n-- 1 EDR endpoints: "+eps.length);
for(const e of eps){const r=has(RAW)?t[RAW].countDocuments({tenant_id:TENANT,endpoint_ref:e.endpoint_id}):0;
print("   "+p(e.endpoint_id)+String(e.enrollment_state||"?").padEnd(10)+" raw "+n(r)+"  counter "+(e.event_count??"-")+"  "+(e.hostname||""));}
const EP=eps.map(e=>e.endpoint_id).filter(Boolean);
const TEL=["edr_raw_events","edr_processing_queue","edr_rejected_telemetry","edr_acquisition_gaps","edr_acquisition_integrity","edr_delivery_counters","edr_findings","edr_finding_evaluations","edr_compromise_events","edr_endpoint_address_observations","edr_response_commands","edr_policy_endpoint_state","edr_endpoint_exclusion_enforcement"];
const IDN=["edr_endpoints","edr_agent_credentials","edr_agent_sessions","edr_enrollment_tokens"];
const KEEP=["edr_policies","edr_groups","edr_policy_versions","edr_exclusions","edr_exclusion_sets","edr_isolation_policy","edr_tenant_boundary","edr_connector_deployments","edr_saved_views","edr_enrollment_audit","edr_policy_audit"];
function g(title,names){print("\n-- "+title);let s=0;for(const c of names){if(!has(c)){print("   "+p(c)+"(absent)");continue;}
const sc=t[c].countDocuments({tenant_id:TENANT}),al=t[c].countDocuments({});s+=sc;print("   "+p(c)+"tenant "+n(sc)+"  collection "+al);}print("   "+p("SUBTOTAL")+n(s));return s;}
let edrTotal=0;
edrTotal+=g("2a EDR telemetry/derived (delete candidates)",TEL);
edrTotal+=g("2b EDR identity (recreated by enrolment)",IDN);
g("2c RETAINED by D2/D3 config+audit",KEEP);
print("\n   EDR delete-candidate total: "+edrTotal);
print("\n-- 3 D4 blast radius");
let edrEv=0,edrObs=0;
if(has("xdr_canonical_evidence")&&EP.length){const c=t.xdr_canonical_evidence;
edrEv=c.countDocuments({tenant_id:TENANT,$or:[{"provenance.collector_id":{$in:EP}},{"additional_fields.endpoint_id":{$in:EP}},{"host.host_id":{$in:EP}}]});
print("   "+p("xdr_canonical_evidence EDR-derived")+n(edrEv));
print("   "+p("  of which sensor+AUTHENTICATED")+n(c.countDocuments({tenant_id:TENANT,"provenance.source_kind":"sensor"})));
print("   "+p("xdr_canonical_evidence tenant total")+n(c.countDocuments({tenant_id:TENANT})));
print("   "+p("xdr_canonical_evidence all tenants")+n(c.countDocuments({})));}
if(has("v2_shadow_observations")&&EP.length){const o=t.v2_shadow_observations;
edrObs=o.countDocuments({tenant_id:TENANT,$or:[{collector_id:{$in:EP}},{connector_id:{$in:EP}},{"event.raw.raw_evidence_ref.collection":RAW}]});
print("   "+p("v2_shadow_observations EDR-derived")+n(edrObs));
print("   "+p("v2_shadow_observations tenant total")+n(o.countDocuments({tenant_id:TENANT})));
print("   "+p("v2_shadow_observations all tenants")+n(o.countDocuments({})));}
const only=[],mixed=[];let other=0;
if(has("workspace_cases")){const incs=t.workspace_cases.find({tenant_id:TENANT,doc_type:"xdr_incident"},{id:1,incident_number:1,title:1,incident_state:1,"xdr_pipeline.canonical_event_id":1,"xdr_pipeline.source_provenance.collector_id":1,"endpoint_campaign.endpoint_id":1,"endpoint_campaign.detections.canonical_event_id":1}).toArray();
for(const i of incs){const pr=((i.xdr_pipeline||{}).source_provenance)||{},ca=i.endpoint_campaign||{};
if(!(EP.includes(ca.endpoint_id)||EP.includes(pr.collector_id))){other++;continue;}
const cids=[(i.xdr_pipeline||{}).canonical_event_id].concat((ca.detections||[]).map(d=>d&&d.canonical_event_id)).filter(Boolean);
let foreign=0;
for(const cid of cids){if(!has("xdr_canonical_evidence"))break;
const r=t.xdr_canonical_evidence.findOne({event_id:cid},{"provenance.collector_id":1,"additional_fields.endpoint_id":1});
if(!r)continue;const cc=(r.provenance||{}).collector_id,ee=(r.additional_fields||{}).endpoint_id;
if(!EP.includes(cc)&&!EP.includes(ee))foreign++;}
(foreign===0?only:mixed).push(i);}
print("\n   "+p("incidents EDR-ONLY")+n(only.length));
print("   "+p("incidents MIXED (never auto-deleted)")+n(mixed.length));
print("   "+p("incidents unrelated (preserved)")+n(other));
for(const i of only.slice(0,30))print("      EDR-ONLY "+i.id+" #"+(i.incident_number||"-")+" "+(i.incident_state||"")+" "+String(i.title||"").slice(0,55));
for(const i of mixed.slice(0,30))print("      MIXED    "+i.id+" #"+(i.incident_number||"-")+" "+(i.incident_state||"")+" "+String(i.title||"").slice(0,55));}
const ids=only.map(i=>i.id).filter(Boolean);
print("\n-- 4 dependents of the "+ids.length+" EDR-ONLY incident(s)");
if(ids.length){const probe=t.getCollectionNames().filter(c=>/^(xdr_|v2_|verdict_|investigation|incidents$|canonical_)/.test(c));
let found=0;
for(const c of probe)for(const f of ["incident_id","case_id","id","parent_incident_id","promoted_incident_id"]){let h=0;
try{h=t[c].countDocuments({[f]:{$in:ids}});}catch(e){continue;}
if(h>0){found++;print("   "+p(c+" ."+f)+n(h));}}
if(!found)print("   no dependent artefact references these incident ids");}else print("   none");
print("\n-- 5 preserved after cleanup");
for(const c of ["xdr_canonical_evidence","v2_shadow_observations","workspace_cases","xdr_investigations","xdr_investigation_findings","xdr_detection_rules","xdr_detection_matches","xdr_incidents","investigation_cases"]){
if(!has(c)){print("   "+p(c)+"(absent)");continue;}
const al=t[c].countDocuments({});let rm=0;
if(c==="xdr_canonical_evidence")rm=edrEv;if(c==="v2_shadow_observations")rm=edrObs;if(c==="workspace_cases")rm=only.length;
print("   "+p(c)+"total "+n(al)+"  removal "+n(rm)+"  remaining "+n(al-rm));}
print("\n-- storage");
let by=0;
for(const c of TEL.concat(["xdr_canonical_evidence","v2_shadow_observations"])){if(!has(c))continue;
try{const s=t.runCommand({collStats:c});by+=(s.size||0)+(s.totalIndexSize||0);
print("   "+p(c)+"docs "+n(s.count)+"  data "+((s.size||0)/1048576).toFixed(1)+" MiB  idx "+((s.totalIndexSize||0)/1048576).toFixed(1)+" MiB");}catch(e){print("   "+p(c)+"collStats unavailable");}}
print("   "+p("TOTAL data+index")+(by/1073741824).toFixed(2)+" GiB");
print("\nREAD ONLY - nothing was modified.");
