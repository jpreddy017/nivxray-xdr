"""Versioned snapshot profile and result contract shared by API paths."""
import hashlib,json
from datetime import datetime,timezone,timedelta
from pathlib import Path

ACTION='COLLECT_FORENSIC_SNAPSHOT'
CATALOG=json.loads(Path(__file__).with_name('forensic_catalog.json').read_text())
KEYS={row['id'] for row in CATALOG}
STATES={'COLLECTED','PARTIAL','FAILED','UNAVAILABLE','UNSUPPORTED_PLATFORM','NOT_SELECTED','BUDGET_EXHAUSTED','OUTPUT_LIMIT','TIMED_OUT','INTERRUPTED'}

def target_for(profile):
 if profile=='process':return {}
 if profile not in ('windows_standard','windows_full'):raise ValueError('Unknown snapshot profile')
 return {'profile':profile,'categories':[r['id'] for r in CATALOG], 'include_sensitive':profile=='windows_full'}

def capability_available(endpoint):
 cap=endpoint.get('forensic_collection') or {}
 try:
  stamp=datetime.fromisoformat(cap['reported_at'])
  recent=timedelta(0)<=datetime.now(timezone.utc)-stamp<timedelta(hours=24)
 except (KeyError,ValueError,TypeError):recent=False
 return recent and cap.get('platform')=='windows' and set(cap.get('categories',[]))==KEYS

def validate_target(target,endpoint):
 from edr_plane.response import ResponseError
 profile=target.get('profile')
 if profile not in ('windows_standard','windows_full') or target!=target_for(profile):
  raise ResponseError('INVALID_SNAPSHOT_PROFILE','Only the versioned, fixed collection profiles are accepted.',422)
 if not capability_available(endpoint):
  raise ResponseError('SNAPSHOT_UPGRADE_REQUIRED','This endpoint has not recently advertised the full Windows forensic collector. Install the validated sensor release before requesting this profile.',409)
 return target_for(profile)

def validate_evidence(evidence,target):
 from edr_plane.response import ResponseError
 def reject():raise ResponseError('INVALID_SNAPSHOT_EVIDENCE','Snapshot evidence failed schema, bounds, category, or checksum validation.',422)
 if len(json.dumps(evidence,ensure_ascii=False).encode())>2200000:reject()
 if evidence.get('schema')!='nivxforge.windows-forensic-snapshot.v1':reject()
 categories=evidence.get('categories')
 if not isinstance(categories,list) or len(categories)!=len(target['categories']) or any(not isinstance(c,dict) for c in categories):reject()
 if any(not isinstance(c.get('category_id'),str) for c in categories):reject()
 if {c.get('category_id') for c in categories}!=set(target['categories']):reject()
 for c in categories:
  if not isinstance(c.get('state'),str) or c['state'] not in STATES or not isinstance(c.get('rows'),list) or len(c['rows'])>256 or c.get('row_count')!=len(c['rows']):reject()
  if any(not isinstance(r,dict) for r in c['rows']):reject()
  if not isinstance(c.get('issues',[]),list) or any(not isinstance(i,str) for i in c.get('issues',[])):reject()
  if c['state'] not in ('COLLECTED','PARTIAL') and c['rows']:reject()
 digest=evidence.get('sha256');raw={k:v for k,v in evidence.items() if k!='sha256'}
 if digest!=hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest():reject()
 if not target.get('include_sensitive'):
  sensitive={r['id'] for r in CATALOG if r['sensitive']}
  if any(c['category_id'] in sensitive and c['state']!='NOT_SELECTED' for c in categories):reject()

async def claim_one(db,tenant_id,endpoint_id):
 from edr_plane import response as resp
 now=datetime.now(timezone.utc);cutoff=(now-timedelta(seconds=600)).isoformat()
 doc=await db[resp.COLLECTION].find_one_and_update(
  {'tenant_id':tenant_id,'endpoint_id':endpoint_id,'action':ACTION,
   '$or':[{'state':'REQUESTED','requested_at':{'$gte':cutoff}}, {'state':'DISPATCHED','dispatched_at':{'$lt':cutoff}}]},
  {'$set':{'state':'DISPATCHED','dispatched_at':now.isoformat()},'$push':{'history':{'state':'DISPATCHED','at':now.isoformat(),'actor':endpoint_id}}},
  sort=[('requested_at',1)],projection={'_id':0,'command_id':1,'action':1,'target':1},return_document=True)
 return [doc] if doc else []
