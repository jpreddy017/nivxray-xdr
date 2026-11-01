"""Full-pipeline canonical-write regression against localhost synthetic Mongo only."""
import os, sys, asyncio, json, uuid, time, importlib.util, argparse
from pathlib import Path
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--backend-root', type=Path, default=Path(__file__).resolve().parents[2] / 'backend')
parser.add_argument('--baseline', type=Path, help='Optional frozen pre-fix pipeline for A/B reproduction')
parser.add_argument('--candidate', type=Path, help='Defaults to backend-root/detection_content/xdr_pipeline.py')
args = parser.parse_args()
name='nivx_canonical_write_'+uuid.uuid4().hex
os.environ['MONGO_URL']='mongodb://127.0.0.1:27017'
os.environ['DB_NAME']=name
sys.path.insert(0,str(args.backend_root))
import requests, urllib.request
def no_http(*a,**k):
    raise RuntimeError('External HTTP disabled in synthetic audit')
requests.sessions.Session.request=no_http
urllib.request.urlopen=no_http
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient

def load(path, suffix):
    spec=importlib.util.spec_from_file_location('detection_content.audit_'+suffix,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

async def main():
    client=AsyncIOMotorClient('mongodb://127.0.0.1:27017',serverSelectionTimeoutMS=3000)
    sync=MongoClient('mongodb://127.0.0.1:27017',serverSelectionTimeoutMS=3000)
    import deps
    deps.client._bind(client)
    deps._sync_client=sync
    variants = []
    if args.baseline:
        variants.append(('baseline', load(str(args.baseline), 'baseline')))
    variants.append(('candidate', load(str(args.candidate or args.backend_root / 'detection_content/xdr_pipeline.py'), 'candidate')))
    report=[]
    try:
        for label,module in variants:
            db=client[name+'_'+label]
            deps.db._bind(db)
            coll=db[module.CANONICAL_COLLECTION]
            await coll.create_index([('ingest_time',-1),('tenant_id',1)],name='historical_ingest')
            for offset in range(0,50000,1000):
                await coll.insert_many([dict(tenant_id='seed',event_id='seed_'+str(i),padding='x'*512) for i in range(offset,offset+1000)])
            capture={}
            class Evidence:
                async def insert_one(self,doc):
                    # Same identifier in another tenant must not capture this
                    # delivery's timestamp update. This is synthetic evidence.
                    foreign=dict(doc)
                    foreign['tenant_id']='other_tenant'
                    foreign['audit_marker']='must_remain_unchanged'
                    r=await coll.insert_one(foreign)
                    capture['foreign_id']=r.inserted_id
                    capture['foreign_before']=await coll.find_one({'_id':r.inserted_id})
                    own=await coll.insert_one(doc)
                    capture['own_id']=own.inserted_id
                    capture['own_before']=await coll.find_one({'_id':own.inserted_id})
                    return own
                async def update_one(self,q,u,**kwargs):
                    capture['query']=q
                    capture['update']=u
                    return await coll.update_one(q,u,**kwargs)
            class Database:
                def __getitem__(self,key):
                    return Evidence() if key==module.CANONICAL_COLLECTION else db[key]
            event=dict(event_type='flow',timestamp='2026-10-31T11:40:00Z',src_ip='192.0.2.1',dest_ip='198.51.100.1',proto='TCP')
            t=time.perf_counter()
            result=await module.process_event_through_pipeline(Database(),event,trace_id='fixture',integration_id='fixture',collector_id='fixture',tenant_id='fixture')
            elapsed=round((time.perf_counter()-t)*1000,3)
            own=await coll.find_one({'_id':capture['own_id']})
            foreign=await coll.find_one({'_id':capture['foreign_id']})
            stamped=own.get('provenance',{}).get('timestamps',{}).get('verdict_at') != capture['own_before'].get('provenance',{}).get('timestamps',{}).get('verdict_at')
            foreign_unchanged=foreign==capture['foreign_before']
            plan=await db.command('explain',{'update':module.CANONICAL_COLLECTION,'updates':[{'q':capture['query'],'u':capture['update'],'multi':False,'upsert':False}]},verbosity='executionStats')
            stats=plan['executionStats']
            row=dict(variant=label,pipeline_ms=elapsed,own_stamped=stamped,foreign_unchanged=foreign_unchanged,query_keys=list(capture['query']),keys_examined=stats['totalKeysExamined'],docs_examined=stats['totalDocsExamined'],execution_ms=stats['executionTimeMillis'])
            report.append(row)
            if label=='baseline':
                assert not stamped and not foreign_unchanged,row
                assert row['docs_examined']>=50000,row
            else:
                assert stamped and foreign_unchanged,row
                assert row['docs_examined']==1 and row['keys_examined']==1,row
        print('CANONICAL_WRITE_AUDIT',json.dumps(report,sort_keys=True))
        print('PASS: canonical timestamp update touches only its inserted document using the _id index')
    finally:
        for label in ('baseline','candidate'):
            await client.drop_database(name+'_'+label)
        client.close();sync.close()

if __name__=='__main__':
    asyncio.run(main())
