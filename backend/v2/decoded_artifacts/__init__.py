"""Tenant/version-partitioned immutable legacy reports, never global hash reuse.

Old unowned rows stay untouched and are unavailable to scoped consumers. No
migration or index change is performed. A command hash is content identity,
not authorization. Existing NCI evidence storage remains independent.
"""
from __future__ import annotations
import hashlib
import json
import re
from datetime import datetime, timezone
from pymongo.errors import DuplicateKeyError
from deps import db

COLL = 'v2_decoded_payloads'
PIPELINE_VERSION = 'v9-ps-semantic-intelligence'
CACHE_POLICY = 'tenant-version-command/1'


def _now():
    return datetime.now(timezone.utc).isoformat()


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', errors='strict')).hexdigest()


def _scope(tenant_id, pipeline_version):
    if type(tenant_id) is not str or not tenant_id.strip() or type(pipeline_version) is not str or not pipeline_version.strip():
        raise ValueError('Explicit artifact tenant and pipeline version required')
    return {'tenant_id':tenant_id, 'pipeline_version':pipeline_version, 'cache_policy':CACHE_POLICY}


def _key(sha256, tenant_id, pipeline_version, command_binary=""):
    if type(command_binary) is not str or len(command_binary) > 128:
        raise ValueError("Invalid command parser profile")
    if type(sha256) is not str or re.fullmatch('[0-9a-f]{64}', sha256) is None:
        raise ValueError('Invalid command SHA-256')
    scope = _scope(tenant_id, pipeline_version)
    key = hashlib.sha256(json.dumps([CACHE_POLICY, tenant_id, pipeline_version, command_binary, sha256], ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest()
    return {'_id':key, 'sha256':sha256, 'command_binary':command_binary, **scope}


def _report_summary(report):
    findings = report.get('findings') or {}
    iocs = findings.get('iocs') or {}
    return {'iocs_summary':{k:list(dict.fromkeys(v))[:32] for k,v in iocs.items() if k in ('ips','urls','domains','sha256','sha1','md5') and isinstance(v,list)},
            'mitre_ids':list(dict.fromkeys(m['id'] for m in findings.get('mitre_techniques',[]) if isinstance(m,dict) and m.get('id'))),
            'verdict':findings.get('verdict') or 'unknown', 'risk_score':int(findings.get('risk_score') or 0),
            'trace_layers':len(report.get('trace') or []), 'elapsed_ms_first':int(report.get('elapsed_ms') or 0)}


async def get_artifact(sha256: str, *, tenant_id: str, pipeline_version: str = PIPELINE_VERSION, command_binary: str = ""):
    query = _key(sha256, tenant_id, pipeline_version, command_binary)
    doc = await db[COLL].find_one(query, {'_id':0})
    if doc and any(doc.get(k) != v for k,v in query.items() if k != '_id'):
        raise ValueError('Artifact ownership does not match query')
    if doc:
        original = doc.get("original_command")
        report = doc.get("report")
        if type(original) is not str or sha256_of(original) != sha256 or type(report) is not dict:
            raise ValueError("Artifact input integrity mismatch")
        digest = hashlib.sha256(json.dumps(report, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if digest != doc.get("report_sha256"):
            raise ValueError("Artifact report integrity mismatch")
    return doc


async def upsert_artifact(*, command_binary: str, command_line: str, report_dict: dict,
                          tenant_id: str, job_id=None, source='AUTO_INVESTIGATE',
                          pipeline_version=PIPELINE_VERSION):
    if len(command_line.encode("utf-8")) > 16384:
        raise ValueError("Artifact input exceeds 16 KiB")
    query = _key(sha256_of(command_line), tenant_id, pipeline_version, command_binary)
    if type(report_dict) is not dict:
        raise ValueError('Artifact report must be an object')
    # Freeze the submitted JSON now; caller mutation cannot alter stored content.
    report = json.loads(json.dumps(report_dict, ensure_ascii=False, allow_nan=False))
    now = _now()
    doc = {**query, 'command_binary':command_binary, 'command_line':command_line[:2048],
           'command_full_bytes':len(command_line.encode('utf-8')), 'original_command':command_line, 'report':report,
           'report_sha256':hashlib.sha256(json.dumps(report, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest(),
           **_report_summary(report), 'provenance':{'first_seen':now,'last_seen':now,'hit_count':0,
               'seen_in_jobs':[job_id] if job_id else [], 'sources':[source]}, 'created_at':now}
    try:
        await db[COLL].insert_one(doc)
        return query['sha256'], True
    except DuplicateKeyError:
        # An actual duplicate is the only error that can mean cache reuse.
        existing = await get_artifact(query['sha256'], tenant_id=tenant_id, pipeline_version=pipeline_version, command_binary=command_binary)
        if not existing:
            raise ValueError('Duplicate key without an owned artifact')
        push = {'provenance.sources':{'$each':[source], '$slice':-20}}
        if job_id: push['provenance.seen_in_jobs'] = {'$each':[job_id], '$slice':-50}
        await db[COLL].update_one(query, {'$set':{'provenance.last_seen':now}, '$inc':{'provenance.hit_count':1}, '$push':push})
        return query['sha256'], False


async def stats(*, tenant_id: str, pipeline_version: str = PIPELINE_VERSION):
    coll = db[COLL]; scope = _scope(tenant_id, pipeline_version)
    total = await coll.count_documents(scope)
    agg = await coll.aggregate([{'$match':scope},{'$group':{'_id':None,'total_hits':{'$sum':{'$ifNull':['$provenance.hit_count',0]}},'avg_layers':{'$avg':'$trace_layers'}}}]).to_list(1)
    top = await coll.aggregate([{'$match':scope},{'$sort':{'provenance.hit_count':-1}},{'$limit':8},{'$project':{'_id':0,'sha256':1,'command_binary':1,'verdict':1,'risk_score':1,'trace_layers':1,'hit_count':'$provenance.hit_count','last_seen':'$provenance.last_seen','mitre_ids':1,'command_line':1}}]).to_list(8)
    return {'total_artifacts':total,'total_reuses':agg[0]['total_hits'] if agg else 0,'avg_trace_layers':round((agg[0]['avg_layers'] if agg else 0) or 0,2),'top_artifacts':top}


async def list_recent(limit=25, *, tenant_id: str, pipeline_version: str = PIPELINE_VERSION):
    cap=max(1,min(200,int(limit)))
    return await db[COLL].find(_scope(tenant_id,pipeline_version), {'_id':0,'report':0,'original_command':0}).sort('provenance.last_seen',-1).limit(cap).to_list(cap)


async def ensure_indexes():
    # Preserve existing indexes; namespaced _id already supplies uniqueness.
    await db[COLL].create_index('provenance.last_seen')
    await db[COLL].create_index('verdict')
    await db[COLL].create_index('mitre_ids')
