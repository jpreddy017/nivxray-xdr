"""Dedicated read-only collection worker with a durable replay journal.

Uses its own HTTP session and connection so it cannot interrupt telemetry's
keep-alive connection. Unknown actions never invoke a shell or command.
"""
import json
import re
import sqlite3
import threading
import urllib.request
import urllib.error
from pathlib import Path
import windows_snapshot as collector

ACTION='COLLECT_FORENSIC_SNAPSHOT'
MAX_JOURNAL_BYTES=32*1024*1024

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'Redirect refused', headers, fp)

class Worker:
    def __init__(self, api, identity, state_dir):
        self.api=api.rstrip('/');self.identity=dict(identity);self.stop_event=threading.Event();self.token=None
        endpoint=re.sub('[^a-zA-Z0-9_-]','_',identity['endpoint_id'])
        self.path=Path(state_dir)/('forensic-'+endpoint+'.sqlite3')
        self.thread=threading.Thread(target=self.run,name='forensic-snapshot',daemon=True)

    def http(self,path,body=None):
        raw=json.dumps(body).encode() if body is not None else None
        headers={'Accept':'application/json','Content-Type':'application/json'}
        if self.token:headers['Authorization']='Bearer '+self.token
        req=urllib.request.Request(self.api+path,data=raw,headers=headers,method='POST' if body is not None else 'GET')
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=30) as response:
            payload=response.read(3*1024*1024+1)
            if len(payload)>3*1024*1024:raise ValueError('Response too large')
            return json.loads(payload)

    def process(self,db,command):
        command_id=command.get('command_id','')
        if not re.fullmatch(r'cmd_[a-fA-F0-9]{20}',command_id):raise ValueError('Invalid command identifier')
        old=db.execute('select result from jobs where id=?',(command_id,)).fetchone()
        if old and old[0]:return json.loads(old[0])
        if old:
            result={'outcome':'FAILED','detail':'Previous collection was interrupted; it was not silently recaptured.','evidence':{}}
        else:
            db.execute('insert into jobs(id,result,reported) values (?,NULL,0)',(command_id,));db.commit()
            if command.get('action')!=ACTION:
                result={'outcome':'CAPABILITY_UNAVAILABLE','detail':'Windows collection worker does not implement this action.','evidence':{}}
            else:
                target=command.get('target') or {}
                try:
                    evidence=collector.collect(target.get('categories'),include_sensitive=target.get('include_sensitive') is True,
                        runner=lambda key,timeout:collector.run_query(key,timeout,cancelled=self.stop_event.is_set),cancelled=self.stop_event.is_set)
                    good=sum(r['state'] in ('COLLECTED','PARTIAL') for r in evidence['categories'])
                    result={'outcome':'EXECUTED' if good else 'FAILED','detail':f'{good} categories returned evidence; inspect per-category coverage.','evidence':evidence}
                except Exception as exc:
                    result={'outcome':'FAILED','detail':'Collection rejected: '+type(exc).__name__,'evidence':{}}
        result['command_id']=command_id
        db.execute('update jobs set result=? where id=?',(json.dumps(result),command_id));db.commit()
        return result

    def acknowledge(self,db,command_id):
        """Release acknowledged evidence bytes, retaining a replay receipt.

        Unacknowledged evidence is never removed. The server is the evidence
        repository; the local ledger prevents a completed capture being rerun.
        """
        old=db.execute('select result from jobs where id=?',(command_id,)).fetchone()
        if not old or not old[0]:raise ValueError('Cannot acknowledge missing evidence')
        result=json.loads(old[0])
        receipt={'command_id':command_id,'receipt_only':True,'outcome':result.get('outcome'),
                 'evidence_sha256':result.get('evidence',{}).get('sha256'),
                 'detail':'Evidence acknowledged by the server; local replay receipt retained.'}
        db.execute('update jobs set result=?,reported=1 where id=?',(json.dumps(receipt),command_id));db.commit()
        free=db.execute('pragma freelist_count').fetchone()[0]
        pages=db.execute('pragma page_count').fetchone()[0]
        if free>256 and free>pages//2:db.execute('vacuum')

    def cycle(self,db):
        if not self.token:
            self.token=self.http('/api/edr/agent/session',{'tenant_id':self.identity['tenant_id'],'agent_credential':self.identity['agent_credential']})['session_token']
        # Retry persisted results before claiming more work. A lost response
        # does not trigger another endpoint capture.
        for command_id,payload in db.execute('select id,result from jobs where reported=0 and result is not NULL').fetchall():
            self.http('/api/edr/agent/command-result',json.loads(payload))
            self.acknowledge(db,command_id)
        # Compact evidence acknowledged by older sensor versions as well.
        for command_id, in db.execute('select id from jobs where reported=1 and length(result)>1024').fetchall():
            self.acknowledge(db,command_id)
        if self.path.stat().st_size>=MAX_JOURNAL_BYTES:return
        self.http('/api/edr/agent/forensic-capabilities',{'platform':'windows','collector_version':collector.VERSION,'categories':list(collector.CATALOG)})
        commands=self.http('/api/edr/agent/forensic-commands').get('commands',[])
        for command in commands:
            if self.stop_event.is_set():return
            prior=db.execute('select reported from jobs where id=?',(command.get('command_id'),)).fetchone()
            if prior and prior[0]:continue
            result=self.process(db,command)
            self.http('/api/edr/agent/command-result',result)
            self.acknowledge(db,result['command_id'])

    def run(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute('pragma synchronous=FULL')
            db.execute('create table if not exists jobs(id text primary key,result text,reported integer not null default 0)');db.commit()
            while not self.stop_event.is_set():
                try:self.cycle(db)
                except Exception as exc:
                    self.token=None
                    # No command contents, credentials or collected values in logs.
                    print('[forensic-snapshot] retry: '+type(exc).__name__,flush=True)
                self.stop_event.wait(15)

    def start(self):self.thread.start();return self
    def stop(self):self.stop_event.set();self.thread.join(timeout=20)
