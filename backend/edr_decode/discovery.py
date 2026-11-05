"""Bounded offline candidate discovery. Candidates are hypotheses, not verdicts."""
import base64
import hashlib
import re
import time
from .recipes import run_recipe, MAX_BYTES


def _operations(data):
    if data.startswith(b'\x1f\x8b'):yield 'gzip'
    if len(data)>1 and data[0]&15==8 and (data[0]*256+data[1])%31==0:yield 'zlib'
    if len(data)>=8 and len(data)%4==0:
        if re.fullmatch(rb'[A-Za-z0-9+/]+={0,2}',data):yield 'base64'
        if (b'-' in data or b'_' in data) and re.fullmatch(rb'[A-Za-z0-9_-]+={0,2}',data):yield 'base64url'
    if len(data)>=8 and len(data)%2==0 and re.fullmatch(rb'[0-9a-fA-F]+',data):yield 'hex'
    if re.search(rb'%[0-9a-fA-F]{2}',data):yield 'percent'
    if len(data)>=4 and len(data)%2==0:
        if data.startswith(b'\xff\xfe') or data[1::2].count(0)/len(data[1::2])>.5:yield 'utf16le'
        if data.startswith(b'\xfe\xff') or data[::2].count(0)/len(data[::2])>.5:yield 'utf16be'


def discover(data, *, max_depth=8, max_nodes=32, timeout_seconds=.5):
    if not isinstance(data,bytes) or len(data)>MAX_BYTES:raise ValueError('bounded bytes required')
    if not (1<=max_depth<=16 and 1<=max_nodes<=64 and 0<timeout_seconds<=2):
        raise ValueError('invalid discovery budget')
    started=time.monotonic(); queue=[(data,[])];seen={hashlib.sha256(data).hexdigest()}
    candidates=[];failures=[];limited=False;attempts=0
    while queue:
        current,path=queue.pop(0)
        operations=list(_operations(current))
        if len(path)>=max_depth:
            limited=limited or bool(operations);continue
        for op in operations:
            if attempts>=max_nodes or time.monotonic()-started>=timeout_seconds:
                limited=True;queue.clear();break
            attempts+=1
            result=run_recipe(current,[{'operation':op}])
            if result['status']!='completed':
                failures.append({'parent_path':path,'operation':op,'reason':result['failure']['reason']});continue
            output=base64.b64decode(result['output_base64'])
            digest=result['output_sha256']
            if digest in seen:continue
            seen.add(digest);newpath=path+[{'operation':op}]
            try:
                decoded=output.decode('utf-8')
                readable=bool(decoded) and sum(c.isprintable() or c in '\n\r\t' for c in decoded)/len(decoded)>.95
            except UnicodeError:decoded=None;readable=False
            candidates.append({'recipe':newpath,'output_sha256':digest,'output_bytes':len(output),
                               'output_base64':result['output_base64'],
                               'preview':decoded[:500] if decoded is not None else None,
                               'readable_text':readable,'interpretation':'unverified_candidate'})
            queue.append((output,newpath))
    return {'status':'budget_limited' if limited else 'search_complete',
            'input_sha256':hashlib.sha256(data).hexdigest(),'attempts':attempts,
            'candidates':candidates,'failed_transforms':failures,
            'scope':'pattern-supported transforms only; no unknown-key decryption',
            'executed':False,'verdict':'not_assessed'}
