"""Local-only characterization of OPEN legacy resource findings, not a PASS gate.
Run: PYTHONPATH=backend python docs/research/command-intelligence/security_probes.py
Uses a synthetic auth store, a 1 MiB harmless allocation and a 50 ms sleep.
No submitted script execution, external service access or production data.
"""
import asyncio
import gzip
import json
import secrets
import threading
import time

import jwt
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import deps
from routers.ops import router
from routers.helpers.decode_offload import run_offloaded
from decoders.gzip_stream import GzipDecoder
from services.decoder.base.compression import inflate_bounded


def main():
    key = secrets.token_hex(32)
    class Users:
        async def find_one(self, query, projection):
            if query['email'] == 'review@synthetic.invalid':
                return {'email': query['email'], 'role': 'analyst'}
    class DB:
        users = Users()
    deps.JWT_SECRET, deps.db = key, DB()
    app = FastAPI()
    app.include_router(router, prefix='/api')
    headers = {'Authorization': 'Bearer ' + jwt.encode({'sub': 'review@synthetic.invalid'}, key, algorithm='HS256')}
    result = {}
    with TestClient(app) as c:
        raw = 'whoami' + ' ' * 16384
        result['command_input_bytes'] = len(raw.encode())
        result['automatic_http'] = c.post('/api/analyze/command', headers=headers, json={'input': raw, 'automatic': True}).status_code
        result['legacy_http'] = c.post('/api/analyze/command', headers=headers, json={'input': raw}).status_code
    raw = gzip.compress(b'A' * 1048576, mtime=0)
    result['compressed_bytes'] = len(raw)
    result['legacy_gzip_output_bytes'] = len(GzipDecoder().decode(raw.decode('latin1'), {}, None).output)
    try:
        inflate_bounded(raw, max_output=131072)
        result['automatic_gzip'] = 'UNEXPECTED ACCEPT'
    except ValueError as exc:
        result['automatic_gzip'] = str(exc)
    done = threading.Event()
    def harmless_delay():
        time.sleep(.05)
        done.set()
    async def probe():
        try:
            await run_offloaded(harmless_delay, timeout_s=.005)
        except HTTPException as exc:
            result['thread_timeout_http'] = exc.status_code
            result['thread_done_at_timeout'] = done.is_set()
        await asyncio.sleep(.1)
        result['thread_completed_after_timeout'] = done.is_set()
    asyncio.run(probe())
    result['legacy_resource_acceptance'] = 'FAIL: open release blocker'
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
