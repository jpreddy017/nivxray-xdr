"""Local-only before/after characterization of CI-09 resource controls.
Run: PYTHONPATH=backend python docs/research/command-intelligence/security_probes.py
Uses a synthetic auth store, a 1 MiB harmless allocation and a killable delayed marker.
No submitted script execution, external service access or production data.
"""
import asyncio
import gzip
import json
import secrets
import tempfile
from pathlib import Path
import time

import jwt
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import deps
from routers.ops import router
from routers.helpers.decode_offload import run_offloaded
from decoders.gzip_stream import GzipDecoder
from services.decoder.base.compression import inflate_bounded
from services.decoder.resource_limits import DecodeLimitExceeded

def harmless_delay(marker):
    time.sleep(.5)
    Path(marker).write_text("completed")


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
    try:
        result['legacy_gzip_output_bytes'] = len(GzipDecoder().decode(raw.decode('latin1'), {}, None).output)
    except DecodeLimitExceeded as exc:
        result['legacy_gzip'] = str(exc)
    try:
        inflate_bounded(raw, max_output=131072)
        result['automatic_gzip'] = 'UNEXPECTED ACCEPT'
    except ValueError as exc:
        result['automatic_gzip'] = str(exc)
    with tempfile.TemporaryDirectory(prefix='ci09-probe-') as directory:
        marker = str(Path(directory)/'completed')
        async def probe():
            try:
                await run_offloaded(harmless_delay, marker, timeout_s=.1)
            except DecodeLimitExceeded as exc:
                result['worker_timeout_http'] = exc.status_code
                result['worker_done_at_timeout'] = Path(marker).exists()
            await asyncio.sleep(.6)
            result['worker_completed_after_timeout'] = Path(marker).exists()
        asyncio.run(probe())
    passed = (result['legacy_http'] == 413 and 'legacy_gzip' in result
              and result.get('worker_timeout_http') == 504
              and not result.get('worker_completed_after_timeout', True))
    result['legacy_resource_acceptance'] = 'PASS' if passed else 'FAIL'
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
