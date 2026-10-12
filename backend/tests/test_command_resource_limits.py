"""CI-09: actual hostile resource shapes with harmless content, never scripts."""
import asyncio
import base64
import bz2
import gzip
import lzma
import multiprocessing
from pathlib import Path
import time
import zlib

import pytest
from services.decoder import bounded_codecs as codecs, isolated
from services.decoder.resource_limits import DecodeLimitExceeded, MAX_OUTPUT, budget, charge
from routers.helpers.decode_offload import run_offloaded
from test_command_automatic_api import client


def _delayed_marker(path):
    time.sleep(.5)
    Path(path).write_text('worker escaped timeout')


def _large_report():
    return {'output': 'x' * (isolated.MAX_RESULT+1)}


@pytest.mark.parametrize('pack,unpack', [
    (gzip.compress, codecs.gzip.decompress), (zlib.compress, codecs.zlib.decompress),
    (bz2.compress, codecs.bz2.decompress), (lzma.compress, codecs.lzma.decompress),
])
def test_streaming_limits_and_valid_compatibility(pack, unpack):
    plain = b'Write-Output "hello"'
    assert unpack(pack(plain)) == plain
    with pytest.raises(DecodeLimitExceeded):
        unpack(pack(b'A' * (MAX_OUTPUT*8)))
    with pytest.raises((Exception, DecodeLimitExceeded)):
        unpack(pack(plain)[:-4])

@pytest.mark.parametrize('codec', ['brotli','snappy','lz4frame','lz4block','zstandard'])
def test_optional_codecs_remain_supported_and_bounded(codec):
    import importlib
    module = importlib.import_module({'lz4frame':'lz4.frame','lz4block':'lz4.block'}.get(codec,codec))
    compress = module.ZstdCompressor().compress if codec=='zstandard' else module.compress
    bounded = getattr(codecs, codec)
    decompress = bounded.ZstdDecompressor().decompress if codec=='zstandard' else bounded.decompress
    assert decompress(compress(b'harmless text')) == b'harmless text'
    with pytest.raises(DecodeLimitExceeded): decompress(compress(b'A' * (MAX_OUTPUT*8)))


def test_raw_deflate_detection_is_bounded():
    from decoders.zlib_deflate import ZlibDecoder
    from types import SimpleNamespace
    bomb = zlib.compress(b'A' * (MAX_OUTPUT*8))[2:-4].decode('latin1')
    with pytest.raises(DecodeLimitExceeded):
        ZlibDecoder().detect(bomb, SimpleNamespace(is_binary=True,entropy=7),None)


def test_lzma_speculative_detection_is_bounded():
    from decoders.lzma_stream import LzmaDecoder
    from types import SimpleNamespace
    bomb = lzma.compress(b'A' * (MAX_OUTPUT*8),format=lzma.FORMAT_ALONE).decode('latin1')
    with pytest.raises(DecodeLimitExceeded):
        LzmaDecoder().detect(bomb,SimpleNamespace(english_density=0,printable_ratio=0,entropy=7),None)


def test_cumulative_budget_does_not_reset_for_nested_work():
    with budget():
        for _ in range(8):
            with budget(): charge(MAX_OUTPUT)
        with pytest.raises(DecodeLimitExceeded):
            with budget(): charge(1)

@pytest.mark.asyncio
async def test_timeout_reaps_worker_and_cannot_write_after_return(tmp_path):
    path = tmp_path/'escaped'
    before = {p.pid for p in multiprocessing.active_children()}
    with pytest.raises(DecodeLimitExceeded) as error:
        await run_offloaded(_delayed_marker, str(path), timeout_s=.1)
    assert error.value.status_code == 504
    assert {p.pid for p in multiprocessing.active_children()} == before
    await asyncio.sleep(.6)
    assert not path.exists()

@pytest.mark.asyncio
async def test_event_loop_remains_responsive_during_supervision(tmp_path):
    task = asyncio.create_task(run_offloaded(_delayed_marker,str(tmp_path/'normal'),timeout_s=3))
    start = time.monotonic()
    await asyncio.sleep(.03)
    assert time.monotonic()-start < .3
    await task


def test_shared_capacity_rejects_immediately():
    assert isolated._CAPACITY.acquire(False)
    assert isolated._CAPACITY.acquire(False)
    try:
        with pytest.raises(DecodeLimitExceeded) as error:
            isolated.invoke(__name__,'_large_report',(),{})
        assert error.value.status_code == 503
        from services.decoder.automatic_worker import analyze_isolated
        with pytest.raises(RuntimeError,match='busy'): analyze_isolated('whoami')
    finally:
        isolated._CAPACITY.release(); isolated._CAPACITY.release()


def test_report_serialization_is_bounded():
    with pytest.raises(DecodeLimitExceeded,match='limit'):
        isolated.invoke(__name__,'_large_report',(),{})

@pytest.mark.parametrize('route,extra', [('/analyze/command',{}),('/decode/magic',{}),('/decode/smart',{}),('/recipe/run',{'steps':[]}),('/decode/candidates',{})])
def test_all_legacy_ops_ingress_limits(client, route, extra):
    c,headers=client
    r=c.post('/api'+route,headers=headers(),json={'input':'whoami'+' '*16384,**extra})
    assert r.status_code == 413,r.text
    assert r.json()['detail']['code']=='decode_limit'


def test_legacy_recipe_contract_and_bomb_refusal(client):
    c,headers=client
    result=c.post('/api/recipe/run',headers=headers(),json={'input':'aGVsbG8=','steps':[{'op':'base64-decode'}]})
    assert result.status_code==200,result.text
    assert result.json()['output']=='hello'
    bomb=base64.b64encode(gzip.compress(b'A'*(MAX_OUTPUT*8))).decode()
    result=c.post('/api/recipe/run',headers=headers(),json={'input':bomb,'steps':[{'op':'base64-gzip'}]})
    assert result.status_code==413,result.text
    assert 'output' not in result.json()


def test_request_controlled_search_and_step_limits(client):
    c,headers=client
    assert c.post('/api/decode/magic',headers=headers(),json={'input':'hello','max_depth':100000}).status_code==422
    assert c.post('/api/recipe/run',headers=headers(),json={'input':'hello','steps':[{'op':'reverse'}]*33}).status_code==422


def test_extended_recipe_operations_registered_in_spawned_worker(client):
    c,headers=client
    for operation, pack in [('bzip2-decompress',bz2.compress),('lzma-decompress',lzma.compress)]:
        r=c.post('/api/recipe/run',headers=headers(),json={'input':base64.b64encode(pack(b'hello')).decode(),'steps':[{'op':operation}]})
        assert r.status_code==200,r.text
        assert r.json()['output']=='hello'
        assert r.json()['errors']==[]


def test_parent_exception_fallback_cannot_swallow_worker_refusal(client):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from services.decoder.http_boundary import DecoderResourceMiddleware
    from operations import run_operation
    app=FastAPI()
    app.add_middleware(DecoderResourceMiddleware)
    fallback=[]
    @app.get('/probe')
    async def probe():
        try:
            return await run_offloaded(run_operation,'base64-gzip',base64.b64encode(gzip.compress(b'A'*(MAX_OUTPUT*8))).decode())
        except Exception:
            fallback.append(True)
            return {'recovered':True}
    with TestClient(app) as c:
        r=c.get('/probe')
    assert r.status_code==413,r.text
    assert fallback==[]

@pytest.mark.asyncio
async def test_cumulative_budget_survives_separate_workers():
    from operations import run_operation
    with budget():
        for _ in range(4):
            assert await run_offloaded(run_operation,'reverse','a'*16000) == 'a'*16000
        for _ in range(7): charge(MAX_OUTPUT)
        with pytest.raises(DecodeLimitExceeded):
            await run_offloaded(run_operation,'reverse','a'*16000)


def test_archive_limits_and_recursive_compatibility():
    import io,zipfile
    from services.die.archive_recovery import recover, recover_recursive
    def zipped(payload):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr('harmless.txt',payload)
        return out.getvalue()
    assert recover(zipped(b'hello'))['children'][0]['size']==5
    assert recover_recursive(zipped(b'hello'))['total']==1
    with pytest.raises(DecodeLimitExceeded): recover(zipped(b'A'*(MAX_OUTPUT*8)))
    with pytest.raises(DecodeLimitExceeded): recover_recursive(zipped(b'hello'),max_depth=100000)


def test_worker_setup_failure_releases_shared_capacity(monkeypatch):
    def fail(_): raise OSError('fixture process setup failure')
    monkeypatch.setattr(isolated.multiprocessing,'get_context',fail)
    for _ in range(3):
        with pytest.raises(OSError): isolated.invoke(__name__,'_large_report',(),{})
    assert isolated._CAPACITY.acquire(False)
    assert isolated._CAPACITY.acquire(False)
    isolated._CAPACITY.release(); isolated._CAPACITY.release()


@pytest.mark.asyncio
async def test_lifespan_tasks_do_not_inherit_request_budget():
    from services.decoder.http_boundary import DecoderResourceMiddleware
    from services.decoder.resource_limits import _CURRENT
    seen=[]
    async def background(): seen.append(_CURRENT.get())
    async def app(scope, receive, send): await asyncio.create_task(background())
    await DecoderResourceMiddleware(app)({'type':'lifespan'},None,None)
    assert seen == [None]


def _spawn_harmless_utility(marker):
    import subprocess,sys
    child=subprocess.Popen([sys.executable,'-c',
        'import time,pathlib,sys; time.sleep(1); pathlib.Path(sys.argv[1]).write_text("escaped")',marker])
    return child.pid


def test_worker_descendants_reaped_after_success(tmp_path):
    marker=tmp_path/'escaped'
    isolated.invoke(__name__,'_spawn_harmless_utility',(str(marker),),{})
    time.sleep(1.2)
    assert not marker.exists()
