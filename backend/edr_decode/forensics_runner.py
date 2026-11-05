from .forensics_validation import validate_request
"""Bounded Forensics transport using the same guarded worker as EDR decoding.

No application configuration or Workspace runtime is imported. Python audit
hooks are defense in depth, not an OS security sandbox.
"""
import asyncio
import json
from pathlib import Path
import sys
from .runner import DecodeUnavailable


class ForensicsRunner:
    def __init__(self, *, timeout_seconds=25, max_workers=2):
        if timeout_seconds <= 0 or max_workers < 1:
            raise ValueError('positive bounds required')
        self.timeout=timeout_seconds
        self.slots=asyncio.Semaphore(max_workers)

    async def analyze(self, request):
        validate_request(request)
        if not isinstance(request,dict) or request.get('mode') not in {'command','recipe'}:
            raise ValueError('explicit analysis mode required')
        payload=json.dumps(request,ensure_ascii=True).encode('utf-8')
        if len(payload)>2*1024*1024:
            raise ValueError('request too large')
        try:
            await asyncio.wait_for(self.slots.acquire(),.1)
        except asyncio.TimeoutError as exc:
            raise DecodeUnavailable('analysis capacity busy') from exc
        process=None
        async def read_bounded(stream):
            chunks=[];size=0
            while True:
                chunk=await stream.read(65536)
                if not chunk:return b''.join(chunks)
                size+=len(chunk)
                if size>4*1024*1024:raise DecodeUnavailable('analysis output limit exceeded')
                chunks.append(chunk)
        try:
            process=await asyncio.create_subprocess_exec(sys.executable,'-I',str(Path(__file__).with_name('worker.py')),
                stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,
                env={'LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0'})
            async def exchange():
                process.stdin.write(payload)
                await process.stdin.drain()
                process.stdin.close()
                output=await read_bounded(process.stdout)
                await process.wait()
                return output
            output=await asyncio.wait_for(exchange(),self.timeout)
            response=json.loads(output)
            if process.returncode or not isinstance(response,dict) or response.get('status')!='complete':
                raise DecodeUnavailable('static analysis unavailable')
            report=response.get('report')
            if not isinstance(report,dict) or report.get('schema_version')!='edr-forensics-v1' or report.get('mode')!=request['mode'] or report.get('executed') is not False:
                raise DecodeUnavailable('invalid static analysis report')
            return report
        except (asyncio.TimeoutError,OSError,ValueError) as exc:
            raise DecodeUnavailable('static analysis failed or deadline exceeded') from exc
        finally:
            try:
                if process is not None:
                    if process.returncode is None:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass  # Worker exited between returncode check and kill.
                    await process.wait()
            finally:
                self.slots.release()
