"""One admission/kill boundary for shared legacy decoder entry points.

Only server-owned decorated functions select targets. Input strings are never
code. Child processes share one cumulative budget across nested calls. Result
files are private, bounded and read only after the child exits: no blocking pipe
receive after a nominal timeout. No database or auth decisions move here.
"""
import functools
import importlib
import multiprocessing
import os
import pickle
import tempfile
import threading
import time
from .resource_limits import budget, check_input, charge, DecodeLimitExceeded, MAX_SECONDS, MAX_TOTAL, MAX_STEPS, Budget, _CURRENT, charge_result

_CAPACITY = threading.BoundedSemaphore(2)
_IN_WORKER = False
MAX_RESULT = 8 * 1024 * 1024
MAX_MEMORY = 1024 * 1024 * 1024

def _input_limit(module):
    # Archive upload API retains its separate bounded binary-input profile.
    return 131072 if module == "services.die.archive_recovery" else 16384

class _Writer:
    def __init__(self, stream):
        self.stream, self.count = stream, 0
    def write(self, data):
        self.count += len(data)
        if self.count > MAX_RESULT:
            raise DecodeLimitExceeded('Decoder report byte limit exceeded')
        return self.stream.write(data)

def _child(path, module, name, args, kwargs, initial=None):
    global _IN_WORKER
    _IN_WORKER = True
    try:
        if hasattr(os, 'setsid'):
            os.setsid()
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY, MAX_MEMORY))
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_SECONDS, MAX_SECONDS+1))
        if module in {'operations','smart_decoder','magic_decoder','analysis_core','command_analyzer','services.decoder.recipe','services.canonical_evidence_recovery','engine.orchestrator','routers.uaie','routers.moe_panel'}:
            from .bootstrap import register_operations
            register_operations()
        target = importlib.import_module(module)
        for part in name.split('.'):
            target = getattr(target, part)
        before_total = initial.total if initial else 0
        before_steps = initial.steps if initial else 0
        with budget(initial) as state:
            result = target(*args, **kwargs)
            charge_result(result)
            used = (state.total-before_total, state.steps-before_steps)
        with open(path, 'wb') as stream:
            pickle.dump(('ok', result, used), _Writer(stream), protocol=5)
    except DecodeLimitExceeded as exc:
        with open(path, 'wb') as stream:
            pickle.dump(('limit', str(exc), (0,0)), stream)
    except BaseException:
        with open(path, 'wb') as stream:
            pickle.dump(('error', 'Decoder worker could not complete safely', (0,0)), stream)

def invoke(module, name, args, kwargs, timeout=MAX_SECONDS):
    try:
        for value in (*args, *kwargs.values()):
            check_input(value, max_input=_input_limit(module))
        if len(pickle.dumps((args, kwargs), protocol=5)) > 4*_input_limit(module):
            raise DecodeLimitExceeded('Decoder argument byte limit exceeded')
    except DecodeLimitExceeded as exc:
        raise DecodeLimitExceeded(str(exc)) from None
    if not _CAPACITY.acquire(blocking=False):
        raise DecodeLimitExceeded('Decoder capacity exhausted; retry shortly', 503, 'decode_busy')
    process = None
    parent = _CURRENT.get()
    initial = None
    if parent:
        initial = Budget(total=parent.total, steps=parent.steps, deadline=parent.deadline)
        timeout = min(timeout, max(.001, parent.deadline-time.monotonic()))
    try:
        with tempfile.TemporaryDirectory(prefix='nivx-decode-') as directory:
            path = os.path.join(directory, 'result')
            process = multiprocessing.get_context('spawn').Process(target=_child, args=(path,module,name,args,kwargs,initial), daemon=True)
            process.start()
            process.join(timeout)
            if process.is_alive():
                raise DecodeLimitExceeded('Decoder exceeded worker deadline; computation stopped', 504, 'decode_timeout')
            if process.exitcode != 0 or not os.path.exists(path):
                raise DecodeLimitExceeded('Decoder worker stopped without a complete result', 503, 'decode_worker_failed')
            if os.path.getsize(path) > MAX_RESULT:
                raise DecodeLimitExceeded('Decoder report limit exceeded')
            with open(path, 'rb') as stream:
                kind, result, used = pickle.load(stream)
            if kind != 'ok':
                raise DecodeLimitExceeded(result, 413 if kind=='limit' else 503, 'decode_limit' if kind=='limit' else 'decode_worker_failed')
            if parent:
                parent.total += used[0]
                parent.steps += used[1]
                if parent.total > MAX_TOTAL or parent.steps > MAX_STEPS:
                    raise DecodeLimitExceeded('Decoder cumulative request budget exceeded')
                charge(0)
            return result
    finally:
        if process is not None and process.pid:
            import signal
            # The group may outlive its leader. Clean it on every exit path.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, AttributeError):
                if process.is_alive(): process.terminate()
            process.join(.2)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, AttributeError):
                if process.is_alive(): process.kill()
            process.join()
            process.close()
        _CAPACITY.release()

def entry(input_arg=0):
    def decorate(fn):
        @functools.wraps(fn)
        def bounded(*args, **kwargs):
            import inspect
            values = inspect.signature(fn).bind(*args, **kwargs).arguments
            parameters = list(inspect.signature(fn).parameters)
            value = values.get(parameters[input_arg], '')
            if not _IN_WORKER:
                try:
                    check_input(value, max_input=_input_limit(fn.__module__))
                    # Bound all serialized arguments, including recipe args/spans.
                    if len(pickle.dumps((args, kwargs), protocol=5)) > 4*_input_limit(fn.__module__):
                        raise DecodeLimitExceeded('Decoder argument byte limit exceeded')
                except DecodeLimitExceeded as exc:
                    raise DecodeLimitExceeded(str(exc)) from None
                return invoke(fn.__module__, fn.__qualname__, args, kwargs)
            check_input(value, external=False)
            with budget():
                result = fn(*args, **kwargs)
                charge_result(result)
                return result
        return bounded
    return decorate
