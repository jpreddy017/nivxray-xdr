"""Shared legacy decoder budgets. No caller-controlled limit enlargement.

Limit exceptions deliberately bypass legacy ``except Exception`` recovery loops:
resource refusal must never become an alternative decode or benign result. The
outer worker maps them to an explicit HTTP error without publishing evidence.
"""
from contextvars import ContextVar
from contextlib import contextmanager
from dataclasses import dataclass
import time

MAX_INPUT = 16384
MAX_OUTPUT = 131072
MAX_TOTAL = 1048576
MAX_STEPS = 256
MAX_DEPTH = 32
MAX_SECONDS = 25
MAX_RATIO = 128

class DecodeLimitExceeded(BaseException):
    def __init__(self, message, status_code=413, code='decode_limit'):
        super().__init__(message)
        self.status_code, self.code = status_code, code

@dataclass
class Budget:
    total: int = 0
    steps: int = 0
    depth: int = 0
    deadline: float = 0

_CURRENT = ContextVar('decoder_budget', default=None)

def size(value):
    return len(value.encode('utf-8')) if isinstance(value, str) else len(value)

def check_input(value, *, external=True, max_input=MAX_INPUT):
    if not isinstance(value, (str, bytes)) and hasattr(value, "content"):
        value = value.content
    if isinstance(value, (str, bytes)) and size(value) > (max_input if external else MAX_OUTPUT):
        raise DecodeLimitExceeded('Decoder input byte limit exceeded')

def charge(n):
    if n > MAX_OUTPUT:
        raise DecodeLimitExceeded('Decoder output byte limit exceeded')
    state = _CURRENT.get()
    if state:
        state.total += n
        if state.total > MAX_TOTAL:
            raise DecodeLimitExceeded('Decoder cumulative output budget exceeded')
        if time.monotonic() > state.deadline:
            raise DecodeLimitExceeded('Decoder time budget exceeded')

@contextmanager
def budget(initial=None):
    state = _CURRENT.get()
    token = None
    if state is None:
        state = initial or Budget(deadline=time.monotonic()+MAX_SECONDS)
        token = _CURRENT.set(state)
    state.depth += 1
    state.steps += 1
    try:
        if state.depth > MAX_DEPTH or state.steps > MAX_STEPS:
            raise DecodeLimitExceeded('Decoder recursion/candidate budget exceeded')
        charge(0)
        yield state
    finally:
        state.depth -= 1
        if token is not None:
            _CURRENT.reset(token)


def charge_result(value):
    """Account nested retained artifacts as well as primitive transform output."""
    import dataclasses
    seen = set()
    def walk(obj):
        if id(obj) in seen:
            return
        seen.add(id(obj))
        if len(seen) > 10000:
            raise DecodeLimitExceeded('Decoder result object budget exceeded')
        if isinstance(obj, (str, bytes)):
            charge(size(obj))
        elif isinstance(obj, dict):
            for key, item in obj.items():
                walk(key); walk(item)
        elif isinstance(obj, (list, tuple, set)):
            for item in obj: walk(item)
        elif dataclasses.is_dataclass(obj):
            for field in dataclasses.fields(obj): walk(getattr(obj, field.name))
        elif hasattr(obj, 'model_dump'):
            walk(obj.model_dump())
    walk(value)
