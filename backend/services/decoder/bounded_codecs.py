"""Local codec facades: bounded detection AND decoding; never monkeypatch stdlib.

Compression and unrelated module operations retain the original implementation.
All output caps are enforced before allocating the complete expanded stream.
"""
import bz2 as _bz2
import gzip as _gzip
import lzma as _lzma
import zlib as _zlib
from .resource_limits import MAX_OUTPUT, MAX_RATIO, DecodeLimitExceeded, charge, check_input

class _Proxy:
    def __init__(self, module, **overrides):
        self._module = module
        self.__dict__.update(overrides)
    def __getattr__(self, key):
        return getattr(self._module, key)

class BoundedZlib:
    def __init__(self, *args, **kwargs):
        self._decoder = _zlib.decompressobj(*args, **kwargs)
        self._input = self._output = 0
    def __getattr__(self, key):
        return getattr(self._decoder, key)
    def decompress(self, data, max_length=0):
        check_input(data, external=False)
        self._input += len(data)
        cap = min(MAX_OUTPUT, max(1024, self._input * MAX_RATIO)) - self._output
        requested = min(cap+1, max_length) if max_length else cap+1
        out = self._decoder.decompress(data, requested)
        if len(out) > cap:
            raise DecodeLimitExceeded('Decompression output/ratio limit exceeded')
        self._output += len(out)
        charge(len(out))
        return out
    def flush(self, length=_zlib.DEF_BUF_SIZE):
        # flush(length) is not a maximum-output API. Drain with decompress only.
        return self.decompress(b'')

def zlib_decompress(data, wbits=_zlib.MAX_WBITS, bufsize=_zlib.DEF_BUF_SIZE):
    d = BoundedZlib(wbits)
    out = d.decompress(data)
    if not d.eof:
        raise _zlib.error('incomplete or truncated stream')
    return out

def gzip_decompress(data):
    check_input(data, external=False)
    out = bytearray()
    remaining = data
    while remaining:
        d = BoundedZlib(31)
        part = d.decompress(remaining)
        if not d.eof:
            raise EOFError('Compressed file ended before the end-of-stream marker')
        out.extend(part)
        if len(out) > min(MAX_OUTPUT, max(1024, len(data)*MAX_RATIO)):
            raise DecodeLimitExceeded('Decompression output/ratio limit exceeded')
        remaining = d.unused_data.lstrip(b'\0')
    return bytes(out)

def _limited_stream(data, factory):
    check_input(data, external=False)
    cap = min(MAX_OUTPUT, max(1024, len(data)*MAX_RATIO))
    output = bytearray()
    remaining = data
    while remaining:
        decoder = factory()
        part = decoder.decompress(remaining, max_length=cap-len(output)+1)
        if len(output)+len(part) > cap:
            raise DecodeLimitExceeded('Decompression output/ratio limit exceeded')
        output.extend(part)
        charge(len(part))
        if not decoder.eof:
            if not decoder.needs_input:
                raise DecodeLimitExceeded('Decompression output limit exceeded')
            raise EOFError('Incomplete compression stream')
        remaining = decoder.unused_data
    return bytes(output)

def lzma_decompress(data, format=_lzma.FORMAT_AUTO, memlimit=None, filters=None):
    # RAW doesn't accept memlimit; explicitly constrain attacker supplied dict_size.
    if filters and any(f.get('dict_size', 0) > 64*1024*1024 for f in filters):
        raise DecodeLimitExceeded('LZMA dictionary memory limit exceeded')
    try:
        return _limited_stream(data, lambda: _lzma.LZMADecompressor(format=format, memlimit=None if format == _lzma.FORMAT_RAW else min(memlimit or 64*1024*1024, 64*1024*1024), filters=filters))
    except EOFError as exc:
        raise _lzma.LZMAError(str(exc)) from exc

def bz2_decompress(data):
    return _limited_stream(data, _bz2.BZ2Decompressor)

gzip = _Proxy(_gzip, decompress=gzip_decompress)
zlib = _Proxy(_zlib, decompress=zlib_decompress, decompressobj=BoundedZlib)
lzma = _Proxy(_lzma, decompress=lzma_decompress)
bz2 = _Proxy(_bz2, decompress=bz2_decompress)

# Optional codecs remain optional. Resolve lazily so installations without them
# preserve their existing plugin availability behavior.
def _cap(data):
    check_input(data, external=False)
    return min(MAX_OUTPUT, max(1024, len(data)*MAX_RATIO))

def brotli_decompress(data):
    import brotli as native
    cap = _cap(data)
    decoder = native.Decompressor()
    out = decoder.process(data, output_buffer_limit=cap+1)
    if len(out) > cap or not decoder.can_accept_more_data():
        raise DecodeLimitExceeded('Brotli output/ratio limit exceeded')
    if not decoder.is_finished():
        raise native.error('Incomplete Brotli stream')
    charge(len(out))
    return out

def snappy_decompress(data, *args, **kwargs):
    import snappy as native
    cap = _cap(data)
    # Raw Snappy begins with a varint uncompressed length; check before allocation.
    declared = 0
    for i, byte in enumerate(data[:5]):
        declared |= (byte & 127) << (7*i)
        if byte < 128:
            break
    else:
        raise ValueError('Invalid Snappy length prefix')
    if declared > cap:
        raise DecodeLimitExceeded('Snappy output/ratio limit exceeded')
    out = native.decompress(data, *args, **kwargs)
    if len(out) > cap:
        raise DecodeLimitExceeded('Snappy output limit exceeded')
    charge(len(out))
    return out

def lz4_frame_decompress(data, **kwargs):
    import lz4.frame as native
    out = _limited_stream(data, native.LZ4FrameDecompressor)
    return bytearray(out) if kwargs.get('return_bytearray') else out

def lz4_block_decompress(data, uncompressed_size=-1, **kwargs):
    import lz4.block as native
    cap = _cap(data)
    if uncompressed_size < 0:
        if len(data) < 4:
            raise ValueError('Missing LZ4 size prefix')
        declared = int.from_bytes(data[:4], 'little')
    else:
        declared = uncompressed_size
    if declared > cap:
        raise DecodeLimitExceeded('LZ4 output/ratio limit exceeded')
    out = native.decompress(data, uncompressed_size=uncompressed_size, **kwargs)
    charge(len(out))
    return out

class BoundedZstd:
    def __init__(self, *args, **kwargs):
        import zstandard as native
        self._args, self._kwargs = args, kwargs
        self._native = native
    def decompress(self, data, **kwargs):
        cap = _cap(data)
        params = self._native.get_frame_parameters(data)
        if params.window_size > 64*1024*1024:
            raise DecodeLimitExceeded('Zstandard window memory limit exceeded')
        declared = params.content_size
        if declared not in (self._native.CONTENTSIZE_UNKNOWN, self._native.CONTENTSIZE_ERROR) and declared > cap:
            raise DecodeLimitExceeded('Zstandard output/ratio limit exceeded')
        decoder = self._native.ZstdDecompressor(*self._args, **self._kwargs)
        # Known size validated first: max_output_size alone ignores known sizes.
        out = decoder.decompress(data, max_output_size=cap)
        charge(len(out))
        return out


def __getattr__(name):
    import importlib
    modules = {'brotli':('brotli', {'decompress':brotli_decompress}),
               'snappy':('snappy', {'decompress':snappy_decompress}),
               'zstandard':('zstandard', {'ZstdDecompressor':BoundedZstd}),
               'lz4frame':('lz4.frame', {'decompress':lz4_frame_decompress}),
               'lz4block':('lz4.block', {'decompress':lz4_block_decompress})}
    if name not in modules:
        raise AttributeError(name)
    module, overrides = modules[name]
    value = _Proxy(importlib.import_module(module), **overrides)
    globals()[name] = value
    return value
