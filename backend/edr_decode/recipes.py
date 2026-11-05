"""Offline, explicit byte recipes. No execution, network, or guessed decryption.

This is a versioned native format, not a CyberChef recipe interpreter. Automatic
candidate selection belongs to the orchestrator; success here proves only that
requested transformations completed, not that the result is benign or correct.
"""
import base64
import binascii
import hashlib
import re
import zlib
from urllib.parse import unquote_to_bytes

VERSION = 'edr-byte-recipe-v1'
OPERATIONS = ('base64', 'base64url', 'hex', 'percent', 'gzip', 'zlib',
              'deflate', 'utf16le', 'utf16be', 'xor')
MAX_BYTES = 1024 * 1024
MAX_STEPS = 16


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _inflate(data, window):
    decoder = zlib.decompressobj(window)
    output = decoder.decompress(data, MAX_BYTES + 1)
    if len(output) > MAX_BYTES or decoder.unconsumed_tail:
        raise ValueError('output_limit')
    if not decoder.eof:
        raise ValueError('incomplete_compressed_stream')
    if decoder.unused_data:
        raise ValueError('trailing_compressed_data')
    return output


def _step(data, step):
    op = step['operation']
    if op in ('base64', 'base64url'):
        pattern = rb'[A-Za-z0-9+/]*={0,2}' if op == 'base64' else rb'[A-Za-z0-9_-]*={0,2}'
        if not re.fullmatch(pattern, data) or len(data) % 4:
            raise ValueError('invalid_base64')
        result = base64.b64decode(data, altchars=b'-_' if op == 'base64url' else None, validate=True)
        canonical = base64.urlsafe_b64encode(result) if op == 'base64url' else base64.b64encode(result)
        if canonical != data:
            raise ValueError('noncanonical_base64')
        return result
    if op == 'hex':
        return binascii.unhexlify(data)
    if op == 'percent':
        if re.search(rb'%(?![0-9A-Fa-f]{2})', data):
            raise ValueError('invalid_percent_escape')
        return unquote_to_bytes(data)
    if op in ('gzip', 'zlib', 'deflate'):
        return _inflate(data, {'gzip':31, 'zlib':15, 'deflate':-15}[op])
    if op in ('utf16le', 'utf16be'):
        return data.decode('utf-16-le' if op == 'utf16le' else 'utf-16-be', errors='strict').encode('utf-8')
    key = bytes.fromhex(step['key_hex'])
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def validate_steps(steps):
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise ValueError('recipe requires 1..16 steps')
    # Validate the entire plan before processing; reject unknown/ignored options.
    for step in steps:
        if not isinstance(step, dict) or step.get('operation') not in OPERATIONS:
            raise ValueError('unsupported operation')
        expected = {'operation', 'key_hex'} if step['operation'] == 'xor' else {'operation'}
        if set(step) != expected:
            raise ValueError('unexpected or missing arguments')
        if step['operation'] == 'xor':
            key = step['key_hex']
            if not isinstance(key, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,256}', key):
                raise ValueError('explicit XOR key required, 1..256 bytes')


def run_recipe(data, steps):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError('bytes input within limit required')
    validate_steps(steps)
    original_hash = _hash(data)
    trace = []
    status = 'completed'
    failure = None
    for index, step in enumerate(steps):
        entry = {'step':index + 1, 'operation':step['operation'],
                 'input_sha256':_hash(data), 'input_bytes':len(data)}
        try:
            result = _step(data, step)
            if len(result) > MAX_BYTES:
                raise ValueError('output_limit')
        except (ValueError, binascii.Error, UnicodeError, zlib.error):
            # Never leak source bytes through exception messages.
            entry['status'] = 'failed'
            trace.append(entry)
            status = 'partial' if index else 'failed'
            failure = {'step':index + 1, 'reason':'invalid_input_or_output_limit'}
            break
        entry.update(status='completed', output_sha256=_hash(result), output_bytes=len(result))
        trace.append(entry)
        data = result
    return {'schema_version':VERSION, 'status':status, 'failure':failure,
            'recipe':[dict(s) for s in steps], 'input_sha256':original_hash,
            'output_sha256':_hash(data), 'output_base64':base64.b64encode(data).decode('ascii'),
            'trace':trace, 'executed':False, 'verdict':'not_assessed'}
