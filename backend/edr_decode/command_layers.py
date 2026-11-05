"""Bounded static extraction of literal payloads; never evaluates PowerShell."""
import base64
import hashlib
import ipaddress
import re
import time
from .indicators import extract
from .recipes import MAX_BYTES, run_recipe
from .discovery import _operations


def recover_layers(command, *, max_nodes=32, max_depth=12):
    if not isinstance(command, str) or len(command.encode()) > 65536:
        raise ValueError('bounded command required')
    if not 1 <= max_nodes <= 64 or not 1 <= max_depth <= 16:
        raise ValueError('invalid budget')
    queue = [(command.encode(), None, 0, None)]
    layers, failures, seen, indicators = [], [], set(), set()
    indicator_sources = {}
    start = time.monotonic()
    limited = False
    while queue:
        data, parent, depth, pending_xor = queue.pop(0)
        if time.monotonic() - start > 1 or len(layers) >= max_nodes:
            limited = True
            break
        text = data.decode('utf-8', errors='replace')
        for indicator in extract(text):
            indicators.add(indicator)
            indicator_sources.setdefault(indicator,set()).add(parent)
        jobs = []
        if pending_xor is not None:
            jobs.append((data, [{'operation':'xor', 'key_hex':f'{pending_xor:02x}'}], None, None))
        else:
            jobs.extend((data, [{'operation':op}], None, None) for op in _operations(data))
            for match in re.finditer(r'(?i)(?<![\w-])-(?:enc|encodedcommand)\s+["\']?([A-Za-z0-9+/]+={0,2})', text):
                jobs.append((match[1].encode(), [{'operation':'base64'}, {'operation':'utf16le'}], match.span(1), None))
            pattern = r'''(?i)(?:(\$\w+)\s*=\s*)?\[(?:System\.)?Convert\]::FromBase64String\(\s*(['"])([A-Za-z0-9+/]+={0,2})\2\s*\)'''
            for match in re.finditer(pattern, text):
                key = None
                if match[1]:
                    var = re.escape(match[1])
                    # Only the explicit same-variable, same-index byte loop is supported.
                    loop = (r'for\s*\(\s*(\$\w+)\s*=\s*0\s*;\s*\1\s*-lt\s*'+var+
                            r'\.Count\s*;\s*\1\+\+\s*\)\s*\{\s*'+var+
                            r'\[\1\]\s*=\s*'+var+r'\[\1\]\s*-bxor\s*(\d{1,3})\s*;?\s*\}')
                    found = re.search(loop, text[match.end():], re.I)
                    if found and int(found[2]) <= 255: key = int(found[2])
                jobs.append((match[3].encode(), [{'operation':'base64'}], match.span(3), key))
        if depth >= max_depth:
            limited |= bool(jobs)
            continue
        for source, steps, span, key in jobs:
            if len(layers) >= max_nodes:
                limited = True
                break
            result = run_recipe(source, steps)
            if result['status'] != 'completed':
                failures.append({'parent':parent, 'operations':steps, 'reason':result['failure']['reason']})
                continue
            output = base64.b64decode(result['output_base64'])
            identity = (result['output_sha256'], key)
            if identity in seen: continue
            seen.add(identity)
            layer_id = len(layers)
            layers.append({'id':layer_id, 'parent':parent, 'operations':steps,
                           'source_span':span, 'span_units':'decoded_parent_characters',
                           'output_sha256':result['output_sha256'], 'output_bytes':len(output),
                           'output_base64':result['output_base64'],
                           'preview':output.decode('utf-8',errors='replace')[:4000]})
            queue.append((output, layer_id, depth+1, key))
    return {'status':'budget_limited' if limited else 'partial' if failures else 'supported_layers_recovered' if layers else 'no_supported_layers',
            'layers':layers, 'failed_transforms':failures,
            'indicators':[{'type':kind,'value':v,'reputation':'not_queried',
                           'source_layers':sorted(indicator_sources[(kind,v)],key=lambda x:-1 if x is None else x)} for kind,v in sorted(indicators)],
            'executed':False, 'completeness':'Not proof of full deobfuscation; only supported literal transforms are recovered.'}

