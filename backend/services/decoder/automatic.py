"""Bounded candidate exploration owned by Universal Decoder (no runtime bridges).

All transformations are static. Ranking chooses a display candidate, never proves
execution, maliciousness, or decryption. Legacy decode() remains compatible.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes, urlsplit

from .base.base64_codec import decode_base64_candidate
from .base.compression import inflate_bounded
from .base.encoding import _DECODERS
from .types import Capability, CapabilityKind, DecodedLayer, Provenance, now_iso
from . import cmd, powershell

VERSION = "1.0.1-auto"
MAX_INPUT = 16384
MAX_OUTPUT = 131072
MAX_TOTAL = 1048576
MAX_NODES = 64
MAX_DEPTH = 12
MAX_RESULTS = 12
MAX_SECONDS = 2.0

_B64 = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_QUOTES = re.compile(r"'[^'\r\n]*'|\"[^\"\r\n]*\"")
_PS_ENC = re.compile(r"(?i)(?<!\S)-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand|ec)\s+(?:[\"'](?P<quoted>[A-Za-z0-9+/=]+)[\"']|(?P<bare>[A-Za-z0-9+/=]+))(?=\s|$|[;&|])")
_PS_CALL = re.compile(r"(?i)\[(?:System\.)?Convert\]\s*::\s*FromBase64String\s*\(\s*(['\"])([A-Za-z0-9+/=]+)\1\s*\)")
_SCRIPT = re.compile(r"(?i)\b(?:write-output|write-host|powershell|pwsh|iex|invoke-expression|invoke-webrequest|start-process|cmd|echo|curl|wget|whoami)\b")
_DYNAMIC = re.compile(r"(?i)\$[\w{(]|%[A-Za-z_][^%\r\n]*%|![A-Za-z_]\w*!|\b(?:AES|RC4|decrypt|GZipStream|DeflateStream)\b|FromBase64String|-(?:join|replace|f)\b|\[char\]|`|'\s*\+|\+\s*'")


def standalone_encodedcommand(text):
    """Only a complete, conservative PS invocation can stand for its child.

    Unknown flags, comments, wrappers and trailing commands remain separate
    evidence. This establishes extraction scope, never execution.
    """
    match = _PS_ENC.search(text)
    return bool(match and re.fullmatch(
        r'(?i)\s*(?:powershell|pwsh)(?:\.exe)?\s+(?:-(?:nop|noprofile|noni|noninteractive)\s+)*',
        text[:match.start()]) and not text[match.end():].strip())


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode('utf-8')).hexdigest()


def wire(value):
    return {"format": "base64" if isinstance(value, bytes) else "text", "value": base64.b64encode(value).decode() if isinstance(value, bytes) else value}


def readable(text):
    return bool(text) and all(c.isprintable() or c in '\r\n\t' for c in text) and not any(0xD800 <= ord(c) <= 0xDFFF for c in text)


def static_folds(text):
    """Use existing PS literal folds only on complete, conservative expressions.

    Quoted token boundaries prevent matching code inside strings. Interpolation,
    comments, escapes and mixed numeric concatenation are deliberately refused.
    """
    if any(s in text for s in ('`', '#', '@"', "@'")):
        return
    token_re = re.compile(r"'[^']*'|\"[^\"]*\"|\[char\]\s*(?:0x[0-9a-f]+|\d+)|\s+|.", re.I | re.S)
    tokens = [m for m in token_re.finditer(text) if not m.group().isspace()]
    def literal(m):
        s = m.group()
        if s[:1] in ('\"', "'") and len(s) >= 2 and s[-1] == s[0]:
            if s[0] == '\"' and '$' in s:
                raise ValueError()
            return s[1:-1]
        if s.lower().startswith('[char]'):
            n = s[6:].strip()
            n = int(n, 16 if n.lower().startswith('0x') else 10)
            if not 0 <= n <= 65535 or 0xD800 <= n <= 0xDFFF:
                raise ValueError()
            return chr(n)
        raise ValueError()
    def expression(i, depth=0):
        if depth > 8 or i >= len(tokens):
            raise ValueError()
        if tokens[i].group() == '(':
            val, j, ops = expression(i + 1, depth + 1)
            if j >= len(tokens) or tokens[j].group() != ')':
                raise ValueError()
            j += 1
        else:
            val, j, ops = literal(tokens[i]), i + 1, 0
        while j < len(tokens) and tokens[j].group() == '+':
            # Atom, not expression: preserve left associativity.
            k = j + 1
            if k < len(tokens) and tokens[k].group() == '(':
                right, end, count = expression(k + 1, depth + 1)
                if end >= len(tokens) or tokens[end].group() != ')':
                    raise ValueError()
                end += 1
            else:
                right, end, count = literal(tokens[k]), k + 1, 0
            val += right
            j, ops = end, ops + count + 1
        return val, j, ops
    i = 0
    while i < len(tokens):
        try:
            value, end, ops = expression(i)
            # Never fold a suffix of an unsupported expression.
            prev = tokens[i - 1].group() if i else ''
            following = tokens[end].group() if end < len(tokens) else ''
            if ops and prev not in ('+', '.') and following not in ('+', '.') and not prev.endswith(("'", '"')) and not following.startswith(("'", '"')) and readable(value):
                start, stop = tokens[i].start(), tokens[end - 1].end()
                chunk = text[start:stop]
                # Reuse established folds for their exact supported grammar.
                old = powershell._run_char_array(chunk, 'auto:literal', 0) if re.fullmatch(r'(?i)(?:\[char\]\d+\s*\+\s*)+\[char\]\d+', chunk) else None
                if old is None and re.fullmatch(r"'[^']*'(?:\s*\+\s*'[^']*')+", chunk):
                    old = powershell._run_string_concat(chunk, 'auto:literal', 0)
                quoted = "'" + value.replace("'", "''") + "'"
                if old is not None and old.output != quoted:
                    raise ValueError()
                yield text[:start] + quoted + text[stop:], {"start": start, "end": stop}, 'powershell.literal_fold'
                return
            i = max(i + 1, end)
        except (ValueError, IndexError):
            i += 1


@dataclass
class Node:
    value: object
    path: list
    reasons: tuple = ()
    hint: str = ''
    embedded: bool = False
    speculative: bool = False


def transitions(node):
    value = node.value
    if isinstance(value, bytes):
        if value.startswith(b'\x1f\x8b') or (len(value) >= 2 and value[0] == 0x78 and int.from_bytes(value[:2], 'big') % 31 == 0):
            out, partial = inflate_bounded(value, max_output=MAX_OUTPUT)
            yield 'gzip' if value.startswith(b'\x1f\x8b') else 'zlib', out, {}, ('Incomplete compression stream or trailing data',) if partial else (), '', False, False
            return
        encs = [node.hint] if node.hint else ['utf-8']
        if not node.hint:
            if value.startswith((b'\xff\xfe', b'\xfe\xff')):
                encs = ['utf-16']
            elif len(value) % 2 == 0 and value:
                if value[1::2].count(0) / (len(value) / 2) > .3:
                    encs = ['utf-16-le']
                elif value[0::2].count(0) / (len(value) / 2) > .3:
                    encs = ['utf-16-be']
        for enc in encs:
            try:
                out = value.decode(enc, errors='strict')
                if readable(out):
                    reasons = ('UTF-16 interpretation has no BOM or zero-byte structure; text meaning is ambiguous',) if enc.startswith('utf-16') and not value.startswith((b'\xff\xfe', b'\xfe\xff')) and b'\0' not in value else ()
                    yield enc, out, {"encoding": enc}, reasons, '', False, False
            except UnicodeError:
                pass
        return
    text = value
    stripped = text.strip()
    is_cmd = bool(re.match(r'(?i)^\s*cmd(?:\.exe)?\s+/(?:c|k)\s+', text)) or any(p['stage'].startswith('cmd.') for p in node.path)
    # Whole-value encodings. Never turn a 32/40/64-hex digest into a payload.
    if len(stripped) >= 8 and _B64.fullmatch(stripped):
        url = '-' in stripped or '_' in stripped
        out = decode_base64_candidate(stripped, urlsafe=url)
        if out is not None:
            yield 'base64url' if url else 'base64', out, {"urlsafe": url}, (), node.hint, False, False
    if re.fullmatch(r'(?:[0-9a-fA-F]{2}[ :\t]*){2,}', stripped):
        digest_shape = len(stripped) in (32, 40, 64) and stripped.isalnum()
        yield 'hex', bytes.fromhex(stripped.replace(':', ' ')), {}, ('Hexadecimal may be a hash rather than encoded text',) if digest_shape else (), '', False, digest_shape
    if re.fullmatch(r'(?:%[0-9a-fA-F]{2}|[^%])*', stripped) and re.search(r'%[0-9a-fA-F]{2}', stripped):
        # Whole URL unescaping is an alternative representation, not script equivalence.
        yield 'url', unquote_to_bytes(stripped), {}, (), '', False, bool(re.search(r'https?://', stripped, re.I))
    for name, fn in _DECODERS:
        signature = {'encoding.unicode_escape': r'\\[uxU][0-9a-fA-F]{2}', 'encoding.html_entities': r'&#(?:x[0-9a-fA-F]+|[0-9]+);', 'encoding.base32': r'^[A-Z2-7]{8,}={0,6}$', 'encoding.base85': r'^<~.*~>$', 'encoding.octal_ascii': r'^(?:\\[0-7]{3})+$', 'encoding.decimal_ascii': r'^\d{2,3}(?:[, ]+\d{2,3}){2,}$'}.get(name)
        if signature and re.search(signature, stripped):
            # Decode only recognized spans: utf8 -> unicode_escape corrupts
            # existing non-ASCII text and also interprets unrelated escapes.
            if name == 'encoding.unicode_escape':
                out = re.sub(r'\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2})', lambda m: chr(int(m.group()[2:], 16)), stripped)
            else:
                out = fn(stripped)
            if out and out != stripped and readable(out):
                yield name, out, {}, (), '', False, bool(_SCRIPT.search(text))
    # Explicit command payloads have source offsets in their immediate parent.
    explicit = []
    if re.search(r'(?i)\b(?:powershell|pwsh)(?:\.exe)?\b', text):
        for m in _PS_ENC.finditer(text):
            group = 'quoted' if m.group('quoted') else 'bare'
            explicit.append(m.span(group))
            yield 'extract.encodedcommand', m.group(group), {"start": m.start(group), "end": m.end(group)}, (), 'utf-16-le', True, False
    for m in _PS_CALL.finditer(text):
        explicit.append(m.span(2))
        yield 'extract.frombase64string', m.group(2), {"start": m.start(2), "end": m.end(2)}, (), '', True, False
    # Isolated literal blobs are candidates only; concatenation fragments are not.
    for m in _QUOTES.finditer(text):
        val = m.group()[1:-1]
        if any(a <= m.start() + 1 < b for a, b in explicit):
            continue
        if text[:m.start()].rstrip().endswith('+') or text[m.end():].lstrip().startswith('+'):
            continue
        if _B64.fullmatch(val) and len(val) >= 16:
            yield 'extract.literal_candidate', val, {"start": m.start()+1, "end": m.end()-1}, ('Literal meaning is not established by a decode operation',), '', True, True
    # Reuse existing format/join folds only when the entire expression is
    # composed of unescaped single-quoted literals (no interpolation).
    safe_literal = r"'[^'\"\r\n]*'"
    format_pattern = safe_literal + r"\s+-f\s+" + safe_literal + r"(?:\s*,\s*" + safe_literal + r")*"
    join_pattern = r"\(\s*" + safe_literal + r"(?:\s*,\s*" + safe_literal + r")+\s*\)\s+-join\s*" + safe_literal
    for pattern, fn, name in ((format_pattern, powershell._run_format_string, 'powershell.format_string_assembly'), (join_pattern, powershell._run_join_split, 'powershell.join_split_fold')):
        if not is_cmd and re.fullmatch(pattern, stripped, re.I):
            folded = fn(stripped, 'auto:literal', 0)
            if folded and readable(folded.output):
                yield name, folded.output, {}, (), '', False, False
    if not is_cmd:
        for out, args, name in static_folds(text):
            yield name, out, args, (), '', False, False
    # Strict CMD wrapper and caret support; do not guess wildcard executables.
    if re.match(r'(?i)^\s*cmd(?:\.exe)?\s+/(?:c|k)\s+', text) and not any(s in text for s in ('%', '!', '\n', '\r', '^^')) and not re.search(r'\^(?![A-Za-z0-9])', text):
        out, peeled, _ = cmd._peel_cmd_wrapper(text)
        if peeled:
            out, _ = cmd.strip_carets_outside_quotes(out)
            yield 'cmd.wrapper_carets', out, {}, (), '', False, False


def layer(parent, op, output, args, index):
    a, b = wire(parent), wire(output)
    cap = Capability(name=op, kind=CapabilityKind.PARSER if op.startswith('extract.') else CapabilityKind.TRANSFORM, language='generic', version=VERSION)
    obj = DecodedLayer(index, op, 'generic', len(parent if isinstance(parent, bytes) else parent.encode()), len(output if isinstance(output, bytes) else output.encode()), a['value'][:64], b['value'], cap, Provenance('sha256:'+digest(parent), op, VERSION, now_iso()), 'MEDIUM', 'Static reconstruction; not execution')
    category = 'extraction' if op.startswith('extract.') else 'compression' if op in ('gzip', 'zlib') else 'obfuscation' if op.startswith(('cmd.', 'powershell.')) else 'encoding'
    return {**obj.to_dict(), 'category': category, 'input': a, 'output_format': b['format'], 'input_sha256': digest(parent), 'output_sha256': digest(output), 'args': args}


def annotations(evidence):
    # Reuse existing IOC rules but retain evidence identity and validated IPs.
    from command_analyzer import extract_iocs
    iocs, behaviors = [], []
    seen = set()
    rules = [(r'(?i)\b(?:IEX|Invoke-Expression)\b', 'An expression-evaluation token is present; its runtime use is not established.'), (r'(?i)\b(?:DownloadString|Invoke-WebRequest|curl|wget)\b', 'A network-retrieval token is present; network contact is not established.'), (r'(?i)\bStart-Process\b', 'A process-launch token is present; launch is not established.'), (r'(?i)\b(?:Write-Output|Write-Host|echo)\b', 'An output/display command token is present; execution is not established.')]
    for text in evidence:
        ref = 'sha256:'+digest(text)
        found = extract_iocs(text)
        found['urls'] = [u.rstrip(');,]') for u in found.get('urls', [])]
        found['file_paths'] = [p for p in found.get('file_paths', []) if not any(p in u for u in found['urls'])]
        for url in found.get('urls', []):
            try:
                host = urlsplit(url).hostname
            except ValueError:
                # Preserve the observed URL string; malformed host is not a domain.
                continue
            if host:
                found.setdefault('domains', []).append(host)
        for kind, vals in found.items():
            vals = [(k, v) for k, vs in vals.items() for v in vs] if isinstance(vals, dict) else [(kind, v) for v in vals]
            for typ, value in vals:
                if typ == 'ips':
                    try: ipaddress.ip_address(value)
                    except ValueError: continue
                key = (typ, value, ref)
                if key not in seen and len(iocs) < 256:
                    seen.add(key)
                    iocs.append({'type': typ, 'value': value, 'evidence_id': ref})
        for pattern, explanation in rules:
            m = re.search(pattern, text)
            if m and len(behaviors) < 64:
                behaviors.append({'explanation': explanation, 'evidence_id': ref, 'match': m.group(), 'start': m.start(), 'end': m.end()})
    return iocs, behaviors


def analyze(text: str):
    if not isinstance(text, str) or not text.strip():
        raise ValueError('Enter a nonempty command line')
    if len(text.encode('utf-8')) > MAX_INPUT:
        raise ValueError('Command exceeds the 16 KiB input limit')
    start = time.monotonic()
    queue = deque([Node(text, [])])
    leaves, seen, warnings = [], set(), []
    nodes, total = 0, 0
    while queue:
        if nodes >= MAX_NODES or time.monotonic() - start >= MAX_SECONDS:
            warnings.append('Candidate or time budget reached; search is incomplete')
            leaves.extend(Node(n.value, n.path, n.reasons + ('Search budget reached',), n.hint, n.embedded, n.speculative) for n in queue)
            break
        node = queue.popleft()
        nodes += 1
        if len(node.path) >= MAX_DEPTH:
            leaves.append(Node(node.value, node.path, node.reasons + ('Depth limit reached',), node.hint, node.embedded, node.speculative))
            continue
        progressed = False
        try:
            for op, out, args, reasons, hint, embedded, speculative in transitions(node):
                size = len(out if isinstance(out, bytes) else out.encode('utf-8'))
                if not size or out == node.value:
                    continue
                if size > MAX_OUTPUT or total + size > MAX_TOTAL or nodes + len(queue) >= MAX_NODES:
                    warnings.append('Output or candidate budget reached; search is incomplete')
                    break
                # Path-local cycles; retain independently sourced identical payloads.
                if digest(out) in [p['input_sha256'] for p in node.path]:
                    continue
                key = (digest(node.value), op, digest(out), str(sorted(args.items())), tuple((p['stage'], str(p['args'])) for p in node.path))
                if key in seen:
                    continue
                seen.add(key)
                total += size
                step = layer(node.value, op, out, args, len(node.path))
                queue.append(Node(out, node.path + [step], node.reasons + reasons, hint, node.embedded or embedded, node.speculative or speculative))
                progressed = True
        except (ValueError, UnicodeError) as exc:
            node = Node(node.value, node.path, node.reasons + (str(exc),), node.hint, node.embedded, node.speculative)
        if not progressed:
            leaves.append(node)
    candidates = []
    for n in leaves:
        if not n.path:
            continue
        reasons = list(n.reasons)
        if isinstance(n.value, bytes):
            reasons.append('Binary output: no supported text encoding/compression; encryption cannot be inferred or decrypted without a key')
        elif _DYNAMIC.search(n.value):
            reasons.append('Runtime-dependent or unsupported expression remains; static evaluation stopped')
        if n.path[-1]['stage'].startswith('extract.'):
            reasons.append('Extracted payload could not be decoded')
        score = (30 if not n.speculative else 0) + (30 if isinstance(n.value, str) and readable(n.value) else 0) + (10 if isinstance(n.value, str) and _SCRIPT.search(n.value) else 0) - len(reasons)*10 - len(n.path)*.1
        candidates.append({'id': 'sha256:'+digest(n.value), 'payload': wire(n.value), 'layers': n.path, 'recipe': [{'op': p['stage'], 'args': p['args'], 'input_sha256': p['input_sha256'], 'output_sha256': p['output_sha256']} for p in n.path], 'score': round(score, 2), 'confidence': 'LOW' if reasons or n.speculative else 'HIGH', 'unresolved': reasons, 'embedded': n.embedded, 'speculative': n.speculative})
    candidates.sort(key=lambda c: (-c['score'], c['id'], str(c['recipe'])))
    if len(candidates) > MAX_RESULTS:
        warnings.append('Result limit reached; additional candidates omitted')
    candidates = candidates[:MAX_RESULTS]
    best = candidates[0] if candidates else None
    plausible = [c for c in candidates if c['payload']['format'] == 'text' and not c['speculative'] and not c['unresolved']]
    alternatives = len({c['id'] for c in plausible}) > 1
    original_dynamic = bool(_DYNAMIC.search(text))
    # An extracted child does not prove that its surrounding script was recovered.
    wrapper_unresolved = bool(best and any(p['stage'].startswith('extract.') and (p['stage'] != 'extract.encodedcommand' or not standalone_encodedcommand(p['input']['value'])) for p in best['layers']))
    if wrapper_unresolved:
        warnings.append('Surrounding script remains separate evidence; recovering an embedded payload does not resolve the wrapper')
    status = 'NOT_REQUIRED'
    if candidates:
        status = 'AMBIGUOUS' if alternatives else 'PARTIALLY_RECOVERED' if warnings or best['unresolved'] or best['speculative'] else 'RECOVERED'
    elif original_dynamic or re.search(r'(?i)^\s*cmd(?:\.exe)?\s+/(?:c|k).*\^', text) or _PS_ENC.search(text) or _B64.fullmatch(text.strip()) or re.search(r'(?i)-(?:enc|encodedcommand)\b|\\[ux][0-9a-f]|%[0-9a-f]{2}', text):
        status = 'UNRECOVERED'
    if not candidates and original_dynamic:
        warnings.append('Runtime-dependent variables, calls or unsupported literal constructions were not evaluated')
    if warnings and status == 'NOT_REQUIRED':
        status = 'LIMIT_REACHED'
    promote = bool(best and status == 'RECOVERED' and best['payload']['format'] == 'text')
    # Only original and actual text artifacts are scanned, never rendered labels or binary base64.
    evidence = [text] + list(dict.fromkeys(p['output'] for c in candidates for p in c['layers'] if p['output_format'] == 'text'))
    iocs, behavior = annotations(evidence)
    reason = {'RECOVERED':'Supported transformations reached a static fixed point; this does not establish execution.', 'AMBIGUOUS':'Multiple plausible recovered artifacts; no single canonical payload selected.', 'PARTIALLY_RECOVERED':'Some evidence recovered; unresolved portions remain.', 'UNRECOVERED':'Recognized encoding/obfuscation could not be safely recovered.', 'NOT_REQUIRED':'No supported encoding or obfuscation identified; this is not a benign verdict.', 'LIMIT_REACHED':'Search stopped at a resource budget.'}[status]
    return {'schema_version':'command-intelligence/1', 'engine':'universal_decoder', 'engine_version':VERSION, 'original_command':text, 'decode_status':status, 'decode_status_reason':reason, 'needs_choice':False, 'confidence':best['confidence'] if best else 'UNDETERMINED', 'unresolved_portions':list(dict.fromkeys(warnings + [reason for c in candidates for reason in c['unresolved']])), 'detected_methods':list(dict.fromkeys(p['stage'] for c in candidates for p in c['layers'])), 'candidates':candidates, 'final_recoverable':best['payload'] if best else wire(text), 'canonical_decoded_artifact':{'promoted':promote, 'text':best['payload']['value'] if promote else None, 'candidate_text':best['payload']['value'] if best and not promote and best['payload']['format']=='text' else None, 'source':'universal_decoder', 'evidence_id':best['id'] if best else None, 'decode_status':status, 'reason':reason}, 'iocs':iocs, 'behaviors':behavior, 'mitre':[], 'mitre_status':'HELD: no ATT&CK promotion or observations', 'warnings':list(dict.fromkeys(warnings)), 'stop_reason':reason, 'limits':{'input_bytes':MAX_INPUT,'output_bytes':MAX_OUTPUT,'total_bytes':MAX_TOTAL,'nodes':MAX_NODES,'depth':MAX_DEPTH,'seconds':MAX_SECONDS}, 'search':{'visited':nodes,'output_bytes':total}, 'static_only':True,'execution':False}


def replay_recipe(original: str, recipe: list):
    """Reproduce a reported recipe; refuse tampered inputs, args, or outputs."""
    if len(original.encode()) > MAX_INPUT or len(recipe) > MAX_DEPTH:
        raise ValueError('Recipe exceeds resource limits')
    node = Node(original, [])
    total = 0
    for item in recipe:
        if digest(node.value) != item['input_sha256']:
            raise ValueError('Recipe input hash mismatch')
        matched = False
        for op, out, args, reasons, hint, embedded, speculative in transitions(node):
            if op == item['op'] and args == item['args'] and digest(out) == item['output_sha256']:
                size = len(out if isinstance(out, bytes) else out.encode())
                total += size
                if size > MAX_OUTPUT or total > MAX_TOTAL:
                    raise ValueError('Recipe output limit')
                node = Node(out, node.path + [layer(node.value, op, out, args, len(node.path))], node.reasons + reasons, hint, embedded, speculative)
                matched = True
                break
        if not matched:
            raise ValueError('Recipe operation/output could not be reproduced')
    return wire(node.value)
