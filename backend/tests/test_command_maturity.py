"""Constant semantics, refusal, provenance and typed behavior acceptance."""
import sys,random
from pathlib import Path
import pytest
from services.decoder.automatic import analyze,replay_recipe,digest
from services.decoder.powershell_constants import reconstruct
sys.path.insert(0,str(Path(__file__).parent/'fixtures/command_maturity'))
from corpus import cases

@pytest.mark.parametrize('case',cases(),ids=lambda c:c['name'])
def test_benchmark_oracle(case):
    r=analyze(case['input']);canon=r['canonical_decoded_artifact']
    assert r['original_command']==case['input']
    if case['policy']=='full':
        assert r['final_recoverable']['value']==case['expected']
        assert canon['text']==case['expected'] and canon['promoted']
    elif case['policy']=='partial':
        assert not canon['promoted']
        assert any(c['payload']['value']==case['expected'] for c in r['candidates'])
    else:assert not canon['promoted']
    for candidate in r['candidates']:
        assert replay_recipe(case['input'],candidate['recipe'])==candidate['payload']
        for layer in candidate['layers']:
            assert layer['provenance']['execution'] is False
    for b in r['behaviors']:
        text=next(t for t in [r['original_command']]+[p['output'] for c in r['candidates'] for p in c['layers'] if p['output_format']=='text'] if 'sha256:'+digest(t)==b['evidence_id'])
        assert text[b['start']:b['end']]==b['match']
        assert b['execution_proven'] is False
    if case['behavior']=='output_only':assert all(b['kind']=='output_display' for b in r['behaviors'])
    elif case['behavior']:assert any(b['kind']==case['behavior'] for b in r['behaviors'])
    assert r['mitre']==[] and r['execution'] is False

@pytest.mark.parametrize('source',[
 "Write-Output ('x'+1)","Write-Output (1+'x')", "Write-Output (1/0)",
 "Write-Output ([char]55296)","Write-Output ([byte]256)",
 "Write-Output ('{0.__class__}' -f 'x')", "Write-Output ('{999999}' -f 'x')",
 "$a='one'; Set-Variable a two; Write-Output $a", "$a='one'; & $a", "$a='one'; $a++ ; Write-Output $a",
 "$global:a='x';Write-Output $global:a", "$a='one'; function change{$a='two'};Write-Output $a",
 "Write-Output (-join (65,66 | ForEach-Object { [char]$_; Start-Process nope }))",
 "Write-Output ('unclosed", "Write-Output (2147483647+1)",
])
def test_unsupported_ast_never_invents(source):
    assert reconstruct(source) is None
    r=analyze(source)
    assert not r['canonical_decoded_artifact']['promoted']

@pytest.mark.parametrize('seed',range(20))
def test_generated_map_oracles(seed):
    rng=random.Random(seed)
    value=''.join(rng.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(15))
    key=rng.randrange(1,31)
    for op,encode in [('-bxor',lambda n:n^key),('-',lambda n:n+key),('+',lambda n:n-key)]:
        array=','.join(str(encode(ord(c))) for c in value)
        source=f"Write-Output (-join ({array} | ForEach-Object {{[char]($_ {op} {key})}}))"
        r=analyze(source)
        assert r['canonical_decoded_artifact']['text']=="Write-Output '"+value+"'"
        assert replay_recipe(source,r['candidates'][0]['recipe'])==r['final_recoverable']

@pytest.mark.parametrize('source',[
 "Write-Output 'IEX DownloadString VirtualAlloc CreateRemoteThread'",
 "# IEX (DownloadString())\nGet-Service", "Write-Output \"schtasks /create\"", "$VirtualAlloc='example';Write-Output $VirtualAlloc",
])
def test_data_and_comments_do_not_become_risk_behaviors(source):
    assert all(b['kind']=='output_display' for b in analyze(source)['behaviors'])


def test_symbolic_search_cannot_enlarge_resource_profile():
    r=analyze('Write-Output ('+'('*30+"'x'"+')'*30+')')
    assert not r['canonical_decoded_artifact']['promoted']
    assert reconstruct('Write-Output (-join [char[]]('+','.join(['65']*513)+'))') is None
    assert r['limits']['input_bytes']==16384 and r['limits']['nodes']==64


def test_join_and_format_limits_are_checked_before_expansion():
    from services.decoder.powershell_constants import safe_join,Unsupported
    with pytest.raises(Unsupported):safe_join(['a'*1000]*512)
    source="$a='"+'a'*1000+"';Write-Output (-join ("+','.join(['1']*300)+" | ForEach-Object {$a}))"
    assert reconstruct(source) is None
    assert not analyze(source)['canonical_decoded_artifact']['promoted']
