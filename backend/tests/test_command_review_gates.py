"""Independent review counterexamples: no script execution or live services."""
import pytest
from services.decoder.automatic import analyze,replay_recipe
from services.decoder.powershell_constants import reconstruct
from decoders.ioc_extractor import IocExtractor,_extract_all
from engine.models import AnalysisContext

@pytest.mark.parametrize('source',[
 'Write-Output (1)+2', "Write-Output ('a')+'b'",
 "Write-Output ('[{0}]' -f 'x') + 'y'", "Write-Output ('a') -join 'b'",
 "Write-Host (1,2) | ForEach-Object {[char]($_+64)}",
 '$x=1+2;$y="c""', '$x=1+2;Write-Output "c""',
 "Write-Output (([char[]](65,66),67) -join '')",
 'Write-Output 2+2',"Write-Output 'a'+'b'", "$x=4;Write-Output $x+2",
 "Write-Host 'a'+'b'","echo 'a'+'b'","bash -c 'echo hi'+'x'",
 "$x='a';Write-Output ${x", "$x='a';Write-Output ${x+2}",
 "'Write-Output' 1+2", "Write-Output (1,2+3)",
])
def test_argument_foreign_and_invalid_scope_never_promoted(source):
    r=analyze(source)
    assert not r['canonical_decoded_artifact']['promoted']
    assert r['original_command']==source
    assert r['final_recoverable']['value']==source

@pytest.mark.parametrize('source,expected',[
 ("Write-Output ('[{0}]' -f 'x' + 'y')","Write-Output '[x]y'"),
 ("Write-Output (('{0}' -f 'a') + 'b')","Write-Output 'ab'"),
 ("Write-Output (2+2)","Write-Output 4"),
 ("$x='a';Write-Output ${x}","$x='a';Write-Output 'a'"),
 ("Write-Output ('{0}/{1}' -f 'a','b' + '/c')","Write-Output 'a/b/c'"),
])
def test_supported_expression_modes_and_precedence(source,expected):
    r=analyze(source)
    assert r['canonical_decoded_artifact']['text']==expected
    for c in r['candidates']:assert replay_recipe(source,c['recipe'])==c['payload']

@pytest.mark.parametrize('source',[
 'Write-Output (1) [Native]::WriteProcessMemory()',
 'cmd /c echo [Native]::VirtualAlloc() [Native]::WriteProcessMemory() [Native]::CreateRemoteThread()',
 'cmd /d /c echo [Native]::VirtualAlloc() [Native]::WriteProcessMemory() [Native]::CreateRemoteThread()',
 r'C:\Windows\System32\cmd.exe /c echo [Native]::VirtualAlloc() [Native]::WriteProcessMemory() [Native]::CreateRemoteThread()',
 r'"C:\Windows\System32\cmd.exe" /d /c echo [Native]::VirtualAlloc() [Native]::WriteProcessMemory() [Native]::CreateRemoteThread()',

 'echo Set-MpPreference -DisableRealtimeMonitoring $false',
 r'echo reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v demo',
 'echo comsvcs.dll MiniDump',
 'echo VirtualAlloc() WriteProcessMemory() CreateRemoteThread()',
 'Write-Output VirtualAlloc() WriteProcessMemory() CreateRemoteThread()',
])
def test_unquoted_display_arguments_are_not_invocations(source):
    assert all(b['kind']=='output_display' for b in analyze(source)['behaviors'])


def test_actual_security_command_still_observed():
    r=analyze('Set-MpPreference -DisableRealtimeMonitoring $true')
    assert any(b['kind']=='security_setting_change' for b in r['behaviors'])
    assert r['mitre']==[]


def test_structured_ipv4_metadata_does_not_invalidate_ioc_result():
    source='http://example.invalid/demo 203.0.113.42 demo@example.invalid MD5:5d41402abc4b2a76b9719d911017c592'
    diagnostics=_extract_all(source)
    assert isinstance(diagnostics['_entity_classifications'][0],dict)
    result=IocExtractor().decode(source,{},AnalysisContext())
    assert result.iocs['urls']==['http://example.invalid/demo']
    assert result.iocs['ips']==['203.0.113.42']
    assert result.iocs['emails']==['demo@example.invalid']
    assert result.iocs['md5']==['5d41402abc4b2a76b9719d911017c592']
    assert all(isinstance(item,str) for values in result.iocs.values() for item in values)


def test_old_valid_literal_recipe_has_typed_equivalence_proof():
    source="('a'+'b')"
    r=analyze(source)
    old=next(c for c in r['candidates'] if c['recipe'][0]['op']=='powershell.literal_fold')
    assert replay_recipe(source,old['recipe'])==old['payload']


def test_valid_escaped_double_quote_is_not_rejected_as_unterminated():
    result=reconstruct('$x=1+2;$y="a"""')
    assert result is not None
    assert result[0]=='$x=3;$y="a"""'


def test_parenthesized_api_expression_retains_real_syntax_observation():
    result=analyze('Write-Output ([Native]::WriteProcessMemory())')
    assert any(b['kind']=='process_memory_write' for b in result['behaviors'])
