"""Observed staging contract mismatch: loopback API only, no live credentials."""
import json
import subprocess
from pathlib import Path
import pytest
from test_command_automatic_api import client
from command_analyzer import analyze_command, classify_behaviors, detect_interpreter, split_pipeline

COMMAND = 'powershell -NoProfile -Command "Write-Output \'NivXRay-Test-123\'"'
CONTRACT = Path(__file__).resolve().parents[2] / 'apps/nivxray-xdr/src/xdr/pages/commandIntelligenceContract.js'

def validate(report, original=COMMAND):
    js = 'import {validateCommandResult} from '+json.dumps(CONTRACT.as_uri())+'; validateCommandResult(JSON.parse(process.argv[1]),JSON.parse(process.argv[2]));'
    return subprocess.run(['node','--input-type=module','-e',js,json.dumps(report),json.dumps(original)],text=True,capture_output=True)

def test_actual_harmless_request_automatic_contract(client):
    c, headers = client
    js = 'import {commandRequest} from '+json.dumps(CONTRACT.as_uri())+'; process.stdout.write(JSON.stringify(commandRequest(JSON.parse(process.argv[1]))));'
    body = json.loads(subprocess.check_output(['node','--input-type=module','-e',js,json.dumps(COMMAND)],text=True))
    assert body == {'input':COMMAND,'automatic':True}
    response = c.post('/api/analyze/command',headers=headers(),json=body)
    assert response.status_code == 200
    r = response.json()
    assert validate(r).returncode == 0
    assert r['schema_version'] == 'command-intelligence/1'
    assert r['decode_status'] == 'NOT_REQUIRED'
    assert r['original_command'] == r['final_recoverable']['value'] == COMMAND
    assert r['behaviors'] == r['iocs'] == r['candidates'] == r['detected_methods'] == []
    assert not r['canonical_decoded_artifact']['promoted']
    assert r['mitre'] == [] and r['static_only'] and not r['execution']

def test_legacy_200_is_rejected_without_fabricating_automatic_evidence(client):
    c, headers = client
    response = c.post('/api/analyze/command',headers=headers(),json={'input':COMMAND})
    assert response.status_code == 200
    r = response.json()
    assert r['original_command'] == COMMAND and 'schema_version' not in r
    failed = validate(r)
    assert failed.returncode != 0
    assert 'compatible automatic analysis report' in failed.stderr
    assert 'schema_version' not in r # no response mutation by validator

@pytest.mark.parametrize('source', [COMMAND,'powershell -c "Write-Output hello"','pwsh -Command "Get-Date"'])
def test_plain_inline_payload_is_not_failed_or_fabricated(source):
    r = analyze_command(source)
    assert r['decode_status'] == 'NOT_REQUIRED'
    assert not r['canonical_decoded_artifact']['promoted']
    assert all(not d['final_output'] for d in r['decode_chains'])

@pytest.mark.parametrize('source',[
 COMMAND,'powershell -NoP -NonInteractive -NoExit -c "Write-Output hello"',
 'powershell -ExecutionPolicy RemoteSigned -Command "Get-Date"',
 'powershell -Command "Write-Output \'-w hidden -ep bypass\'"',
 'powershell -NoProfileExtra -Command "Get-Date"',
 'powershell -File helper.ps1 -w hidden',
 'powershell -NoProfile | echo -ep bypass',
])
def test_legacy_no_benign_or_argument_substring_stealth(source):
    assert 'stealth-flags' not in [b['tag'] for b in classify_behaviors(split_pipeline(source),source,detect_interpreter(source))]

@pytest.mark.parametrize('source',[
 'powershell -WindowStyle Hidden -Command "Get-Date"',
 'powershell -w Hidden -c "Get-Date"',
 'powershell -ExecutionPolicy Bypass -Command "Get-Date"',
 'powershell -ep Unrestricted -c "Get-Date"',
])
def test_explicit_configuration_evidence_retained_without_malicious_verdict(source):
    findings=classify_behaviors(split_pipeline(source),source,detect_interpreter(source))
    finding=next(b for b in findings if b['tag']=='stealth-flags')
    assert 'does not establish malicious intent' in finding['detail']

def test_encoded_command_failure_still_distinguished_from_plain_script():
    r=analyze_command('powershell -EncodedCommand not!base64!')
    assert r['decode_status'] != 'NOT_REQUIRED'
    assert not r['canonical_decoded_artifact']['promoted']
