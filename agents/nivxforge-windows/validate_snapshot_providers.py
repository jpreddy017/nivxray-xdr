"""Windows CI smoke gate. Logs metadata only, never collected artifacts."""
import json,os,sys,base64,subprocess
import windows_snapshot as s

if os.name!='nt':
 raise SystemExit('Native collector validation requires Windows')

# Exercise XML field extraction with a harmless synthetic event on native PowerShell.
fixture = s.HELPERS + r"""
$e=[pscustomobject]@{TimeCreated=[datetime]'2026-11-16T12:00:00Z';Id=4104;RecordId=7;LogName='Microsoft-Windows-PowerShell/Operational';UserId='S-1-5-18'}
$e|Add-Member -MemberType ScriptMethod -Name ToXml -Value {return '<Event><EventData><Data Name="ScriptBlockId">fixture-id</Data><Data Name="MessageTotal">2</Data><Data Name="MessageNumber">1</Data><Data Name="ScriptBlockText">Write-Output &quot;test&quot;</Data><Data Name="Path">C:\test\sample.ps1</Data></EventData></Event>'}
PowerShellEventRow $e|ConvertTo-Json -Compress
"""
exe=os.path.join(os.environ['SystemRoot'],'System32','WindowsPowerShell','v1.0','powershell.exe')
r=subprocess.run([exe,'-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(fixture.encode('utf-16le')).decode()],capture_output=True,timeout=15)
assert r.returncode==0,'PowerShell event parser fixture failed'
e=json.loads(r.stdout.decode('utf-8-sig'))
assert e['script_block_id']=='fixture-id' and e['script_block_count']=='2' and e['message_number']=='1'
assert e['script_text']=='Write-Output "test"' and e['script_name']=='sample.ps1' and e['record_id']==7
print('PowerShell event XML fields: PASS')
# Real Windows collection below must retain bounded PowerShell records rather than lose the category.

original=s.CATALOG['os_version']
try:
 s.CATALOG['os_version']=('Bounded fixture',"1..500|ForEach-Object{[pscustomobject]@{index=$_;payload=('x'*5000)}}",False)
 bounded=s.run_query('os_version')
 assert bounded['state']=='PARTIAL' and 0<len(bounded['rows'])<500 and bounded['rows_truncated'],'Byte limit must retain partial evidence'
finally:
 s.CATALOG['os_version']=original
print('Byte-limited partial evidence retention: PASS')
result=s.collect(include_sensitive=True)
summary=[{'id':c['category_id'],'state':c['state'],'rows':c['row_count'],'error_type':c.get('error_type')} for c in result['categories']]
print(json.dumps({'collector_version':s.VERSION,'categories':summary}))
assert len(summary)==41
assert result['collection_limits']['rows_per_category']==10000
for row in next(c for c in result['categories'] if c['category_id']=='running_hashes')['rows']:
 assert 'owner' in row and 'owner_state' in row
by_id={c['id']:c for c in summary}
for key in ('os_version','services','installed_programs','module_processes','hosts','root_certificates','running_hashes','network_processes','powershell_history','logged_in_users'):
 assert by_id[key]['state'] in ('COLLECTED','PARTIAL'),f'{key}: core Windows provider did not collect'
assert not any(c.get('error_type') in ('ParseException','CommandNotFoundException') for c in summary),'Missing command or parser failure'
print('Windows forensic provider smoke: PASS; per-category availability is reported above.')
