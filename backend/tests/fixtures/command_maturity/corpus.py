"""Harmless generated encodings with explicit literal oracles; no script runtime."""
import base64,gzip,zlib

def cases():
    b64=lambda b:base64.b64encode(b).decode()
    rows=[]
    def add(name,source,expected=None,policy='full',behavior=None):
        rows.append(dict(name=name,input=source,expected=expected,policy=policy,behavior=behavior))
    script="Write-Output 'hello'"
    for name,raw in [('utf8',script.encode()),('utf16le',script.encode('utf-16le')),('gzip',gzip.compress(script.encode(),mtime=0)),('zlib',zlib.compress(script.encode()))]:
        add(name,b64(raw),script)
    add('nested',b64(gzip.compress(b64(script.encode('utf-16le')).encode(),mtime=0)),script)
    add('encodedcommand','powershell -enc '+b64(script.encode('utf-16le')),script)
    add('concat',"Write-Output ('he'+'llo')",script)
    add('char_add',"Write-Output ([char]104+[char]101+[char]108+[char]108+[char]111)",script)
    add('frombase64_ast',"Write-Output ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGVsbG8=')))",script)
    add('frombase64_variable',"$b='aGVsbG8='; Write-Output ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))","$b='aGVsbG8='; Write-Output 'hello'")
    add('char_array',"Write-Output (-join [char[]](104,101,108,108,111))",script)
    add('array_join',"Write-Output (('he','llo') -join '')",script)
    add('format',"Write-Output ('{1}{0}' -f 'llo','he')",script)
    add('variables',"$a='he'; $b='llo'; Write-Output ($a+$b)","$a='he'; $b='llo'; Write-Output 'hello'")
    add('variable_format',"$a='hello'; Write-Output ('{0}!' -f $a)","$a='hello'; Write-Output 'hello!'")
    for name,operator,key,encoded in [('xor','-bxor',7,[ord(c)^7 for c in 'hello']),('subtract','-',3,[ord(c)+3 for c in 'hello']),('add','+',3,[ord(c)-3 for c in 'hello'])]:
        src="Write-Output (-join ("+','.join(map(str,encoded))+" | ForEach-Object { [char]($_ "+operator+' '+str(key)+") }))"
        add(name,src,script)
    add('hex_array',"Write-Output (-join [char[]](0x68,0x65,0x6c,0x6c,0x6f))",script)
    add('cmd_carets','cmd /c ec^ho hello','echo hello')
    add('cmd_nested','cmd /c powershell -enc '+b64(script.encode('utf-16le')),script)
    add('cmd_delayed','cmd /v:on /c "set x=hello&&echo !x!"','cmd /v:on /c "set x=hello&&echo hello"')
    add('cmd_percent','cmd /c "set x=hello&&echo %x%"',policy='refuse')
    add('cmd_unsafe','cmd /v:on /c "set x=hello&whoami&&echo !x!"',policy='refuse')
    add('embedded',"echo prefix; [Convert]::FromBase64String('"+b64(script.encode())+"'); echo suffix",script,'partial')
    for name,src in [('unknown_variable','Write-Output $env:PATH'),('dynamic_call','IEX (Get-Content unknown.ps1)'),('loop_side_effect',"Write-Output (-join (104,101 | ForEach-Object { Start-Process anything; [char]$_ }))"),('unknown_key',"Write-Output (-join (111,98 | ForEach-Object { [char]($_ -bxor $key) }))"),('encrypted','[AES]::Decrypt($cipher,$key)'),('malformed',"Write-Output ('abc"),('branch',"$a='hello'; if($x){$a='bye'}; Write-Output $a"),('mixed_type',"Write-Output ('x'+1)")]:
        add(name,src,policy='refuse')
    add('truncated_gzip',b64(gzip.compress(script.encode(),mtime=0)[:-4]),policy='refuse')
    add('plain_admin','Get-Service',policy='plain')
    add('plain_output',script,policy='plain')
    add('quoted_behavior',"Write-Output 'IEX DownloadString VirtualAlloc schtasks'",policy='plain',behavior='output_only')
    add('download_expression',"IEX (Invoke-WebRequest 'https://example.invalid/hello.ps1')",policy='refuse',behavior='download_and_evaluate')
    add('task',r'schtasks /create /tn Demo /tr "notepad.exe" /sc ONLOGON',policy='plain',behavior='scheduled_task_creation')
    add('run_key',r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Demo /d notepad.exe',policy='plain',behavior='registry_autorun_write')
    add('credential',r'rundll32.exe comsvcs.dll, MiniDump 123 C:\Temp\demo.dmp full',policy='plain',behavior='process_dump_indicator')
    add('injection',"[Native]::VirtualAlloc(); [Native]::WriteProcessMemory(); [Native]::CreateRemoteThread()",policy='plain',behavior='injection_api_chain')
    add('defense','Set-MpPreference -DisableRealtimeMonitoring $true',policy='refuse',behavior='security_setting_change')
    return rows
