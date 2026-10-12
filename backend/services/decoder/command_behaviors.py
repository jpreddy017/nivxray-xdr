"""Bounded command evidence rules. Findings describe syntax, never execution/intent.

Reuse the existing lossless tokenizer to mask strings, variables and comments.
API names inside displayed text are not executable tokens. Compound rules require
multiple code observations in the same artifact and retain exact source spans.
"""
import re
from engine.parsers.powershell_parser import _tokenize

RULES=(
 ('expression_evaluation',r'(?i)(?:^|[;|]\s*|\()\s*(?:IEX|Invoke-Expression)\s+', 'Expression-evaluation command syntax is present.'),
 ('network_retrieval',r'(?i)(?:\bDownload(?:String|File)\s*\(|(?:^|[;|(]\s*)\s*(?:Invoke-WebRequest|iwr|curl|wget)\s+)', 'Network-retrieval command/API syntax is present.'),
 ('process_launch',r'(?i)(?:^|[;|]\s*)\s*Start-Process\s+', 'Process-launch command syntax is present.'),
 ('output_display',r'(?i)(?:^|[;|]\s*)\s*(?:Write-Output|Write-Host|echo)\b', 'Output/display command syntax is present.'),
 ('scheduled_task_creation',r'(?i)(?:^|[;|]\s*)\s*schtasks(?:\.exe)?\s+/create\b', 'Scheduled-task creation syntax is present; persistence intent is not established.'),
 ('registry_autorun_write',r'(?i)(?:^|[;|]\s*)\s*reg(?:\.exe)?\s+add\s+HK(?:CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:\s|\\)', 'A registry autorun write command is present; authorization and intent require context.'),
 ('process_dump_indicator',r'(?i)(?:^|[;|]\s*)\s*rundll32(?:\.exe)?\s+comsvcs\.dll\s*,?\s*MiniDump\b', 'A process-dump API invocation is indicated; credential access depends on the target process.'),
 ('security_setting_change',r'(?i)(?:^|[;|(]\s*)\s*Set-MpPreference\s+-DisableRealtimeMonitoring\b', 'A security-monitoring setting change is requested; the effective value and authorization need validation.'),
 ('virtual_memory_api',r'(?i)(?:::|\.)VirtualAlloc(?:Ex)?\s*\(', 'A virtual-memory allocation API reference is present.'),
 ('process_memory_write',r'(?i)(?:::|\.)WriteProcessMemory\s*\(', 'A process-memory write API reference is present.'),
 ('remote_thread_api',r'(?i)(?:::|\.)CreateRemoteThread(?:Ex)?\s*\(', 'A remote-thread API reference is present.'),
)

def findings(text,evidence_id):
    if len(text.encode())>131072:return []
    masked=list(text)
    for token in _tokenize(text):
        if token.kind in {'STR_SQ','STR_DQ','HERE_SQ','HERE_DQ','LINE_COMMENT','BLOCK_COMMENT','VAR','VAR_SCOPED','VAR_BRACE'}:
            masked[token.start:token.end]=' '* (token.end-token.start)
    code=''.join(masked)
    cmd_executable=re.match(r'(?i)^\s*(?:"(?:[^"\r\n]*[\\/])?cmd(?:\.exe)?"|(?:[^\s"\r\n]*[\\/])?cmd(?:\.exe)?)\s+',text)
    cmd_prefix=(re.match(r'(?i)(?:/[a-z]+(?::[^\s]+)?\s+)*?/(?:c|k)\s+',text[cmd_executable.end():]) if cmd_executable else None)
    cmd_end=cmd_executable.end()+cmd_prefix.end() if cmd_prefix else 0
    if cmd_prefix:
        masked[:cmd_end]=' '*cmd_end
        code=''.join(masked)
    # Unquoted display arguments are data too. Preserve only explicitly
    # parenthesized argument expressions, which can contain real API syntax.
    for display in re.finditer(r'(?i)(?:^|[;|])\s*(?:echo|Write-Output|Write-Host)\b(?P<args>[^;|]*)',code):
        lo,hi=display.span('args')
        argument_code=code[lo:hi]
        masked[lo:hi]=' '*(hi-lo)
        # Only balanced argument groups introduce expression mode. Bare tokens
        # after a group remain display data, including member-like spelling.
        index=0
        while index<len(argument_code):
            if argument_code[index]=='(' and (index==0 or argument_code[index-1].isspace()):
                start=index;depth=1;index+=1
                while index<len(argument_code) and depth:
                    depth += (argument_code[index]=='(')-(argument_code[index]==')')
                    index+=1
                if not depth:masked[lo+start:lo+index]=argument_code[start:index]
            else:index+=1
    code=''.join(masked)
    out=[]
    for kind,pattern,explanation in RULES:
        if cmd_executable and kind in {'virtual_memory_api','process_memory_write','remote_thread_api','expression_evaluation','security_setting_change'}:
            continue
        m=re.search(pattern,code)
        if m:
            out.append(dict(kind=kind,explanation=explanation+' Runtime execution is not established.',evidence_id=evidence_id,match=text[m.start():m.end()],start=m.start(),end=m.end(),basis='observed_syntax',execution_proven=False))
    by_kind={f['kind']:f for f in out}
    def compound(kind,parts,explanation):
        if all(p in by_kind for p in parts):
            spans=[{'start':by_kind[p]['start'],'end':by_kind[p]['end'],'kind':p} for p in parts]
            lo,hi=min(s['start'] for s in spans),max(s['end'] for s in spans)
            out.append(dict(kind=kind,explanation=explanation,evidence_id=evidence_id,match=text[lo:hi],start=lo,end=hi,basis='correlated_syntax',supporting_spans=spans,execution_proven=False))
    # Require explicit nested/pipeline retrieval-to-IEX shape, not two unrelated
    # commands somewhere in the script. Aliases are recognized, never executed.
    if re.search(r'(?i)(?:^|[;|])\s*(?:IEX|Invoke-Expression)\s+\([^;]*\b(?:Invoke-WebRequest|iwr|DownloadString)\b',code):
        compound('download_and_evaluate',['network_retrieval','expression_evaluation'],'A retrieval expression is supplied to expression evaluation; successful download or execution is not established.')
    compound('injection_api_chain',['virtual_memory_api','process_memory_write','remote_thread_api'],'Memory allocation, process-memory writing and remote-thread API references coexist. This is an injection-related indicator chain, not proof of injection or malicious intent.')
    return out[:16]
