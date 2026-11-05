"""Static IOC candidates; no DNS resolution or reputation inference.

Only explicit network contexts and visibly defanged domains are candidates.
Dotted identifiers, executable names and file paths are not arbitrary domains.
"""
import ipaddress
import re
from urllib.parse import urlsplit

_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
_DOMAIN = rf'(?:{_LABEL}\.)+[a-z]{{2,63}}'
_DEFANGED_DOMAIN = rf'{_LABEL}(?:\[\.\]|\(\.\)){_LABEL}(?:(?:\[\.\]|\(\.\)|\.){_LABEL})*'

def _refang(text):
    text = re.sub(r'\[\.\]|\(\.\)', '.', text)
    text = re.sub(r'(?i)\bhxxps(?=://)', 'https', text)
    text = re.sub(r'(?i)\bhxxp(?=://)', 'http', text)
    return re.sub(r'(?i)\b(https?|hxxps?)\[:\]//', lambda m: m[1].lower().replace('xx','tt')+'://', text)

def _domain(value):
    value=value.lower().rstrip('.')
    if len(value)>253 or not re.fullmatch(_DOMAIN,value,re.I):return None
    # Common script type/member and executable/file suffixes are not domain proof.
    if value.startswith(('system.','microsoft.')) or value.rsplit('.',1)[-1] in {'exe','dll','ps1','bat','cmd','sys','txt','log','json','xml'}:
        return None
    return value

def extract(text):
    found=set()
    normalized=_refang(text)
    for value in re.findall(r'https?://[^\s\"\'<>`]+',normalized,re.I):
        value=value.rstrip(');,}')
        try:
            parsed=urlsplit(value)
            host=parsed.hostname
            # Reject malformed/out-of-range ports rather than reporting partial URLs.
            parsed.port
        except ValueError:continue
        if host:
            try:address=str(ipaddress.ip_address(host))
            except ValueError:
                # URL context is explicit; .net/.io are legitimate here.
                if not re.fullmatch(_DOMAIN,host,re.I) or len(host)>253:continue
                found.add(('domain',host.lower()))
            else:found.add(('ip',address))
            found.add(('url',value))
    for value in re.findall(r'(?<![\w.:\]])(?:[0-9a-fA-F]*:){2,}[0-9a-fA-F:.]+(?![\w:.])|(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',normalized):
        try:found.add(('ip',str(ipaddress.ip_address(value))))
        except ValueError:pass
    for value in re.findall(r'(?<![\w])(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![\w])',text):
        found.add(('hash',value.lower()))
    # Explicit network command contexts, allowing common switches before the name.
    pattern=rf'''(?ix)\b(?:nslookup|ping|resolve-dnsname|dig)\s+(?:(?:-[a-z][a-z0-9-]*(?:\s+\d+)?|/(?:[a-z]))\s+)*["']?({_DOMAIN})(?![\w.\\/])'''
    for value in re.findall(pattern,normalized):
        # Explicit network context permits all valid alphabetic suffixes.
        if len(value)<=253:found.add(('domain',value.lower()))
    # Deliberately defanged domain literals are strong evidence even without a URL.
    # Keep original source intact; only the lookup candidate is normalized.
    for match in re.finditer(rf'(?i)(?<![\w.\\/])({_DEFANGED_DOMAIN})(?![\w.\\/])',text):
        value=_domain(_refang(match[1]))
        if value:found.add(('domain',value))
    return found
