"""EDR-owned read-only reputation lookups. Keys and transport stay server-side.

No submissions, URL visits, automatic provider consensus, or Workspace dependency.
The host supplies a tenant-authorized transport; this module never obtains keys.
"""
from .reputation_transport import ProviderNotConfigured
from . import abusech
from .reputation_secrets import SecretStoreUnavailable
import asyncio
import base64
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

PROVIDERS=('VirusTotal','Cisco Talos','AbuseIPDB','urlscan.io','AlienVault OTX') + abusech.PROVIDERS


def validate_ioc(kind,value):
    if not isinstance(value,str) or not 1 <= len(value) <= 2048 or any(ord(c)<32 for c in value):
        raise ValueError('invalid IOC')
    if kind=='ip':
        ip=ipaddress.ip_address(value)
        if not ip.is_global: raise ValueError('public IP required for external lookup')
        return str(ip)
    if kind=='hash' and re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})',value):return value.lower()
    if kind=='domain' and re.fullmatch(r'(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}',value):return value.lower()
    if kind=='url':
        u=urlsplit(value)
        if u.scheme in ('http','https') and u.hostname and not u.username and not u.password:
            try:validate_ioc('ip',u.hostname)
            except ValueError:validate_ioc('domain',u.hostname)
            return value
    raise ValueError('unsupported or invalid IOC')


def lookup_request(provider,kind,value):
    value=validate_ioc(kind,value)
    encoded=quote(value,safe='')
    if provider=='ThreatFox':
        query='query=search_hash&hash=' if kind=='hash' else 'query=search_ioc&search_term='
        return 'https://threatfox-api.abuse.ch/api/v1/?'+query+encoded
    if provider=='MalwareBazaar' and kind=='hash':
        return 'https://mb-api.abuse.ch/api/v1/?query=get_info&hash='+encoded
    if provider=='URLhaus' and kind=='url':
        return 'https://urlhaus-api.abuse.ch/v1/url/?url='+encoded
    if provider=='VirusTotal':
        section={'ip':'ip_addresses','domain':'domains','hash':'files','url':'urls'}[kind]
        key=base64.urlsafe_b64encode(value.encode()).decode().rstrip('=') if kind=='url' else encoded
        return 'https://www.virustotal.com/api/v3/'+section+'/'+key
    if provider=='AlienVault OTX':
        section={'ip':'IPv6' if ':' in value else 'IPv4','domain':'domain','url':'url','hash':'file'}[kind]
        return 'https://otx.alienvault.com/api/v1/indicators/'+section+'/'+encoded+'/general'
    if provider=='AbuseIPDB' and kind=='ip':
        return 'https://api.abuseipdb.com/api/v2/check?ipAddress='+encoded+'&maxAgeInDays=90'
    if provider=='urlscan.io' and kind in ('ip','domain','url'):
        field={'ip':'ip','domain':'domain','url':'page.url.keyword'}[kind]
        literal=value.replace('\\','\\\\').replace('"','\\"')
        return 'https://urlscan.io/api/v1/search/?size=10&q='+quote(field+':"'+literal+'"',safe='')
    return None  # Talos needs a supported licensed integration, not scraping.


def normalize(provider,payload):
    if provider in abusech.PROVIDERS:return abusech.normalize(provider,payload)
    row={'status':'available','disposition':'unknown','labels':[],'categories':[],'threat_classifications':[],'metrics':{}}
    if provider=='VirusTotal':
        a=payload['data']['attributes'];stats=a['last_analysis_stats']
        if not isinstance(stats,dict) or not stats or any(type(v) is not int or v<0 for v in stats.values()):raise ValueError('invalid stats')
        row['metrics']={'malicious':stats.get('malicious'),'suspicious':stats.get('suspicious'),'total':sum(stats.values()),'engine_stats':stats}
        row['labels']=sorted({x['result'] for x in a.get('last_analysis_results',{}).values() if isinstance(x.get('result'),str) and x['result']})
        row['categories']=[{'source':source,'label':label} for source,label in a.get('categories',{}).items() if isinstance(label,str)]
        classification=a.get('popular_threat_classification',{})
        row['threat_classifications']=[{'source':'VirusTotal','label':entry['value'],'count':entry.get('count')} for entry in classification.get('popular_threat_category',[]) if isinstance(entry,dict) and isinstance(entry.get('value'),str)]
        row['observed_at']=a.get('last_analysis_date')
        # Engine votes are evidence, not a fabricated provider-wide verdict.
        row['disposition']='detections_reported' if stats.get('malicious',0) else 'suspicious' if stats.get('suspicious',0) else 'unknown'
    elif provider=='AbuseIPDB':
        a=payload['data'];score=a['abuseConfidenceScore']
        if type(score) is not int or not 0<=score<=100:raise ValueError('invalid score')
        row['metrics']={'abuse_confidence':score,'reports':a.get('totalReports'),'distinct_reporters':a.get('numDistinctUsers')}
        row['interpretation']='Abuse confidence and report count are separate metrics. A zero score does not establish that this address is safe.'
        row['observed_at']=a.get('lastReportedAt')
        row['disposition']='abuse_reported' if score>0 else 'unknown'
    elif provider=='urlscan.io':
        scans=payload['results']
        if not isinstance(scans,list):raise ValueError('invalid scans')
        row['interpretation']='Historical scan matches are context, not a malicious or clean verdict.'
        row['metrics']={'matching_scans_returned':len(scans)}
        row['status']='available' if scans else 'no_record'
        # Search hits alone establish no reputation or exact result verdict.
        row['reports']=[{'scan_id':s.get('_id'),'observed_at':s.get('task',{}).get('time')} for s in scans[:10]]
    elif provider=='AlienVault OTX':
        info=payload['pulse_info'];count=info['count'];pulses=info.get('pulses',[])
        if type(count) is not int or count<0 or not isinstance(pulses,list):raise ValueError('invalid pulses')
        row['metrics']={'pulse_count':count}
        row['interpretation']='Community pulse membership provides research context, not a malicious or clean verdict.'
        row['reports']=[{'pulse_id':p.get('id'),'name':p.get('name'),'observed_at':p.get('modified'),'tags':[t for t in p.get('tags',[]) if isinstance(t,str)][:20]} for p in pulses[:10] if isinstance(p,dict)]
    else:raise ValueError('unsupported provider')
    return row


class ReputationService:
    def __init__(self, authorized_transport):
        self.transport=authorized_transport

    async def lookup(self, *, tenant_id, kind, value):
        if not isinstance(tenant_id,str) or not tenant_id.strip():raise ValueError('tenant required')
        value=validate_ioc(kind,value)
        async def lookup_provider(provider):
            row={'provider':provider,'status':'not_configured','disposition':'unknown','labels':[],'categories':[],'threat_classifications':[],'metrics':{},'checked_at':None}
            url=lookup_request(provider,kind,value)
            if url is None:
                row['status']='not_configured' if provider=='Cisco Talos' else 'not_applicable'
            elif self.transport is not None:
                # Transport must enforce tenant credentials, timeouts, response size and fixed provider hosts.
                try:
                    response=await asyncio.wait_for(self.transport(tenant_id=tenant_id,provider=provider,url=url),timeout=12)
                    status,payload=response
                    row['checked_at']=datetime.now(timezone.utc).isoformat()
                    if status==200:row.update(normalize(provider,payload))
                    else:row['status']={401:'authentication_failed',403:'access_denied',404:'no_record',429:'rate_limited',503:'unavailable'}.get(status,'lookup_failed')
                except SecretStoreUnavailable:row['status']='configuration_unavailable'
                except ProviderNotConfigured:row['status']='not_configured'
                except (ValueError,KeyError,TypeError,AttributeError):row['status']='invalid_response'
                except (TimeoutError,OSError):row['status']='unavailable'
            return row
        rows=await asyncio.gather(*(lookup_provider(provider) for provider in PROVIDERS))
        return {'ioc':{'type':kind,'value':value},'providers':rows,'submitted':False,'consensus':'not_assessed',
                'sources_used':[r['provider'] for r in rows if r['status'] in ('available','no_record') and r['checked_at'] is not None]}
