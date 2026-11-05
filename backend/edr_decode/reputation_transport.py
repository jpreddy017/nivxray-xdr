"""EDR-owned GET transport adapted from the preserved XDR provider adapters.

Credentials are resolved per authenticated tenant by an EDR-owned secret store.
No environment fallback to another product, redirects, submissions or IOC visits.
"""
import asyncio
import json
from urllib.parse import urlsplit, parse_qs, urlunsplit
import httpx

CONFIG = {
    'ThreatFox': ('threatfox-api.abuse.ch', '/api/v1/', 'Auth-Key', 'EDR_ABUSE_CH_AUTH_KEY'),
    'MalwareBazaar': ('mb-api.abuse.ch', '/api/v1/', 'Auth-Key', 'EDR_ABUSE_CH_AUTH_KEY'),
    'URLhaus': ('urlhaus-api.abuse.ch', '/v1/url/', 'Auth-Key', 'EDR_ABUSE_CH_AUTH_KEY'),
    'AlienVault OTX': ('otx.alienvault.com', '/api/v1/indicators/', 'X-OTX-API-KEY', 'EDR_OTX_API_KEY'),
    'VirusTotal': ('www.virustotal.com', '/api/v3/', 'x-apikey', 'EDR_VT_API_KEY'),
    'AbuseIPDB': ('api.abuseipdb.com', '/api/v2/check', 'Key', 'EDR_ABUSEIPDB_API_KEY'),
    'urlscan.io': ('urlscan.io', '/api/v1/search/', 'API-Key', 'EDR_URLSCAN_API_KEY'),
}

class ProviderNotConfigured(Exception):
    pass

class ReputationTransport:
    def __init__(self, *, secret_resolver, http_transport=None):
        if not callable(secret_resolver):raise TypeError('EDR tenant secret resolver required')
        self.secrets=secret_resolver
        self.http_transport=http_transport
        self.slots=asyncio.Semaphore(4)

    async def __call__(self, *, tenant_id, provider, url):
        if not isinstance(tenant_id,str) or not tenant_id.strip():raise ValueError('tenant required')
        host,path,header,config=CONFIG[provider]
        parsed=urlsplit(url)
        if (parsed.scheme!='https' or parsed.netloc!=host or parsed.fragment or
            not (parsed.path.startswith(path) if provider in ('VirusTotal','AlienVault OTX') else parsed.path==path)):
            raise ValueError('provider destination rejected')
        method='GET';kwargs={};destination=url
        if provider in ('ThreatFox','MalwareBazaar','URLhaus'):
            params=parse_qs(parsed.query,strict_parsing=True)
            if any(len(v)!=1 for v in params.values()):raise ValueError('duplicate query')
            params={k:v[0] for k,v in params.items()}
            allowed=({'query','hash'} if params.get('query')=='search_hash' else {'query','search_term'}) if provider=='ThreatFox' else {'query','hash'} if provider=='MalwareBazaar' else {'url'}
            if set(params)!=allowed:raise ValueError('lookup fields required')
            if provider=='ThreatFox':
                if params['query'] not in ('search_hash','search_ioc'):raise ValueError('lookup only')
                if params['query']=='search_ioc':params['exact_match']=True
            if provider=='MalwareBazaar' and params['query']!='get_info':raise ValueError('lookup only')
            method='POST';kwargs={'json' if provider=='ThreatFox' else 'data':params}
            destination=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,'',''))
        async def request():
            key=await self.secrets(tenant_id,config)
            if not isinstance(key,str) or not key.strip():raise ProviderNotConfigured()
            async with self.slots:
                async with httpx.AsyncClient(transport=self.http_transport,follow_redirects=False,trust_env=False,timeout=8.0) as client:
                    async with client.stream(method,destination,headers={header:key,'Accept':'application/json'},**kwargs) as response:
                        if response.status_code!=200:return response.status_code,{}
                        body=bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk)
                            if len(body)>2*1024*1024:raise ValueError('provider response too large')
                        payload=json.loads(body)
                        if not isinstance(payload,dict):raise ValueError('provider object required')
                        return 200,payload
        try:return await asyncio.wait_for(request(),timeout=10)
        except httpx.HTTPError:raise OSError('provider unavailable') from None
