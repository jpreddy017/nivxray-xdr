"""Read-only abuse.ch lookup normalization; never downloads or submits samples."""
PROVIDERS=('ThreatFox','MalwareBazaar','URLhaus')

def normalize(provider,payload):
    status=payload['query_status']
    row={'status':'available','disposition':'unknown','labels':[],'categories':[], 'threat_classifications':[],'metrics':{},'reports':[]}
    if status in ('no_result','hash_not_found','no_results'):
        row['status']='no_record';return row
    if status!='ok':
        row['status']='lookup_failed';return row
    records=[payload] if provider=='URLhaus' else payload['data']
    if not isinstance(records,list) or not records:raise ValueError('invalid provider records')
    row['metrics']={'matching_records':len(records)}
    row['disposition']='listed_by_provider'
    row['interpretation']='Provider listing is source evidence. It does not establish execution or compromise on this endpoint.'
    for item in records[:20]:
        if not isinstance(item,dict):raise ValueError('invalid provider record')
        label=item.get('malware_printable') if provider=='ThreatFox' else item.get('signature') if provider=='MalwareBazaar' else item.get('threat')
        if isinstance(label,str) and label:row['threat_classifications'].append({'source':provider,'label':label})
        tags=item.get('tags') or []
        if not isinstance(tags,list):raise ValueError('invalid tags')
        row['categories'].extend({'source':provider,'label':t} for t in tags[:20] if isinstance(t,str))
        row['reports'].append({'first_seen':item.get('first_seen') or item.get('date_added'),'last_seen':item.get('last_seen'),'confidence':item.get('confidence_level'),'url_status':item.get('url_status')})
    return row
