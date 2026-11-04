"""EDR file discovery projection. Index writes are an explicit offline job.

No request scans source telemetry or changes it. Every result is re-authorized
against the current endpoint resolver. Counts describe indexed unique events.
"""
from datetime import datetime, timezone
import hashlib
import re
from urllib.parse import urlencode

from services.edr.endpoint_file_evidence import project, validate_query, _millis
from edr_plane.trajectory_window import _event_iid, _group_and_key

COLLECTION = 'edr_file_search_v2'
CHECKPOINTS = 'edr_file_search_checkpoints_v2'
HASHES = {'sha256': 64, 'sha1': 40, 'md5': 32}


def coverage_status(checkpoint, now=None):
    """Expose freshness without leaking worker identity or internal errors."""
    now = now or datetime.now(timezone.utc)
    public = {k: checkpoint.get(k) for k in (
        'checked_at', 'caught_up_at_check', 'scanned', 'unresolved', 'schema_version', 'reconciled_at', 'validated_at')}
    try:
        checked = datetime.fromisoformat(checkpoint['checked_at'].replace('Z', '+00:00'))
        age = max(0, (now - checked).total_seconds())
    except (KeyError, TypeError, ValueError):
        age = None
    public['age_seconds'] = age
    public['status'] = ('error' if checkpoint.get('worker_status') == 'error' else
                        'stale' if age is None or age > 60 else
                        'catching_up' if not checkpoint.get('caught_up_at_check') else
                        'partial' if checkpoint.get('unresolved', 0) else 'current')
    return public


def normalized(value):
    return str(value or '').strip().replace('/', '\\').casefold()


def query_args(key, key_type, start, end):
    key = str(key or '').strip()
    validate_query('_', start, end)
    if not key or len(key) > 4096:
        raise ValueError('Enter a filename, path or file hash')
    if key_type == 'auto':
        key_type = next((k for k, n in HASHES.items() if re.fullmatch('[a-fA-F0-9]{%s}' % n, key)),
                        'path' if '/' in key or '\\' in key else 'name')
    if key_type not in ('name', 'path', *HASHES):
        raise ValueError('Unsupported search type')
    if key_type in HASHES and not re.fullmatch('[a-fA-F0-9]{%s}' % HASHES[key_type], key):
        raise ValueError('Enter a complete valid file hash')
    return key_type + ':' + normalized(key)


def project_document(doc, resolution):
    """Separate target-file and executable-image evidence; never borrow hashes."""
    identity = resolution.identity
    tenant = identity.get('tenant_id')
    endpoint = identity.get('endpoint_id')
    if not tenant or not endpoint or doc.get('tenant_id') != tenant:
        return []
    ev = doc.get('event') or {}
    stamp = _millis(ev.get('ts') or doc.get('captured_at'))
    if stamp is None:
        return []
    event_id = str(doc.get('observation_id') or doc.get('_id') or '')
    if not event_id:
        return []
    rows = []
    file_row, _ = project(doc, validate_query(endpoint, stamp, stamp + 1))
    if file_row:
        rows.append(dict(file_row, evidence_type='FILE_OPERATION'))
    proc = ev.get('process') or {}
    path = proc.get('image') or proc.get('name')
    if path:
        hashes = {k: str(v).lower() for k, v in (proc.get('image_hashes') or {}).items()
                  if k in HASHES and re.fullmatch('[a-fA-F0-9]{%s}' % HASHES[k], str(v))}
        rows.append(dict(path=path, name=normalized(path).split('\\')[-1], hashes=hashes,
                         action='Observed execution' if ev.get('kind') == 'process_create' else 'Observed process image',
                         evidence_type='PROCESS_IMAGE', hash_class='PROCESS_IMAGE_HASH',
                         identity_basis='CONTENT_IDENTITY_SHA256' if hashes.get('sha256') else 'PATH_IDENTITY_ONLY',
                         writer_basis='NOT_A_FILE_WRITE', writer_image='', writer_process_guid='',
                         process_image=path, process_guid=proc.get('guid'), process_pid=proc.get('pid'),
                         command_line=proc.get('command_line') or (ev.get('raw') or {}).get('command_line'),
                         parent_image=proc.get('parent_image'),
                         observed_at=datetime.fromtimestamp(stamp / 1000, timezone.utc).isoformat(),
                         assessment='NOT_ASSESSED', source=(ev.get('provenance') or {}).get('source')))
    for row in rows:
        tokens = {f'name:{normalized(row["name"])}', f'path:{normalized(row["path"])}'}
        tokens.update(f'{k}:{v.lower()}' for k, v in row['hashes'].items())
        # Retries with the same source event do not inflate event counts.
        uid = '\x1f'.join((tenant, endpoint, event_id, row['evidence_type'], normalized(row['path'])))
        row.update(_id=hashlib.sha256(uid.encode()).hexdigest(), tenant_id=tenant,
                   endpoint_id=endpoint, hostname=identity.get('hostname') or endpoint,
                   event_key=event_id, event_iid=ev.get('iid'), evidence_ref=doc.get('observation_id'),
                   trajectory_event_iid=_event_iid(doc, ev, _group_and_key(ev)[1]),
                   record_id=str(doc['_id']), time_ms=stamp, tokens=sorted(tokens))
    return rows


def ensure_indexes(collection):
    collection.create_index([('tenant_id', 1), ('_id', 1)], name='file_validation')
    collection.create_index([('tenant_id', 1), ('tokens', 1), ('time_ms', 1), ('endpoint_id', 1)], name='file_discovery')
    collection.create_index([('tenant_id', 1), ('endpoint_id', 1), ('tokens', 1), ('time_ms', 1)], name='file_device_events')


def device_link(row):
    stamp = row['time_ms']
    args = {'device': row['endpoint_id'], 't0': stamp - 60000, 't1': stamp + 60000,
            'from': datetime.fromtimestamp((stamp - 60000)/1000, timezone.utc).isoformat(),
            'to': datetime.fromtimestamp((stamp + 60000)/1000, timezone.utc).isoformat(),
            'at': row['observed_at'], 'source': 'file_search'}
    # V2 uses a persisted observation plus lane fingerprint, not the raw observation ID.
    ref = row.get('trajectory_event_iid')
    if row.get('evidence_ref'):
        args['observation_id'] = row['evidence_ref']
    if ref:
        args['event'] = ref
    return '/edr/computers/' + row['endpoint_id'] + '/trajectory?' + urlencode(args)


def search(collection, tenant, scope, resolve, token, start, end, endpoint=None, after='', limit=50):
    if not tenant or scope.get('all_tenants') or scope.get('tenant_ids') != [tenant]:
        raise PermissionError('Explicit authorized customer required')
    if not 1 <= limit <= 100 or len(after) > 512:
        raise ValueError('Invalid result page')
    predicate = {'tenant_id': tenant, 'tokens': token, 'time_ms': {'$gte': start, '$lt': end}}
    if endpoint:
        res = resolve(endpoint, scope)
        if not res or res.identity.get('tenant_id') != tenant:
            raise PermissionError('Endpoint not authorized')
        predicate['endpoint_id'] = res.identity['endpoint_id']
        if after:
            predicate['_id'] = {'$gt': after}
        cursor = collection.find(predicate, {'tokens': 0}).sort('_id', 1).limit(limit + 1).max_time_ms(5000)
        try:
            rows = list(cursor)
        finally:
            cursor.close()
        more = len(rows) > limit
        rows = rows[:limit]
        for row in rows:
            row['trajectory_url'] = device_link(row)
        return {'observations': rows, 'complete': not more, 'next_cursor': rows[-1]['_id'] if more else None,
                'state': 'INDEXED_EVIDENCE', 'issues': {}}
    if after:
        predicate['endpoint_id'] = {'$gt': after}
    pipeline = [{'$match': predicate},
                {'$group': {'_id': {'endpoint': '$endpoint_id', 'event': '$event_key'},
                            'first': {'$min': '$time_ms'}, 'last': {'$max': '$time_ms'}}},
                {'$group': {'_id': '$_id.endpoint', 'matching_events': {'$sum': 1},
                            'first_seen': {'$min': '$first'}, 'last_seen': {'$max': '$last'}}},
                {'$sort': {'_id': 1}}, {'$limit': limit + 1}]
    groups = list(collection.aggregate(pipeline, maxTimeMS=5000, allowDiskUse=False))
    more = len(groups) > limit
    page = groups[:limit]
    allowed = []
    for group in page:
        res = resolve(group['_id'], scope)
        if res and res.identity.get('tenant_id') == tenant:
            allowed.append(dict(endpoint_id=group['_id'], hostname=res.hostname or group['_id'],
                                matching_events=group['matching_events'], first_seen=group['first_seen'], last_seen=group['last_seen']))
    return {'devices': allowed, 'next_cursor': page[-1]['_id'] if more else None,
            'complete': not more, 'count_basis': 'Unique indexed source events per device'}
