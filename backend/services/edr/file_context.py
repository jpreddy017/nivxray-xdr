"""EDR-only source context. Hash + source process GUID joins, never PID joins."""
from datetime import datetime
import re

LIMIT = 1000

def _time(value):
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return int(dt.timestamp() * 1000) if dt.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def correlate(rows, documents, query):
    records = []
    for doc in documents[:LIMIT]:
        event = doc.get('event') or {}
        stamp = _time(event.get('ts'))
        if stamp is not None and query['time_start'] <= stamp < query['time_end']:
            records.append((doc, event))
    # Conflicting image hashes on one GUID make that GUID unusable.
    identities = {}
    for doc, event in records:
        proc = event.get('process') or {}
        guid = proc.get('guid')
        sha = (proc.get('image_hashes') or {}).get('sha256')
        if isinstance(guid, str) and guid and isinstance(sha, str) and re.fullmatch('[a-fA-F0-9]{64}', sha):
            identities.setdefault(guid, set()).add(sha.lower())
    for row in rows:
        sha = (row.get('hashes') or {}).get('sha256', '').lower()
        guids = {g for g, hashes in identities.items() if sha and hashes == {sha}}
        executions, connections = [], []
        for doc, event in records:
            proc = event.get('process') or {}
            if proc.get('guid') not in guids:
                continue
            evidence = dict(record_id=str(doc['_id']), observed_at=event.get('ts'),
                            process_guid=proc['guid'], image=proc.get('image'),
                            source=(event.get('provenance') or {}).get('source'),
                            basis='FILE_SHA256_EQUALS_PROCESS_IMAGE_SHA256_AND_SOURCE_GUID')
            if event.get('kind') == 'process_create':
                executions.append(dict(evidence, command_line=proc.get('command_line'),
                                       parent_guid=proc.get('parent_guid'), parent_image=proc.get('parent_image')))
            if event.get('kind') in ('network_connect', 'dns_query'):
                for net in (event.get('artefacts') or {}).get('network', []):
                    if isinstance(net, dict):
                        connections.append(dict(evidence, **{k: net.get(k) for k in ('dst_ip', 'dst_port', 'protocol', 'dns', 'url')}))
        row['executions'] = executions[:50]
        row['network_connections'] = connections[:100]
        row['context_results_truncated'] = len(executions) > 50 or len(connections) > 100
        row['context_coverage'] = 'BOUNDED_SCAN_INCOMPLETE' if len(documents) > LIMIT else 'AVAILABLE_RECORDS_ONLY'
        row['context_scanned_records'] = min(len(documents), LIMIT)
    return rows


def enrich(collection, predicate, rows, query):
    if not rows or not any((r.get('hashes') or {}).get('sha256') for r in rows):
        return rows
    cursor = collection.find(predicate, {'_id': 1, 'event': 1}).sort('_id', -1).limit(LIMIT + 1).max_time_ms(3000)
    try:
        documents = list(cursor)
    finally:
        cursor.close()
    return correlate(rows, documents, query)
