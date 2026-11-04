from types import SimpleNamespace
from urllib.parse import urlparse, parse_qs
import mongomock
import pytest
from services.edr.global_file_index import project_document, query_args, search, device_link, ensure_indexes

START = 1793757600000

def resolution(ep='ep_a', tenant='t1'):
    return SimpleNamespace(identity={'endpoint_id': ep, 'tenant_id': tenant, 'hostname': ep}, hostname=ep)

def document(i='source1', **extra):
    return dict(_id=i, tenant_id='t1', observation_id=i, event={
        'iid': i, 'kind': 'process_create', 'ts': '2026-11-04T02:00:00Z',
        'process': {'image': r'C:\Windows\System32\wevtutil.exe', 'image_hashes': {'sha256': 'a'*64}},
        'raw': {'sha256': 'b'*64}}, **extra)

def test_execution_without_file_event_is_searchable():
    row, = project_document(document(), resolution())
    assert row['evidence_type'] == 'PROCESS_IMAGE'
    assert row['action'] == 'Observed execution'
    assert 'name:wevtutil.exe' in row['tokens']
    assert 'sha256:' + 'a'*64 in row['tokens']
    assert 'sha256:' + 'b'*64 not in row['tokens']
    assert row['writer_basis'] == 'NOT_A_FILE_WRITE'

def test_target_never_borrows_executable_hash():
    d = document(); d['event'].update(kind='file_create')
    d['event']['raw']['file'] = {'path': r'C:\tmp\output.txt'}
    rows = project_document(d, resolution())
    target, image = rows
    assert target['hashes'] == {}
    assert image['hashes']['sha256'] == 'a'*64
    assert target['_id'] != image['_id']

def test_malformed_or_cross_tenant_records_excluded():
    d = document(); d['tenant_id'] = 't2'
    assert project_document(d, resolution()) == []
    d = document(); d['event']['ts'] = 'not-a-date'
    assert project_document(d, resolution()) == []

def test_normalization_hash_detection_and_validation():
    assert query_args(' WEVTUTIL.EXE ', 'auto', START, START+1000) == 'name:wevtutil.exe'
    assert query_args('A'*64, 'auto', START, START+1000) == 'sha256:'+'a'*64
    assert query_args('A'*40, 'auto', START, START+1000).startswith('sha1:')
    assert query_args('A'*32, 'auto', START, START+1000).startswith('md5:')
    with pytest.raises(ValueError): query_args('xyz', 'sha256', START, START+1)
    with pytest.raises(ValueError): query_args('', 'name', START, START+1)

def test_device_counts_deduplicate_retry_and_multiple_evidence_roles():
    c = mongomock.MongoClient().db.files
    ensure_indexes(c)
    d=document(); d['event']['raw']['file']={'path': r'C:\Windows\System32\wevtutil.exe'}
    for ep in ['ep_a','ep_b']:
        for _ in range(2):
            for row in project_document(d,resolution(ep)):
                c.replace_one({'_id':row['_id']},row,upsert=True)
    for row in project_document(document('source2'),resolution('ep_a')): c.insert_one(row)
    for row in project_document(document('foreign'),resolution('ep_c','t2')): c.insert_one(row)
    result=search(c,'t1',{'all_tenants':False,'tenant_ids':['t1']},lambda ep,s:resolution(ep),'name:wevtutil.exe',START,START+1000)
    assert [(r['endpoint_id'],r['matching_events']) for r in result['devices']] == [('ep_a',2),('ep_b',1)]
    first=search(c,'t1',{'all_tenants':False,'tenant_ids':['t1']},lambda ep,s:resolution(ep),'name:wevtutil.exe',START,START+1000,limit=1)
    assert first['next_cursor']=='ep_a'
    second=search(c,'t1',{'all_tenants':False,'tenant_ids':['t1']},lambda ep,s:resolution(ep),'name:wevtutil.exe',START,START+1000,after=first['next_cursor'])
    assert [r['endpoint_id'] for r in second['devices']]==['ep_b']

def test_current_endpoint_authorization_and_tenant_required():
    c=mongomock.MongoClient().db.files
    for row in project_document(document(),resolution()):c.insert_one(row)
    scope={'all_tenants':False,'tenant_ids':['t1']}
    assert search(c,'t1',scope,lambda ep,s:None,'name:wevtutil.exe',START,START+1000)['devices']==[]
    with pytest.raises(PermissionError): search(c,'t1',scope,lambda ep,s:None,'name:wevtutil.exe',START,START+1000,endpoint='ep_a')
    with pytest.raises(PermissionError): search(c,'t1',{'all_tenants':True},lambda ep,s:resolution(ep),'name:wevtutil.exe',START,START+1000)

def test_exact_event_link_carries_identity_time_and_source_reference():
    row,=project_document(document(),resolution())
    assert urlparse(device_link(row)).path == '/edr/computers/ep_a/trajectory'
    q=parse_qs(urlparse(device_link(row)).query)
    assert q['event'][0].startswith('source1#') and q['device']==['ep_a']
    assert q['observation_id']==['source1'] and q['source']==['file_search']
    assert int(q['t0'][0]) < row['time_ms'] < int(q['t1'][0])
    assert 'from' in q and 'to' in q


def test_repeated_content_fingerprint_does_not_collapse_distinct_observations():
    first=document('obs-first'); second=document('obs-second')
    first['event']['iid']=second['event']['iid']='same-content-fingerprint'
    a,=project_document(first,resolution()); b,=project_document(second,resolution())
    assert a['event_key'] != b['event_key']
    assert a['_id'] != b['_id']
    assert a['trajectory_event_iid'] != b['trajectory_event_iid']
