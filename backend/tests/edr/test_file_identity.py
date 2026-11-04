from types import SimpleNamespace
from services.edr.file_identity import resolve_file_identity


def test_two_store_aliases_count_as_one_device_and_cache_is_tenant_scoped():
    calls=[]
    def resolver(ref, scope):
        calls.append((ref,scope))
        return SimpleNamespace(identity={'endpoint_id':'ep_one','tenant_id':'t1'})
    cache={}
    shadow={'tenant_id':'t1','event':{'device_iid':'dev_one'}}
    canonical={'tenant_id':'t1','provenance':{'collector_id':'ep_one'}}
    resolved=[resolve_file_identity(d,s,'t1',resolver,cache) for d,s in [
        (shadow,'v2_shadow_observations'),(canonical,'xdr_canonical_evidence'),(shadow,'v2_shadow_observations')]]
    assert {r.identity['endpoint_id'] for r in resolved} == {'ep_one'}
    assert len(calls)==2
    assert all(scope == {'all_tenants':False,'tenant_ids':['t1']} for _,scope in calls)


def test_identity_fails_closed_without_ownership_or_strong_reference():
    def resolver(ref, scope):
        return SimpleNamespace(identity={'endpoint_id':'ep_foreign','tenant_id':'t2'})
    assert resolve_file_identity({'tenant_id':'t1','collector_id':'foreign'},'v2_shadow_observations','t1',resolver,{}) is None
    assert resolve_file_identity({'tenant_id':'t2','collector_id':'foreign'},'v2_shadow_observations','t1',resolver,{}) is None
    assert resolve_file_identity({'tenant_id':'t1','event':{'computer':'same-name'}},'v2_shadow_observations','t1',resolver,{}) is None


def test_invalid_collector_does_not_fall_back_to_device_alias():
    calls=[]
    def resolver(ref, scope):
        calls.append(ref)
        return None
    assert resolve_file_identity({'tenant_id':'t1','collector_id':'invalid','event':{'device_iid':'valid'}},'v2_shadow_observations','t1',resolver,{}) is None
    assert calls==['invalid']
