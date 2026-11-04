"""Stable, tenant-scoped file evidence identity shared by EDR reads and indexing."""

def evidence_ref(doc, store):
    if store == 'v2_shadow_observations':
        event = doc.get('event') or {}
        return (doc.get('connector_id') or doc.get('collector_id')
                or event.get('device_iid') or doc.get('device_iid'))
    if store == 'xdr_canonical_evidence':
        return ((doc.get('provenance') or {}).get('collector_id')
                or (doc.get('host') or {}).get('host_id'))
    return None


def resolve_file_identity(doc, store, tenant, resolver, cache):
    # Do not fall back from a supplied but unauthorized strong reference to a
    # weaker name. Hostnames alone are not sufficient file evidence ownership.
    if not tenant or doc.get('tenant_id') != tenant:
        return None
    ref = evidence_ref(doc, store)
    if not isinstance(ref, str) or not ref.strip():
        return None
    key = (tenant, ref)
    if key not in cache:
        cache[key] = resolver(ref, {'all_tenants': False, 'tenant_ids': [tenant]})
    res = cache[key]
    if res and res.identity.get('tenant_id') == tenant and not res.identity.get('endpoint_id'):
        iid = res.identity.get('device_iid')
        if not iid:
            return None
        from deps import sync_collection
        rows = list(sync_collection('edr_endpoints').find(
            {'tenant_id': tenant, 'device_iid': iid}, {'endpoint_id': 1}).limit(2))
        # Ambiguous enrollments must not silently merge distinct devices.
        if len(rows) != 1 or not rows[0].get('endpoint_id'):
            return None
        res = resolver(rows[0]['endpoint_id'], {'all_tenants': False, 'tenant_ids': [tenant]})
        cache[key] = res
    if not res or res.identity.get('tenant_id') != tenant or not res.identity.get('endpoint_id'):
        return None
    return res
