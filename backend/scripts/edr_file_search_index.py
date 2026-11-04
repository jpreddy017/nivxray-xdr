"""Explicit resumable EDR indexing job. Run against the candidate database first.

PYTHONPATH=backend python backend/scripts/edr_file_search_index.py --tenant ID
Use --follow for incremental polling. Source evidence is never modified.
The source must be append-only with monotonically increasing ObjectIds;
late records inserted with older IDs require an explicit rebuild.
"""
import argparse
from datetime import datetime, timezone
import time
from bson import ObjectId
from pymongo import MongoClient
import deps
from services.edr import endpoint_query as eq
from services.edr.global_file_index import COLLECTION, CHECKPOINTS, ensure_indexes, project_document


def batch(db, tenant, size=500):
    source, target, state = db.v2_shadow_observations, db[COLLECTION], db[CHECKPOINTS]
    checkpoint = state.find_one({'_id': tenant}) or {}
    query = {'tenant_id': tenant}
    if checkpoint.get('after'):
        query['_id'] = {'$gt': ObjectId(checkpoint['after'])}
    docs = list(source.find(query).sort('_id', 1).limit(size).max_time_ms(5000))
    scope = {'all_tenants': False, 'tenant_ids': [tenant]}
    cache, skipped, written = {}, 0, 0
    for doc in docs:
        ref = doc.get('connector_id') or doc.get('collector_id')
        if ref not in cache:
            cache[ref] = eq.resolve_endpoint(ref, scope) if ref else None
        res = cache[ref]
        # Recheck membership using the exact authoritative source predicate.
        if not res or not source.find_one({'$and': [{'_id': doc['_id']}, res.predicate('v2_shadow_observations')]}, {'_id': 1}):
            skipped += 1
            continue
        for row in project_document(doc, res):
            target.replace_one({'_id': row['_id']}, row, upsert=True)
            written += 1
    # Checkpoint only after all writes succeed. Replays are idempotent.
    now = datetime.now(timezone.utc).isoformat()
    update = {'checked_at': now, 'caught_up_at_check': len(docs) < size,
              'schema_version': 1}
    if docs:
        update['after'] = str(docs[-1]['_id'])
    state.update_one({'_id': tenant}, {'$set': update, '$inc': {'scanned': len(docs), 'unresolved': skipped}}, upsert=True)
    return len(docs), written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tenant', required=True)
    parser.add_argument('--follow', action='store_true')
    args = parser.parse_args()
    if not deps.MONGO_URL or not deps.DB_NAME:
        raise SystemExit('Configure the candidate MONGO_URL and DB_NAME')
    client = MongoClient(deps.MONGO_URL)
    db = client[deps.DB_NAME]
    ensure_indexes(db[COLLECTION])
    while True:
        count, written = batch(db, args.tenant)
        print(f'scanned={count} indexed={written}', flush=True)
        if count < 500:
            if not args.follow:
                break
            time.sleep(5)


if __name__ == '__main__':
    main()
