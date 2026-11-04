"""Explicit resumable EDR indexing job. Run against the candidate database first.

PYTHONPATH=backend python backend/scripts/edr_file_search_index.py --tenant ID
Use --follow for incremental polling. Source evidence is never modified.
The source must be append-only with monotonically increasing ObjectIds;
periodic bounded reconciliation revisits older IDs and repaired mappings.
"""
import argparse
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from pymongo.errors import DuplicateKeyError, PyMongoError
import time
from bson import ObjectId
from pymongo import MongoClient
import deps
from services.edr import endpoint_query as eq
from services.edr.file_identity import resolve_file_identity
from services.edr.global_file_index import COLLECTION, CHECKPOINTS, ensure_indexes, project_document


class LeaseBusy(RuntimeError):
    pass


def acquire(db, tenant, owner):
    now = datetime.now(timezone.utc)
    try:
        result = db[CHECKPOINTS].update_one(
            {'_id': tenant, '$or': [{'lease_until': {'$lt': now}},
                                  {'lease_until': {'$exists': False}}, {'owner': owner}]},
            {'$set': {'owner': owner, 'lease_until': now + timedelta(seconds=60)}}, upsert=True)
        return bool(result.matched_count or result.upserted_id)
    except DuplicateKeyError:
        return False


def renew(db, tenant, owner):
    now = datetime.now(timezone.utc)
    result = db[CHECKPOINTS].update_one(
        {'_id': tenant, 'owner': owner, 'lease_until': {'$gt': now}},
        {'$set': {'lease_until': now + timedelta(seconds=60)}})
    if not result.matched_count:
        raise LeaseBusy('Indexer lease lost')


def batch(db, tenant, size=500, owner=None, reconcile=False):
    if owner:
        renew(db, tenant, owner)
    source, target, state = db.v2_shadow_observations, db[COLLECTION], db[CHECKPOINTS]
    checkpoint = state.find_one({'_id': tenant}) or {}
    query = {'tenant_id': tenant}
    cursor_field = 'reconcile_after' if reconcile else 'after'
    if checkpoint.get(cursor_field):
        query['_id'] = {'$gt': ObjectId(checkpoint[cursor_field])}
    docs = list(source.find(query).sort('_id', 1).limit(size).max_time_ms(5000))
    scope = {'all_tenants': False, 'tenant_ids': [tenant]}
    cache, skipped, written = {}, 0, 0
    for doc in docs:
        if owner:
            renew(db, tenant, owner)
        res = resolve_file_identity(doc, 'v2_shadow_observations', tenant, eq.resolve_endpoint, cache)
        # Recheck membership using the exact authoritative source predicate.
        if not res or not source.find_one({'$and': [{'_id': doc['_id']}, res.predicate('v2_shadow_observations')]}, {'_id': 1}):
            skipped += 1
            continue
        for row in project_document(doc, res):
            target.replace_one({'_id': row['_id']}, row, upsert=True)
            written += 1
    # Checkpoint only after all writes succeed. Replays are idempotent.
    now = datetime.now(timezone.utc).isoformat()
    if reconcile:
        unresolved = checkpoint.get('reconcile_unresolved', 0) + skipped
        update = {'reconcile_after': str(docs[-1]['_id']) if docs else checkpoint.get('reconcile_after'),
                  'reconcile_unresolved': unresolved}
        if len(docs) < size:
            update.update(reconcile_after=None, reconcile_unresolved=0,
                          reconciled_at=now, unresolved=unresolved)
        increments = {}
    else:
        update = {'checked_at': now, 'caught_up_at_check': len(docs) < size,
                  'schema_version': 2, 'worker_status': 'running'}
        if docs:
            update['after'] = str(docs[-1]['_id'])
        increments = {'scanned': len(docs), 'unresolved': skipped}
    predicate = {'_id': tenant}
    if owner:
        renew(db, tenant, owner)
        predicate.update(owner=owner)
    result = state.update_one(predicate, {'$set': update, **({'$inc': increments} if increments else {})}, upsert=not bool(owner))
    if owner and not result.matched_count:
        raise LeaseBusy('Indexer lease lost before checkpoint')
    return len(docs), written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    tenants = parser.add_mutually_exclusive_group(required=True)
    tenants.add_argument('--tenant')
    tenants.add_argument('--all-registered-tenants', action='store_true', help='Index tenants present in the authoritative endpoint directory')
    parser.add_argument('--follow', action='store_true')
    args = parser.parse_args()
    if not deps.MONGO_URL or not deps.DB_NAME:
        raise SystemExit('Configure the candidate MONGO_URL and DB_NAME')
    client = MongoClient(deps.MONGO_URL, serverSelectionTimeoutMS=5000,
                         socketTimeoutMS=10000, connectTimeoutMS=5000)
    db = client[deps.DB_NAME]
    owner, failures = str(uuid4()), 0
    held = set()
    try:
        ensure_indexes(db[COLLECTION])
        while True:
            tenants = ([args.tenant] if args.tenant else sorted(
                value for value in db.edr_endpoints.distinct('tenant_id')
                if isinstance(value, str) and value.strip()))
            pending = False
            for tenant in tenants:
                try:
                    if not acquire(db, tenant, owner):
                        raise LeaseBusy('Another indexer holds this tenant lease')
                    held.add(tenant)
                    count, written = batch(db, tenant, owner=owner)
                    # One bounded historical batch per turn: catches older-ID arrivals
                    # and retries identities repaired after their initial scan.
                    replayed, _ = batch(db, tenant, owner=owner, reconcile=True)
                    pending = pending or count == 500 or replayed == 500
                    failures = 0
                    print(f'scanned={count} indexed={written} reconciled={replayed}', flush=True)
                except (PyMongoError, LeaseBusy):
                    if not args.follow:
                        raise
                    failures += 1
                    try:
                        db[CHECKPOINTS].update_one({'_id': tenant, 'owner': owner},
                            {'$set': {'worker_status': 'error'}})
                    except PyMongoError:
                        pass
                    print('Indexer retry pending; last successful checkpoint retained', flush=True)
            if not args.follow and not pending:
                break
            if failures or not pending:
                time.sleep(min(30, 2 ** min(failures, 5)) if failures else 5)
    finally:
        try:
            for tenant in held:
                db[CHECKPOINTS].update_one({'_id': tenant, 'owner': owner},
                    {'$unset': {'owner': '', 'lease_until': ''}})
        finally:
            client.close()


if __name__ == '__main__':
    main()
