"""Raw append collision recovery; no database or credentials required."""
import unittest
from unittest.mock import AsyncMock
from pymongo.errors import DuplicateKeyError
from edr_plane import raw_events as raw

class RawAppendRaceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.event = raw.RawEndpointEvent.build(tenant_id='tenant-a', source='endpoint-a', payload='{}')
        self.coll = AsyncMock()
        self.db = {raw.COLLECTION: self.coll}
        self.existing = {'raw_id': self.event.raw_id, 'duplicate_count': 2}

    async def test_new_event_retains_payload(self):
        self.coll.find_one_and_update.return_value = None
        result = await raw.append(self.db, self.event)
        self.assertTrue(result['stored'])
        self.assertEqual(self.coll.insert_one.await_args.args[0]['payload'], '{}')

    async def test_existing_delivery_does_not_insert(self):
        self.coll.find_one_and_update.return_value = self.existing
        result = await raw.append(self.db, self.event)
        self.assertEqual(result['duplicate_count'], 3)
        self.coll.insert_one.assert_not_awaited()

    async def test_expected_collision_recovers_in_same_tenant(self):
        self.coll.find_one_and_update.side_effect = [None, self.existing]
        self.coll.insert_one.side_effect = DuplicateKeyError('race', 11000, {'keyPattern': {'tenant_id': 1, 'dedup_key': 1}})
        result = await raw.append(self.db, self.event)
        self.assertFalse(result['stored'])
        self.assertTrue(result['duplicate'])
        self.assertEqual(result['raw_id'], self.event.raw_id)
        self.assertEqual(result['duplicate_count'], 3)
        for call in self.coll.find_one_and_update.await_args_list:
            self.assertEqual(call.args[0], {'tenant_id': 'tenant-a', 'dedup_key': self.event.dedup_key})

    async def test_unrelated_and_unidentified_collisions_propagate(self):
        for details in [{'keyPattern': {'other': 1}}, None]:
            with self.subTest(details=details):
                self.coll.reset_mock()
                self.coll.find_one_and_update.return_value = None
                error = DuplicateKeyError('other', 11000, details)
                self.coll.insert_one.side_effect = error
                with self.assertRaises(DuplicateKeyError) as raised:
                    await raw.append(self.db, self.event)
                self.assertIs(raised.exception, error)
                self.assertEqual(self.coll.find_one_and_update.await_count, 1)

    async def test_missing_winner_propagates_original_collision(self):
        self.coll.find_one_and_update.return_value = None
        error = DuplicateKeyError('race', 11000, {'keyPattern': {'tenant_id': 1, 'dedup_key': 1}})
        self.coll.insert_one.side_effect = error
        with self.assertRaises(DuplicateKeyError) as raised:
            await raw.append(self.db, self.event)
        self.assertIs(raised.exception, error)

    async def test_recovery_database_failure_propagates(self):
        self.coll.find_one_and_update.side_effect = [None, RuntimeError('database unavailable')]
        self.coll.insert_one.side_effect = DuplicateKeyError('race', 11000, {'keyPattern': {'tenant_id': 1, 'dedup_key': 1}})
        with self.assertRaisesRegex(RuntimeError, 'database unavailable'):
            await raw.append(self.db, self.event)

if __name__ == '__main__':
    unittest.main()
