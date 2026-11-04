import asyncio
import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, patch
from edr_plane import processing_lease as lease, processing_queue as queue

class LeaseTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.job = dict(tenant_id='tenant-a', raw_id='raw-a', attempts=2,
                        lease_until=queue._now()+timedelta(seconds=1))

    async def test_fast_work_has_no_renewal_write(self):
        with patch.object(lease, 'renew', new_callable=AsyncMock) as renew:
            self.assertEqual(await lease.run_with_lease({},self.job,asyncio.sleep(0,result=7),lease_seconds=1),7)
            renew.assert_not_awaited()

    async def test_naive_mongo_utc_deadline(self):
        self.job['lease_until']=self.job['lease_until'].replace(tzinfo=None)
        self.assertEqual(await lease.run_with_lease({},self.job,asyncio.sleep(0,result=4),lease_seconds=1),4)

    async def test_long_work_renews(self):
        with patch.object(lease,'renew',new_callable=AsyncMock,return_value=True) as renew:
            self.assertEqual(await lease.run_with_lease({},self.job,asyncio.sleep(.75,result=9),lease_seconds=1),9)
            self.assertGreaterEqual(renew.await_count,2)

    async def test_lost_lease_cancels_work(self):
        stopped=asyncio.Event()
        async def work():
            try: await asyncio.Event().wait()
            finally: stopped.set()
        with patch.object(lease,'renew',new_callable=AsyncMock,return_value=False):
            with self.assertRaises(lease.ProcessingLeaseLost):
                await lease.run_with_lease({},self.job,work(),lease_seconds=1)
        self.assertTrue(stopped.is_set())

    async def test_renewal_error_cancels_work(self):
        with patch.object(lease,'renew',new_callable=AsyncMock,side_effect=RuntimeError('db down')):
            with self.assertRaises(lease.ProcessingLeaseLost):
                await lease.run_with_lease({},self.job,asyncio.sleep(10),lease_seconds=1)

    async def test_renewal_timeout_is_bounded(self):
        async def slow(*a,**kw): await asyncio.sleep(10)
        with patch.object(lease,'renew',side_effect=slow):
            with self.assertRaises(lease.ProcessingLeaseLost):
                await asyncio.wait_for(lease.run_with_lease({},self.job,asyncio.sleep(10),lease_seconds=1),2)

    async def test_work_error_propagates(self):
        async def fail(): raise ValueError('detection failed')
        with self.assertRaisesRegex(ValueError,'detection failed'):
            await lease.run_with_lease({},self.job,fail(),lease_seconds=1)

    async def test_expired_claim_does_not_start_work(self):
        started=[]
        async def work(): started.append(True)
        self.job['lease_until']=queue._now()-timedelta(seconds=1)
        with self.assertRaises(lease.ProcessingLeaseLost):
            await lease.run_with_lease({},self.job,work(),lease_seconds=1)
        self.assertEqual(started,[])

    async def test_parent_cancel_stops_child(self):
        started=asyncio.Event(); stopped=asyncio.Event()
        async def work():
            started.set()
            try: await asyncio.Event().wait()
            finally: stopped.set()
        task=asyncio.create_task(lease.run_with_lease({},self.job,work(),lease_seconds=1))
        await started.wait(); task.cancel()
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertTrue(stopped.is_set())

if __name__=='__main__': unittest.main()
