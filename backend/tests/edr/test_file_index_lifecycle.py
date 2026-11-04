import asyncio
import unittest
from unittest.mock import AsyncMock, patch
from edr_plane import file_index_lifecycle as worker


class Process:
    pid = 123
    def __init__(self, stubborn=False):
        self.returncode = None
        self.exited = asyncio.Event()
        self.stubborn = stubborn
        self.terminated = self.killed = False
    async def wait(self):
        await self.exited.wait()
        return self.returncode
    def exit(self, code):
        self.returncode = code
        self.exited.set()
    def terminate(self):
        self.terminated = True
        if not self.stubborn:
            self.exit(-15)
    def kill(self):
        self.killed = True
        self.exit(-9)


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.patches = [patch.dict('os.environ', {'NIVX_EDR_FILE_INDEX_WORKER_ENABLED':'1'}),
                        patch.object(worker, 'RESTART_SECONDS', .001),
                        patch.object(worker, 'STOP_SECONDS', .02)]
        for p in self.patches: p.start()
    async def asyncTearDown(self):
        await worker.stop_file_index_worker()
        for p in reversed(self.patches): p.stop()
    async def until(self, predicate):
        async def poll():
            while not predicate(): await asyncio.sleep(.001)
        await asyncio.wait_for(poll(), 1)
    async def test_start_once_and_stop(self):
        child=Process()
        with patch.object(asyncio, 'create_subprocess_exec', AsyncMock(return_value=child)) as spawn:
            await worker.start_file_index_worker()
            await worker.start_file_index_worker()
            await self.until(lambda: spawn.call_count == 1)
            await worker.stop_file_index_worker()
            self.assertTrue(child.terminated)
            self.assertIsNone(worker._task)
            self.assertEqual(spawn.call_args.args[1:], ('-m','scripts.edr_file_search_index','--all-registered-tenants','--follow'))
    async def test_restarts_after_exit(self):
        first,second=Process(),Process()
        with patch.object(asyncio, 'create_subprocess_exec', AsyncMock(side_effect=[first,second])) as spawn:
            await worker.start_file_index_worker()
            await self.until(lambda: spawn.call_count == 1)
            first.exit(1)
            await self.until(lambda: spawn.call_count == 2)
            await worker.stop_file_index_worker()
            self.assertTrue(second.terminated)
    async def test_stubborn_child_is_killed(self):
        child=Process(stubborn=True)
        with patch.object(asyncio, 'create_subprocess_exec', AsyncMock(return_value=child)) as spawn:
            await worker.start_file_index_worker()
            await self.until(lambda: spawn.call_count == 1)
            await worker.stop_file_index_worker()
            self.assertTrue(child.killed)
    async def test_disabled_does_not_spawn(self):
        with patch.dict('os.environ', {'NIVX_EDR_FILE_INDEX_WORKER_ENABLED':'0'}), patch.object(asyncio, 'create_subprocess_exec', AsyncMock()) as spawn:
            await worker.start_file_index_worker()
            spawn.assert_not_called()
    async def test_recovers_from_spawn_failure(self):
        child=Process()
        with patch.object(asyncio, 'create_subprocess_exec', AsyncMock(side_effect=[OSError('unavailable'),child])) as spawn:
            await worker.start_file_index_worker()
            await self.until(lambda: spawn.call_count == 2)
            await worker.stop_file_index_worker()
            self.assertTrue(child.terminated)
    async def test_stop_during_spawn(self):
        child=Process()
        async def delayed(*args, **kwargs):
            await asyncio.sleep(.005)
            return child
        with patch.object(asyncio, 'create_subprocess_exec', delayed):
            await worker.start_file_index_worker()
            await asyncio.sleep(0)
            await worker.stop_file_index_worker()
            self.assertTrue(child.terminated)


if __name__ == '__main__': unittest.main()
