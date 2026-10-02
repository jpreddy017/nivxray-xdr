import asyncio

import pytest

from edr_trajectory.fixtures import REF
from edr_trajectory.service import load, scenario


@pytest.fixture(scope="session")
def ev():
    cache = {}

    def get(sid, tenant=None, device=None, source="merged"):
        s = scenario(sid)
        k = (sid, tenant, device, source)
        if k not in cache:
            cache[k] = asyncio.run(load(sid, tenant or s["tenant_id"], device or s["device_id"], source=source))
        return cache[k]
    return get


@pytest.fixture
def ref():
    return REF
