"""Tenant-scoped encrypted EDR provider configuration; no shared DB fallback.

Collection and encryption key are supplied by the EDR host. Provision through a
trusted administrative process, never via the analysis endpoint.
"""
import json
from datetime import datetime, timezone
from cryptography.fernet import Fernet, InvalidToken
from .reputation_transport import CONFIG

NAMES=frozenset(v[3] for v in CONFIG.values())

class SecretStoreUnavailable(RuntimeError):
    pass

class ReputationSecrets:
    def __init__(self, collection, *, encryption_key):
        self.collection=collection
        self.cipher=Fernet(encryption_key)

    @staticmethod
    def identity(tenant_id,name):
        if not isinstance(tenant_id,str) or not tenant_id.strip() or len(tenant_id)>256 or name not in NAMES:
            raise ValueError('explicit tenant and supported EDR credential required')
        return {'tenant_id':tenant_id,'name':name,'schema':'edr-reputation-secret-v1'}

    async def initialize(self):
        await self.collection.create_index([('tenant_id',1),('name',1)],unique=True)

    async def provision(self,tenant_id,name,value):
        identity=self.identity(tenant_id,name)
        if not isinstance(value,str) or not value.strip() or len(value)>8192 or any(ord(c)<32 for c in value):
            raise ValueError('invalid provider credential')
        envelope=json.dumps({**identity,'value':value},sort_keys=True).encode()
        ciphertext=self.cipher.encrypt(envelope).decode()
        try:
            result=await self.collection.update_one(identity,{'$set':{'ciphertext':ciphertext,'updated_at':datetime.now(timezone.utc).isoformat()}},upsert=True)
            if not result.acknowledged:raise SecretStoreUnavailable()
        except Exception:raise SecretStoreUnavailable('EDR secret persistence unavailable') from None

    async def __call__(self,tenant_id,name):
        identity=self.identity(tenant_id,name)
        try:
            doc=await self.collection.find_one(identity)
            if doc is None:return None
            envelope=json.loads(self.cipher.decrypt(doc['ciphertext'].encode()))
            if any(envelope.get(k)!=v for k,v in identity.items()):raise ValueError('identity mismatch')
            value=envelope['value']
            if not isinstance(value,str) or not value:raise ValueError('invalid credential')
            return value
        except Exception:raise SecretStoreUnavailable('EDR secret retrieval unavailable') from None
