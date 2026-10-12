# Webhook authentication and replay contract

This is an engineering candidate. Production and integration HOLDs remain.

Each webhook URL must identify exactly one configured connector. Signing
configuration must contain a nonempty `credentials.hmac_secret`; unsigned
requests are refused in every environment. Existing custom signature header,
algorithm (`sha256` or `sha1`), and prefix settings remain supported.

Send `X-Timestamp` as a finite Unix timestamp and sign the exact bytes:

```
HMAC(secret, X-Timestamp bytes + b"." + original HTTP body bytes)
```

The signature header accepts the configured prefix followed by hexadecimal
digest, or the bare digest. Hexadecimal case and prefix presence cannot create
a different replay identity. JSON must not be reserialized before verification.
Timestamp-bound signing is mandatory: existing body-only senders must migrate
before this candidate can be deployed. The accepted clock skew is 300 seconds
in either direction. HTTP 401 denotes authentication/replay refusal; HTTP 503
denotes unavailable replay protection. No envelope is delivered on either.

## Shared replay store

Install the collector requirements (including `redis==5.2.1`). Configure
`NIVX_WEBHOOK_REPLAY_REDIS_URL`, or reuse `REDIS_URL`. All replicas serving the
same webhook must use the same Redis database. `rediss://` supports TLS. No
in-memory fallback or bypass exists when configuration or Redis is unavailable.

The Redis operation is one atomic `SET key 1 NX EX 601`. Its key is a digest
of the tenant, stable webhook `secret_id`, signed timestamp, and original body.
It contains no plaintext secret, tenant ID, or event payload. The 601-second
retention covers the complete acceptance window, including future timestamps.
Changing process, connector instance ID, signature prefix, or hex case does not
reset the claim. Request verification runs in a thread pool with one-second
Redis connection and socket timeouts.

Replay protection is at-most-once admission within the signed request window,
not an exactly-once delivery guarantee. Claims are retained after downstream
delivery failures or ambiguous Redis timeouts; deleting them could admit a
request already processed. Delivery recovery and event-level dedup remain owned
by the existing collector pipeline. Sender retry/recovery behavior requires
integration acceptance; a new signed request is distinct from an old replay.

Redis persistence, failover, memory/no-eviction policy, credentials, clock
synchronization, and shared configuration require deployment review. Redis data
loss or premature eviction can erase accepted replay history. This patch does
not certify Redis restart/failover safety or configure infrastructure.

## Validation boundary

Deterministic tests use the production Redis adapter with an atomic Redis double
and synthetic HMACs. They cover concurrent instances and HTTP requests, signed
raw bytes, expired/future/non-finite timestamps, signature representation
variants, missing configuration, and backing-store failures. A real shared Redis
service, production sender migration, and the combined A4+A5 security gate are
still required before release approval.
