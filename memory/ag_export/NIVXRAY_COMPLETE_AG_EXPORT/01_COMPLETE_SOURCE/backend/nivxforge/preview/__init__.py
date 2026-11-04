"""Preview subrouter — ADR-0005 read-only Preview UI endpoints.

Every route here is GET-only. Nothing writes to Mongo, nothing
modifies state. Data is served from `/app/memory/` files.
"""
