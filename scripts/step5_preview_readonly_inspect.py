"""STEP 5 · PREVIEW-ONLY, READ-ONLY inspection. No writes of any kind."""
import os
import sys

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv("/app/backend/.env")

url = os.environ["MONGO_URL"]
name = os.environ["DB_NAME"]
if "localhost" not in url and "127.0.0.1" not in url:
    sys.exit(f"REFUSING: MONGO_URL is not local/preview: {url.split('@')[-1]}")

db = MongoClient(url, serverSelectionTimeoutMS=5000)[name]
print(f"db={name} (preview, local)")

for coll in ("edr_processing_queue", "edr_raw_events"):
    print(f"\n=== {coll} ===")
    print("exists:", coll in db.list_collection_names())
    print("count :", db[coll].estimated_document_count())
    for ix in db[coll].list_indexes():
        d = dict(ix)
        print("  idx:", d.get("name"), list(d.get("key", {}).items()),
              "unique=" + str(d.get("unique", False)),
              "partial=" + str(d.get("partialFilterExpression")))

q = db.edr_processing_queue
print("\n=== queue state histogram ===")
for row in q.aggregate([{"$group": {"_id": "$state", "n": {"$sum": 1}}}]):
    print("  ", row["_id"], row["n"])

print("\n=== raw evidence contract histogram ===")
for row in db.edr_raw_events.aggregate([
        {"$group": {"_id": "$processing_contract", "n": {"$sum": 1}}}]):
    print("  ", repr(row["_id"]), row["n"])

print("\n=== endpoints currently polling preview (liveness) ===")
for d in db.edr_endpoints.find(
        {}, {"_id": 0, "endpoint_id": 1, "hostname": 1, "status": 1,
             "last_reported_at": 1, "last_seen_at": 1}).limit(10):
    print("  ", d)
