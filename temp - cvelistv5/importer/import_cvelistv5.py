#!/usr/bin/env python3
import os, glob, json
from git import Repo
from pymongo import MongoClient

REPO_URL   = "https://github.com/CVEProject/cvelistV5.git"
LOCAL_DIR  = "./cvelistV5"
DB_NAME    = "cve-search"
COLL_NAME  = "cvelistv5"

# 1) Clone or update the official CVE List V5 repo
if not os.path.isdir(LOCAL_DIR):
    print("Cloning cvelistV5…")
    Repo.clone_from(REPO_URL, LOCAL_DIR)
else:
    print("Updating cvelistV5…")
    Repo(LOCAL_DIR).remotes.origin.pull()

# 2) Connect to MongoDB
client = MongoClient("mongodb://mongo:27017/")
db     = client[DB_NAME]
coll   = db[COLL_NAME]

# 3) Upsert each CVE JSON file
count = 0
for path in glob.glob(os.path.join(LOCAL_DIR, "cves", "*", "*.json")):
    with open(path) as f:
        rec = json.load(f)
    cve_id = rec["cveMetadata"]["cveId"]
    coll.replace_one({"cveMetadata.cveId": cve_id}, rec, upsert=True)
    count += 1

print(f"[ import_cvelistv5 ] {count} records upserted into {DB_NAME}.{COLL_NAME}")
