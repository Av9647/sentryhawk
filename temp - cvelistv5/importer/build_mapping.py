#!/usr/bin/env python3
from pymongo import MongoClient

DB_NAME      = "cve-search"
NVD_COLL     = "fkie_nvd"               # <-- updated
CVELIST_COLL = "cvelistv5"
MAP_NVD      = "map_vendor_product_nvd"
MAP_CVELIST  = "map_vendor_product_cvelistv5"

client = MongoClient("mongodb://mongo:27017/")
db     = client[DB_NAME]

# Drop old mapping collections
db[MAP_NVD].drop()
db[MAP_CVELIST].drop()

# 1) Build NVD → vendor/product map via CPEs
print("Building map_vendor_product_nvd…")
pipeline_nvd = [
  {"$unwind": "$configurations.nodes"},
  {"$unwind": "$configurations.nodes.cpe_match"},
  {"$project": {
     "cve": "$cveMetadata.cveId",
     "cpe":  "$configurations.nodes.cpe_match.criteria"
  }},
  {"$project": {
     "cve": 1,
     "vendor":  {"$arrayElemAt":[{"$split":["$cpe",":"]},3]},
     "product": {"$arrayElemAt":[{"$split":["$cpe",":"]},4]}
  }},
  {"$group":{
     "_id": {"vendor":"$vendor","product":"$product"},
     "cves": {"$addToSet":"$cve"}
  }},
  {"$merge":{
     "into": MAP_NVD,
     "on":   "_id",
     "whenMatched":"replace",
     "whenNotMatched":"insert"
  }}
]
db[NVD_COLL].aggregate(pipeline_nvd, allowDiskUse=True)
print(" →", db[MAP_NVD].count_documents({}), "entries")

# 2) Build Official List → vendor/product map via CNA-affected
print("Building map_vendor_product_cvelistv5…")
pipeline_cl = [
  {"$unwind": "$containers.cna.affected"},
  {"$group": {
     "_id": {
       "vendor":  "$containers.cna.affected.vendor",
       "product": "$containers.cna.affected.product"
     },
     "cves": {"$addToSet":"$cveMetadata.cveId"}
  }},
  {"$merge":{
     "into": MAP_CVELIST,
     "on":   "_id",
     "whenMatched":"replace",
     "whenNotMatched":"insert"
  }}
]
db[CVELIST_COLL].aggregate(pipeline_cl, allowDiskUse=True)
print(" →", db[MAP_CVELIST].count_documents({}), "entries")
