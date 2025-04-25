#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from pymongo import MongoClient
from fastapi.middleware.cors import CORSMiddleware
import os

# Config via env
MONGO_URI     = os.getenv("MONGO_URI", "mongodb://mongo:27017/")
DB_NAME       = os.getenv("DB_NAME", "cve-search")
NVD_COLL      = os.getenv("NVD_COLL", "fkie_nvd")      # <-- default updated
CVELIST_COLL  = os.getenv("CVELIST_COLL", "cvelistv5")
PORT          = int(os.getenv("API_PORT", 8000))

app = FastAPI(title="Vendor·Product CVE Lookup")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

client    = MongoClient(MONGO_URI)
db        = client[DB_NAME]
nvd_col   = db[NVD_COLL]
cvelist_col = db[CVELIST_COLL]

@app.get("/api/search/{vendor}/{product}")
async def lookup(vendor: str, product: str):
    # Official list: CNA-affected
    clq = {"containers.cna.affected": {"$elemMatch": {"vendor": vendor, "product": product}}}
    cl  = list(cvelist_col.find(clq))
    # NVD mirror: CPE regex
    regex = rf"^cpe:2\.3:[aloh]:{vendor}:{product}:"
    nvdq  = {"configurations.nodes.cpe_match.criteria": {"$regex": regex, "$options": "i"}}
    nvd  = list(nvd_col.find(nvdq))
    if not cl and not nvd:
        raise HTTPException(404, f"No CVEs for {vendor}/{product}")
    return {"cvelistv5": cl, "fkie_nvd": nvd}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("vendor_product_api:app", host="0.0.0.0", port=PORT, reload=True)
