import os
import json
import gzip
import uuid
import requests
import urllib.parse
from datetime import datetime, timezone
import boto3

# S3 client; bucket is fixed per requirement
s3     = boto3.client("s3")
BUCKET = "cve-ingestion"  

def log_message(msg: str):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} - {msg}")

def fetch_cve_data(vendor: str, product: str) -> dict:
    url = (
        "https://cve.circl.lu/api/search/"
        f"{urllib.parse.quote(vendor)}/{urllib.parse.quote(product)}"
    )
    try:
        resp = requests.get(url, timeout=120)
    except Exception as e:
        log_message(f"ERROR fetching {vendor}-{product}: {e}")
        raise
    log_message(f"Fetched {vendor}-{product}, status {resp.status_code}")
    if resp.status_code != 200:
        raise RuntimeError(f"CVE API for {vendor}-{product} returned {resp.status_code}")
    data = resp.json()
    return {
        "cvelistv5": data.get("cvelistv5", []),
        "fkie_nvd":  data.get("fkie_nvd", [])
    }

def lambda_handler(event, context):
    records = event.get("Records", [])
    if not records:
        log_message("No messages to process.")
        return {"status": "NO_MESSAGES"}

    for msg in records:
        # 1) Parse and validate
        body = json.loads(msg["body"])
        vendor  = body.get("vendor")
        product = body.get("product")
        if not vendor or not product:
            raise RuntimeError("Message missing vendor or product")

        # 2) Ingestion timestamp & date prefix
        ts_in = body.get("ingestionTimestamp")
        ingestion_ts   = ts_in if ts_in else datetime.now(timezone.utc).isoformat()
        ingestion_date = ingestion_ts[:10]  # YYYY‑MM‑DD

        # 3) Fetch CVE data (raises on any error)
        data = fetch_cve_data(vendor, product)

        # 4) Build full record, include availability flag
        has_data = bool(data["cvelistv5"] or data["fkie_nvd"])
        record = {
            "ingestionDate":      ingestion_date,
            "ingestionTimestamp": ingestion_ts,
            "vendor":             vendor,
            "product":            product,
            "cveDataAvailable":   has_data,
            "cvelistv5":          data["cvelistv5"],
            "fkie_nvd":           data["fkie_nvd"]
        }

        # 5) Serialize + gzip
        raw = (json.dumps(record) + "\n").encode("utf-8")
        gz  = gzip.compress(raw)

        # 6) Safely encode vendor/product for filenames
        safe_vendor  = urllib.parse.quote(vendor,  safe='')
        safe_product = urllib.parse.quote(product, safe='')

        # 7) Write to S3 under cve_json/{ingestionDate}/
        key = (
            f"cve_json/{ingestion_date}/{safe_vendor}/"
            f"{safe_vendor}_{safe_product}_{ingestion_date}_{uuid.uuid4()}.json.gz"
        )
        log_message(f"Writing {vendor}-{product} → s3://{BUCKET}/{key}")
        s3.put_object(
            Bucket=BUCKET,
            Key=key,
            Body=gz,
            ContentEncoding="gzip",
            ContentType="application/x-ndjson"
        )

    log_message(f"Successfully wrote {len(records)} objects to S3.")
    return {"status": "OK", "messages": len(records)}
