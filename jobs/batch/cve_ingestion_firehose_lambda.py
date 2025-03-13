import os
import boto3
import json
import sys
import requests
import urllib.parse
from datetime import datetime, timezone

# Initialize Firehose client
firehose = boto3.client('firehose')

# Environment variable for Firehose delivery stream name
STREAM_NAME = os.environ['cve_ingestion_firehose']

# Record size limit: 1 MB (Firehose max record size)
MAX_RECORD_SIZE = 1 * 1024 * 1024  # 1 MB in bytes

def log_message(message):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - {message}")

def measure_json_size(obj):
    """Return the size in bytes of the JSON-serialized object."""
    return sys.getsizeof(json.dumps(obj))

def fetch_cve_data(vendor, product):
    """
    Fetch CVE data for the given vendor-product combination from the CIRCL API.
    Retain only the keys we care about: 'cvelistv5' and 'fkie_nvd'.
    """
    encoded_vendor = urllib.parse.quote(vendor)
    encoded_product = urllib.parse.quote(product)
    url = f"https://cve.circl.lu/api/search/{encoded_vendor}/{encoded_product}"
    try:
        response = requests.get(url, timeout=10)
        log_message(f"Fetched CVE data for {vendor}-{product} (status {response.status_code})")
        if response.status_code == 200:
            data = response.json()
            result = {}
            if "cvelistv5" in data:
                result["cvelistv5"] = data["cvelistv5"]
            if "fkie_nvd" in data:
                result["fkie_nvd"] = data["fkie_nvd"]
            return result
        else:
            log_message(f"Non-200 status code: {response.status_code}")
            return {}
    except Exception as e:
        log_message(f"Exception fetching CVE data for {vendor}-{product}: {e}")
        return {}

def split_record(record, max_size):
    """
    If the record (with vendor, product, and data) exceeds max_size,
    split it recursively along the largest top-level list.
    Returns a list of records (each guaranteed to be <= max_size if possible).
    """
    current_size = measure_json_size(record)
    if current_size <= max_size:
        return [record]
    
    if isinstance(record, dict):
        # Identify the largest list among keys 'cvelistv5' or 'fkie_nvd'
        largest_key = None
        largest_len = 0
        for key in ["cvelistv5", "fkie_nvd"]:
            value = record.get(key)
            if isinstance(value, list) and len(value) > largest_len:
                largest_key = key
                largest_len = len(value)
        if largest_key is None:
            log_message("WARNING: Record too large but no list found to split; returning as-is.")
            return [record]
        big_list = record[largest_key]
        num_chunks = (current_size // max_size) + 1
        chunk_size = len(big_list) // num_chunks
        if chunk_size == 0:
            chunk_size = 1
        chunks = []
        for i in range(0, len(big_list), chunk_size):
            subset = big_list[i:i+chunk_size]
            new_record = record.copy()
            new_record[largest_key] = subset
            chunks.extend(split_record(new_record, max_size))
        return chunks
    
    if isinstance(record, list):
        num_chunks = (measure_json_size(record) // max_size) + 1
        chunk_size = len(record) // num_chunks
        if chunk_size == 0:
            chunk_size = 1
        results = []
        for i in range(0, len(record), chunk_size):
            subset = record[i:i+chunk_size]
            results.extend(split_record(subset, max_size))
        return results

    return [record]

def lambda_handler(event, context):
    records = event.get("Records", [])
    if not records:
        log_message("No records received.")
        return {"status": "NO_MESSAGES"}
    
    firehose_records = []  # List to collect records for Firehose

    for msg in records:
        try:
            body = json.loads(msg["body"])
        except Exception as e:
            log_message(f"Error parsing message body: {e}")
            continue
        
        vendor = body.get("vendor")
        product = body.get("product")
        if not vendor or not product:
            log_message("Message missing vendor or product.")
            continue
        
        # Fetch and filter CVE data; result will have keys "cvelistv5" and/or "fkie_nvd"
        data = fetch_cve_data(vendor, product)
        
        # Build the record structure with ingestion metadata
        record = {
            "vendor": vendor,
            "product": product,
            "cvelistv5": data.get("cvelistv5"),
            "fkie_nvd": data.get("fkie_nvd"),
            "ingestionTimestamp": datetime.now(timezone.utc).isoformat(),
            "ingestionDate": datetime.now(timezone.utc).strftime("%Y-%m-%d")
        }
        
        # Split the record if its JSON size exceeds 1 MB
        record_chunks = split_record(record, MAX_RECORD_SIZE)
        log_message(f"Data for {vendor}-{product} split into {len(record_chunks)} chunk(s).")
        
        # For each chunk, serialize as NDJSON record and add to Firehose batch
        for chunk in record_chunks:
            record_str = json.dumps(chunk) + "\n"
            encoded_record = record_str.encode('utf-8')
            firehose_records.append({'Data': encoded_record})
    
    # Send records to Firehose in batches (max 500 records per batch)
    MAX_BATCH = 500
    total_sent = 0
    for i in range(0, len(firehose_records), MAX_BATCH):
        batch = firehose_records[i:i+MAX_BATCH]
        try:
            response = firehose.put_record_batch(DeliveryStreamName=STREAM_NAME, Records=batch)
            failed = response.get("FailedPutCount", 0)
            total_sent += (len(batch) - failed)
            if failed:
                for idx, res in enumerate(response["RequestResponses"]):
                    if "ErrorCode" in res:
                        log_message(f"Firehose error: {res['ErrorCode']} - {res.get('ErrorMessage')}")
        except Exception as e:
            log_message(f"Exception sending batch to Firehose: {e}")
    log_message(f"Total records sent to Firehose: {total_sent}")
    return {"status": "OK", "records_sent": total_sent}
