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
STREAM_NAME = os.environ['FIREHOSE_STREAM_NAME']

# Record size limit: 1 MB (Firehose max record size is 1,024,000 bytes)
MAX_RECORD_SIZE = 1 * 1024 * 1024  # 1 MB in bytes

# Safety margin (10 KB) to leave room for overhead and newline
SAFETY_MARGIN = 10 * 1024  # 10 KB

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
        response = requests.get(url, timeout=30)
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

def split_chunk_to_fit(candidate, key, max_size):
    """
    Given a candidate record that is too large, reduce the number of items in candidate[key]
    by halving, until the serialized size fits within max_size.
    """
    items = candidate[key]
    while measure_json_size(candidate) > max_size and len(items) > 1:
        new_count = max(1, len(items) // 2)
        candidate[key] = items[:new_count]
        items = candidate[key]
    return candidate

def split_record(record, max_size):
    """
    Splits a record if its JSON size exceeds max_size.
    This function computes the overhead (base record without large keys),
    estimates how many items can fit, and splits the largest list accordingly.
    If a chunk still exceeds the size limit, it further reduces the chunk.
    """
    current_size = measure_json_size(record)
    if current_size <= max_size:
        return [record]
    
    # Candidate keys holding large data
    candidate_keys = ["cvelistv5", "fkie_nvd"]
    # Build base record (exclude candidate keys)
    base_record = {k: record[k] for k in record if k not in candidate_keys}
    overhead = measure_json_size(base_record)
    
    # Identify the largest key among candidate_keys
    largest_key = None
    largest_len = 0
    for key in candidate_keys:
        value = record.get(key)
        if isinstance(value, list) and len(value) > largest_len:
            largest_key = key
            largest_len = len(value)
    if largest_key is None:
        log_message("WARNING: Record too large and no splittable key found; returning as-is.")
        return [record]
    
    big_list = record[largest_key]
    if not big_list:
        return [record]
    
    # Estimate average size per item
    sample_item = big_list[0]
    sample_size = measure_json_size(sample_item)
    if sample_size == 0:
        sample_size = 1
    
    # Compute available size for items after subtracting overhead and safety margin
    available_size = max_size - overhead - SAFETY_MARGIN
    max_items = available_size // sample_size if available_size >= sample_size else 1

    log_message(f"Splitting using key '{largest_key}', overhead={overhead} bytes, "
                f"sample_size={sample_size} bytes, initial max_items per chunk={max_items}")
    
    chunks = []
    total_items = len(big_list)
    for i in range(0, total_items, max_items):
        new_record = base_record.copy()
        new_record[largest_key] = big_list[i:i+max_items]
        # Ensure the new record fits within max_size; if not, reduce further.
        if measure_json_size(new_record) > max_size:
            new_record = split_chunk_to_fit(new_record, largest_key, max_size)
        chunks.append(new_record)
    
    return chunks

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
        
        # Build the record with metadata
        record = {
            "vendor": vendor,
            "product": product,
            "cvelistv5": data.get("cvelistv5"),
            "fkie_nvd": data.get("fkie_nvd"),
            "ingestionTimestamp": datetime.now(timezone.utc).isoformat(),
            "ingestionDate": datetime.now(timezone.utc).strftime("%Y-%m-%d")
        }
        
        # Split record if needed
        record_chunks = split_record(record, MAX_RECORD_SIZE)
        log_message(f"Data for {vendor}-{product} split into {len(record_chunks)} chunk(s).")
        
        # Serialize each chunk and add to Firehose batch if within limit
        for chunk in record_chunks:
            record_str = json.dumps(chunk) + "\n"
            encoded_record = record_str.encode('utf-8')
            if len(encoded_record) > 1024000:
                log_message("Warning: Chunk size still exceeds Firehose limit; skipping this chunk.")
                continue
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
