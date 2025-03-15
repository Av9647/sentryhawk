import os
import boto3
import json
import sys
import math
import requests
import urllib.parse
from datetime import datetime, timezone

# Initialize Firehose client
firehose = boto3.client('firehose')

# Environment variable for Firehose delivery stream name
STREAM_NAME = os.environ['FIREHOSE_STREAM_NAME']

# Record size limit for each individual record: 1 MB (Firehose max record size is 1,024,000 bytes)
MAX_RECORD_SIZE = 1 * 1024 * 1024  # 1 MB in bytes

# Safety margin (e.g., 10 KB) to leave room for overhead and newline
SAFETY_MARGIN = 10 * 1024  # 10 KB

# Maximum total batch size for PutRecordBatch is 4 MB.
MAX_BATCH_BYTES = 4 * 1024 * 1024  # 4 MB in bytes

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

def recursive_split(record, max_size):
    """
    Recursively splits the record along the candidate key (whose value is a list)
    that contributes the most to the record size, until the JSON-serialized record
    (with a newline) is under Firehose's size limit.
    This function preserves all data.
    """
    encoded = (json.dumps(record) + "\n").encode('utf-8')
    if len(encoded) <= 1024000:
        return [record]
    
    candidate_keys = [k for k, v in record.items() if isinstance(v, list) and len(v) > 1]
    if not candidate_keys:
        log_message("WARNING: Record too large and no candidate key to split; returning as-is.")
        return [record]
    
    max_contrib = 0
    key_to_split = None
    for key in candidate_keys:
        contrib = measure_json_size({key: record[key]})
        if contrib > max_contrib:
            max_contrib = contrib
            key_to_split = key
    if key_to_split is None:
        return [record]
    
    lst = record[key_to_split]
    mid = len(lst) // 2
    rec1 = record.copy()
    rec2 = record.copy()
    rec1[key_to_split] = lst[:mid]
    rec2[key_to_split] = lst[mid:]
    
    return recursive_split(rec1, max_size) + recursive_split(rec2, max_size)

def even_split_record(record, max_size):
    """
    Splits the record evenly based on total size.
    This function estimates the number of chunks needed based on the record's size
    and splits each candidate key (list-type) evenly.
    If any chunk still exceeds max_size, it is recursively split.
    """
    current_size = measure_json_size(record)
    if current_size <= max_size:
        return [record]
    
    candidate_keys = [k for k, v in record.items() if isinstance(v, list)]
    base_record = {k: record[k] for k in record if k not in candidate_keys}
    base_size = measure_json_size(base_record)
    if base_size + SAFETY_MARGIN >= max_size:
        log_message("WARNING: Base record itself is too large!")
        return [record]
    
    desired_chunks = math.ceil(current_size / (max_size - SAFETY_MARGIN))
    log_message(f"Even splitting into {desired_chunks} chunk(s) based on total size {current_size} bytes.")
    
    split_data = {}
    for key in candidate_keys:
        lst = record.get(key, [])
        n = len(lst)
        chunk_size = max(1, math.ceil(n / desired_chunks)) if desired_chunks > 0 else n
        split_data[key] = [lst[i:i+chunk_size] for i in range(0, n, chunk_size)]
        while len(split_data[key]) < desired_chunks:
            split_data[key].append([])
    
    chunks = []
    for i in range(desired_chunks):
        new_chunk = base_record.copy()
        for key in candidate_keys:
            new_chunk[key] = split_data[key][i] if i < len(split_data[key]) else []
        if measure_json_size(new_chunk) + SAFETY_MARGIN > max_size:
            sub_chunks = even_split_record(new_chunk, max_size)
            chunks.extend(sub_chunks)
        else:
            chunks.append(new_chunk)
    
    return chunks

def split_record(record, max_size):
    """
    Attempts an even split first; if that produces any chunk still over the limit,
    falls back to recursive splitting on that chunk.
    """
    chunks = even_split_record(record, max_size)
    final_chunks = []
    for chunk in chunks:
        encoded = (json.dumps(chunk) + "\n").encode('utf-8')
        if len(encoded) > 1024000:
            sub_chunks = recursive_split(chunk, max_size)
            final_chunks.extend(sub_chunks)
        else:
            final_chunks.append(chunk)
    return final_chunks

def create_batches(records, max_batch_bytes):
    """
    Groups the list of Firehose records (each a dict with key 'Data')
    into batches such that the total byte size of each batch does not exceed max_batch_bytes.
    Returns a list of batches (each a list of records).
    """
    batches = []
    current_batch = []
    current_size = 0
    for rec in records:
        rec_size = len(rec['Data'])
        # If adding this record would exceed the max, finalize the current batch.
        if current_size + rec_size > max_batch_bytes and current_batch:
            batches.append(current_batch)
            current_batch = []
            current_size = 0
        current_batch.append(rec)
        current_size += rec_size
    if current_batch:
        batches.append(current_batch)
    return batches

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
        
        # Fetch CVE data
        data = fetch_cve_data(vendor, product)
        
        # Build the complete record with ingestion metadata.
        record = {
            "vendor": vendor,
            "product": product,
            "cvelistv5": data.get("cvelistv5", []),
            "fkie_nvd": data.get("fkie_nvd", []),
            "ingestionTimestamp": datetime.now(timezone.utc).isoformat(),
            "ingestionDate": datetime.now(timezone.utc).strftime("%Y-%m-%d")
        }
        
        # Split the record so that each chunk is under MAX_RECORD_SIZE.
        record_chunks = split_record(record, MAX_RECORD_SIZE)
        log_message(f"Data for {vendor}-{product} split into {len(record_chunks)} chunk(s).")
        
        for chunk in record_chunks:
            record_str = json.dumps(chunk) + "\n"
            encoded_record = record_str.encode('utf-8')
            if len(encoded_record) > 1024000:
                log_message("Warning: A chunk still exceeds Firehose limit; skipping this chunk.")
                continue
            firehose_records.append({'Data': encoded_record})
    
    # Create batches that do not exceed MAX_BATCH_BYTES (4 MB).
    batches = create_batches(firehose_records, MAX_BATCH_BYTES)
    log_message(f"Total firehose records: {len(firehose_records)} split into {len(batches)} batch(es).")
    
    total_sent = 0
    for batch in batches:
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
