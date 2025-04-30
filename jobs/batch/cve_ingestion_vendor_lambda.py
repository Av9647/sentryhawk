import os
import json
import boto3
import requests
from datetime import datetime, timezone
import urllib.parse  # In case vendor names need URL encoding in future use cases

# Initialize SQS client outside handler for re-use (kept warm by AWS if possible)
sqs = boto3.client('sqs')
VENDOR_QUEUE_URL = os.environ['VENDOR_QUEUE_URL']  # SQS queue URL from environment

def log_message(message):
    """Print a log message with a UTC timestamp."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - {message}")

def fetch_vendor_list():
    """Retrieve the list of vendors from the CIRCL CVE Search API with detailed debugging."""
    vendor_api_url = "https://cve.circl.lu/api/browse"
    try:
        response = requests.get(vendor_api_url, timeout=10)
        log_message(f"DEBUG: Fetched vendor list with status code {response.status_code}")
        log_message(f"DEBUG: Response text (truncated): {response.text[:500]}")
        if response.status_code == 200:
            data = response.json()
            # If data is a list, use it directly; otherwise assume dict with key 'vendor'
            return data if isinstance(data, list) else data.get("vendor", [])
        else:
            log_message(f"DEBUG: Non-200 status code received: {response.status_code}")
            return []
    except Exception as e:
        log_message(f"DEBUG: Exception occurred while fetching vendor list: {e}")
        return []

def lambda_handler(event, context):
    log_message("Starting vendor message enqueuing process.")
    
    # Retrieve vendors from the API
    vendors = fetch_vendor_list()
    if not vendors:
        log_message("No vendors found to process. Exiting.")
        return {"status": "NO_VENDORS"}
    
    log_message(f"Retrieved {len(vendors)} vendors. Enqueuing to SQS...")

    # Generate a single ingestion timestamp for this batch
    ingestion_ts = datetime.now(timezone.utc).isoformat()
    
    batch_size = 10
    total_sent = 0

    # Enqueue in batches of up to 10
    for i in range(0, len(vendors), batch_size):
        batch = vendors[i:i+batch_size]
        entries = []
        for idx, vendor in enumerate(batch):
            payload = {
                "vendor": vendor,
                "ingestionTimestamp": ingestion_ts
            }
            entries.append({
                'Id': str(idx),
                'MessageBody': json.dumps(payload)
            })
        try:
            response = sqs.send_message_batch(QueueUrl=VENDOR_QUEUE_URL, Entries=entries)
            failed = response.get('Failed', [])
            if failed:
                for f in failed:
                    failed_idx = int(f['Id'])
                    failed_vendor = batch[failed_idx] if failed_idx < len(batch) else "Unknown"
                    log_message(f"Failed to enqueue vendor {failed_vendor}: {f['Message']}")
            total_sent += len(entries) - len(failed)
        except Exception as e:
            log_message(f"Exception sending message batch for vendors {batch}: {e}")
    
    log_message(f"Enqueued {total_sent} vendor messages to SQS.")
    return {"vendors_enqueued": total_sent}
