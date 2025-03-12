import os
import boto3
import json
import requests
from datetime import datetime, timezone
import urllib.parse  # In case vendor names need URL encoding in future use cases

# Initialize SQS client outside handler for re-use (will be reused across invocations if AWS keeps the container warm)
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
            # The API returns a JSON object with a key 'vendor' that contains the list of vendors.
            vendors = data.get("vendor", [])
            return vendors
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
    
    batch_size = 10
    total_sent = 0
    for i in range(0, len(vendors), batch_size):
        batch = vendors[i:i+batch_size]
        entries = []
        for idx, vendor in enumerate(batch):
            entries.append({
                'Id': str(idx),
                'MessageBody': vendor  # Using vendor name as the message body
            })
        try:
            response = sqs.send_message_batch(QueueUrl=VENDOR_QUEUE_URL, Entries=entries)
            # Log any failed messages in the batch
            if 'Failed' in response and response['Failed']:
                for f in response['Failed']:
                    failed_vendor = batch[int(f['Id'])] if f.get('Id') and f['Id'].isdigit() else "Unknown"
                    log_message(f"Failed to enqueue vendor {failed_vendor}: {f['Message']}")
            total_sent += len(batch) - len(response.get('Failed', []))
        except Exception as e:
            log_message(f"Exception sending message batch for vendors {batch}: {e}")
    
    log_message(f"Enqueued {total_sent} vendor messages to SQS.")
    return {"vendors_enqueued": total_sent}
