# vendor_lambda.py

import os
import json
import boto3
from datetime import datetime, timezone

# Initialize SQS client
sqs = boto3.client('sqs')
VENDOR_QUEUE_URL = os.environ['VENDOR_QUEUE_URL']

# Define FAANG vendors directly
FAANG_VENDORS = ["meta", "apple", "amazon", "netflix", "google", "microsoft", "tesla"]

def log_message(message):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - {message}")

def lambda_handler(event, context):
    log_message("Starting FAANG vendor message enqueuing process.")

    now_iso = datetime.now(timezone.utc).isoformat()
    entries = []
    for idx, vendor in enumerate(FAANG_VENDORS):
        payload = {
            "vendor": vendor,
            "ingestionTimestamp": now_iso
        }
        entries.append({
            'Id': str(idx),
            'MessageBody': json.dumps(payload)
        })

    total_sent = 0
    batch_size = 10

    for i in range(0, len(entries), batch_size):
        batch = entries[i:i+batch_size]
        try:
            response = sqs.send_message_batch(QueueUrl=VENDOR_QUEUE_URL, Entries=batch)
            failed = response.get('Failed', [])
            if failed:
                for f in failed:
                    failed_idx = int(f['Id'])
                    failed_vendor = FAANG_VENDORS[failed_idx]
                    log_message(f"Failed to enqueue vendor {failed_vendor}: {f['Message']}")
            total_sent += len(batch) - len(failed)
        except Exception as e:
            log_message(f"Exception sending message batch: {e}")

    log_message(f"Enqueued {total_sent} FAANG vendor messages to SQS.")
    return {"faang_vendors_enqueued": total_sent}
