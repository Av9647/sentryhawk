import os
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

    entries = [{'Id': str(idx), 'MessageBody': vendor} for idx, vendor in enumerate(FAANG_VENDORS)]
    total_sent = 0
    batch_size = 10

    for i in range(0, len(entries), batch_size):
        batch = entries[i:i+batch_size]
        try:
            response = sqs.send_message_batch(QueueUrl=VENDOR_QUEUE_URL, Entries=batch)
            if 'Failed' in response and response['Failed']:
                for f in response['Failed']:
                    failed_vendor = batch[int(f['Id'])]['MessageBody'] if f.get('Id') and f['Id'].isdigit() else "Unknown"
                    log_message(f"Failed to enqueue vendor {failed_vendor}: {f['Message']}")
            total_sent += len(batch) - len(response.get('Failed', []))
        except Exception as e:
            log_message(f"Exception sending message batch: {e}")

    log_message(f"Enqueued {total_sent} FAANG vendor messages to SQS.")
    return {"faang_vendors_enqueued": total_sent}
