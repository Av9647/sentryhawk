import os
import json
import boto3
import requests
import urllib.parse
from datetime import datetime, timezone

# Initialize SQS client outside handler for re-use
sqs = boto3.client('sqs')
PRODUCT_QUEUE_URL = os.environ['PRODUCT_QUEUE_URL']

def log_message(message):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - {message}")

def fetch_product_list(vendor):
    """
    Retrieve list of products for a given vendor from the CIRCL CVE Search API.
    Endpoint: https://cve.circl.lu/api/browse/{vendor}
    """
    encoded = urllib.parse.quote(vendor)
    url = f"https://cve.circl.lu/api/browse/{encoded}"
    try:
        r = requests.get(url, timeout=60)
        log_message(f"Fetched products for '{vendor}', status {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            return data if isinstance(data, list) else data.get("product", [])
        else:
            return []
    except Exception as e:
        log_message(f"Exception fetching products for '{vendor}': {e}")
        return []

def lambda_handler(event, context):
    records = event.get('Records', [])
    if not records:
        log_message("No SQS messages received.")
        return {"status": "NO_MESSAGES"}

    total_products_sent = 0
    failed_vendors = []

    for rec in records:
        try:
            body = json.loads(rec['body'])
            vendor = body['vendor']
            ingestion_ts = body.get('ingestionTimestamp')
        except Exception as e:
            log_message(f"Error parsing message body: {e}")
            failed_vendors.append(rec.get('messageId'))
            continue

        log_message(f"Processing vendor: {vendor}")
        products = fetch_product_list(vendor)
        if not products:
            log_message(f"No products found for vendor '{vendor}'.")
            continue

        # Enqueue products in batches of up to 10 messages
        for i in range(0, len(products), 10):
            batch = products[i:i+10]
            entries = []
            for idx, product in enumerate(batch):
                payload = {
                    "vendor": vendor,
                    "product": product,
                    "ingestionTimestamp": ingestion_ts
                }
                entries.append({
                    'Id': str(idx),
                    'MessageBody': json.dumps(payload)
                })

            try:
                resp = sqs.send_message_batch(QueueUrl=PRODUCT_QUEUE_URL, Entries=entries)
                failed = resp.get('Failed', [])
                if failed:
                    for f in failed:
                        bad = json.loads(entries[int(f['Id'])]['MessageBody'])
                        log_message(f"Failed to enqueue {bad}: {f['Message']}")
                total_products_sent += len(batch) - len(failed)
            except Exception as e:
                log_message(f"Exception sending product batch for '{vendor}': {e}")

        log_message(f"Processed vendor '{vendor}': {len(products)} products enqueued.")

    result = {"products_enqueued": total_products_sent}
    if failed_vendors:
        result["batchItemFailures"] = [{"itemIdentifier": vid} for vid in failed_vendors]
    return result
