import os
import boto3
import json
import requests
from datetime import datetime, timezone
import urllib.parse  # For URL encoding vendor names

# Initialize SQS client outside handler for re-use
sqs = boto3.client('sqs')
PRODUCT_QUEUE_URL = os.environ['PRODUCT_QUEUE_URL']

def log_message(message):
    """Log a message with a UTC timestamp."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - {message}")

def fetch_product_list(vendor):
    """
    Retrieve list of products for a given vendor from the CIRCL CVE Search API.
    Endpoint: https://cve.circl.lu/api/browse/{vendor}
    """
    # URL encode the vendor name to safely include it in the URL
    encoded_vendor = urllib.parse.quote(vendor)
    url = f"https://cve.circl.lu/api/browse/{encoded_vendor}"
    try:
        response = requests.get(url, timeout=10)
        log_message(f"DEBUG: Fetched products for vendor '{vendor}' with status code {response.status_code}")
        log_message(f"DEBUG: Response text (truncated): {response.text[:500]}")
        if response.status_code == 200:
            data = response.json()
            # The API returns a JSON object. Typically, the list of products is under the "product" key.
            products = data.get("product", [])
            return products
        else:
            log_message(f"DEBUG: Non-200 status code received: {response.status_code}")
            return []
    except Exception as e:
        log_message(f"DEBUG: Exception occurred while fetching products for vendor '{vendor}': {e}")
        return []

def lambda_handler(event, context):
    records = event.get('Records', [])
    if not records:
        log_message("No SQS messages received.")
        return {"status": "NO_MESSAGES"}
    
    failed_vendors = []  # To keep track of any failures
    total_products_sent = 0

    for record in records:
        vendor = record.get('body')
        log_message(f"Processing vendor: {vendor}")
        try:
            products = fetch_product_list(vendor)
        except Exception as e:
            log_message(f"ERROR: Failed to fetch products for vendor '{vendor}': {e}")
            failed_vendors.append(record.get('messageId'))
            continue

        if not products:
            log_message(f"No products found for vendor '{vendor}'. Skipping.")
            continue

        # Enqueue products in batches of up to 10 messages per SQS batch call
        for i in range(0, len(products), 10):
            batch = products[i:i+10]
            entries = []
            for idx, product in enumerate(batch):
                body = json.dumps({"vendor": vendor, "product": product})
                entries.append({
                    'Id': str(idx),  # Unique batch ID
                    'MessageBody': body
                })
            try:
                resp = sqs.send_message_batch(QueueUrl=PRODUCT_QUEUE_URL, Entries=entries)
                if 'Failed' in resp and resp['Failed']:
                    for f in resp['Failed']:
                        failed_msg = json.loads(entries[int(f['Id'])]['MessageBody'])
                        log_message(f"Failed to enqueue {failed_msg}: {f['Message']}")
                total_products_sent += len(batch) - len(resp.get('Failed', []))
            except Exception as e:
                log_message(f"Exception sending product batch for vendor '{vendor}': {e}")
        log_message(f"Processed vendor '{vendor}': {len(products)} products enqueued.")
    
    result = {"products_enqueued": total_products_sent}
    if failed_vendors:
        result["batchItemFailures"] = [{"itemIdentifier": vid} for vid in failed_vendors]
    return result
