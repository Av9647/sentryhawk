import json
import boto3
import requests
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Constants
BASE_URL = "https://cve.circl.lu/api"
S3_BUCKET = "cve-api-raw-data"  # Change to your bucket name
RAW_DATA_FOLDER = "raw_data"     # Folder for JSON files
INGESTION_LOG_FOLDER = "ingestion logs"  # Folder for ingestion log files

# Initialize S3 client
s3_client = boto3.client("s3")

def log_message(log_list, message):
    """Append a timestamped message to log_list."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    log_list.append(f"{timestamp} - {message}")

def fetch_all_vendors():
    """Call the List All Vendors API and return the list of vendors."""
    url = f"{BASE_URL}/browse"
    try:
        response = requests.get(url, timeout=10)
        print(f"DEBUG: Status code from {url} => {response.status_code}")
        print(f"DEBUG: Response text => {response.text[:500]}")  # log first 500 chars

        if response.status_code == 200:
            # The API returns a JSON list of vendor strings.
            data = response.json()  
            return data if data else []
        else:
            print(f"DEBUG: Non-200 status code => {response.status_code}")
            return []
    except Exception as e:
        print(f"DEBUG: Exception occurred => {e}")
        return []

def fetch_products_for_vendor(vendor):
    """Call the List Products by Vendor API and return the list of products for a given vendor."""
    url = f"{BASE_URL}/browse/{vendor}"
    try:
        response = requests.get(url, timeout=10)
        print(f"DEBUG: Status code from {url} => {response.status_code}")
        print(f"DEBUG: Response text => {response.text[:500]}")
        if response.status_code == 200:
            # Assume the API returns a JSON list of product names.
            data = response.json()
            return data if data else []
        else:
            print(f"DEBUG: Non-200 status code for vendor {vendor} => {response.status_code}")
            return []
    except Exception as e:
        print(f"DEBUG: Exception occurred for vendor {vendor} => {e}")
        return []

def fetch_cve_data(vendor, product):
    """Call the Search CVEs by Product API and return the JSON response."""
    url = f"{BASE_URL}/search/{vendor}/{product}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error fetching CVE data for {vendor} - {product}: {response.status_code}")
            return None
    except Exception as e:
        print(f"Exception fetching CVE data for {vendor} - {product}: {e}")
        return None

def store_data_in_s3(data, vendor, product, ingestion_day):
    """Store JSON data in S3 under raw_data/{ingestion_day}/."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    file_key = f"{RAW_DATA_FOLDER}/{ingestion_day}/{vendor}_cve_{product}_raw_{timestamp}.json"
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=file_key,
            Body=json.dumps(data),
            ContentType="application/json"
        )
        return True, file_key
    except Exception as e:
        return False, str(e)

def update_ingestion_log(new_logs, ingestion_day):
    """Append new_logs to the ingestion log file stored in S3.
       Log file key: ingestion logs/ingestion_log_{ingestion_day}.txt
    """
    log_file_key = f"{INGESTION_LOG_FOLDER}/ingestion_log_{ingestion_day}.txt"
    try:
        # Attempt to get the existing log
        existing_obj = s3_client.get_object(Bucket=S3_BUCKET, Key=log_file_key)
        existing_log = existing_obj["Body"].read().decode("utf-8")
    except ClientError as e:
        # If the object doesn't exist, start with an empty log.
        if e.response['Error']['Code'] == "NoSuchKey":
            existing_log = ""
        else:
            existing_log = ""
    # Combine logs with newline separation
    combined_log = existing_log + "\n" + "\n".join(new_logs) if existing_log else "\n".join(new_logs)
    # Write back the log file
    s3_client.put_object(
        Bucket=S3_BUCKET,
        Key=log_file_key,
        Body=combined_log,
        ContentType="text/plain"
    )

def lambda_handler(event, context):
    ingestion_day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_list = []
    log_message(log_list, "Starting CVE data ingestion process.")
    
    # Get the vendor list
    vendors = fetch_all_vendors()
    if not vendors:
        log_message(log_list, "No vendors fetched. Exiting process.")
        update_ingestion_log(log_list, ingestion_day)
        return {"statusCode": 500, "body": "No vendors fetched."}
    
    log_message(log_list, f"Fetched {len(vendors)} vendors.")
    
    # Loop over each vendor
    for vendor in vendors:
        log_message(log_list, f"Processing vendor: {vendor}")
        products = fetch_products_for_vendor(vendor)
        if not products:
            log_message(log_list, f"No products found for vendor '{vendor}'. Skipping.")
            continue
        log_message(log_list, f"Found {len(products)} products for vendor '{vendor}'.")
        
        # Loop over each product for this vendor
        for product in products:
            log_message(log_list, f"Fetching CVE data for {vendor} - {product}.")
            cve_data = fetch_cve_data(vendor, product)
            if cve_data is None:
                log_message(log_list, f"Error: No CVE data returned for {vendor} - {product}.")
                continue
            success, info = store_data_in_s3(cve_data, vendor, product, ingestion_day)
            if success:
                log_message(log_list, f"Stored data for {vendor} - {product} at: {info}")
            else:
                log_message(log_list, f"Failed to store data for {vendor} - {product}. Error: {info}")
    
    log_message(log_list, "CVE data ingestion process completed.")
    
    # Write (or update) the ingestion log file in S3
    update_ingestion_log(log_list, ingestion_day)
    
    return {"statusCode": 200, "body": json.dumps("CVE data fetched and stored in S3 successfully!")}
