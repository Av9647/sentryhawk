import json
import boto3
import requests
from datetime import datetime

# Constants
BASE_URL = "https://cve.circl.lu/api"
S3_BUCKET = "cve-api-raw-data"  # Change this to your actual S3 bucket name
VENDOR = "microsoft"  # Change this to test different vendors
PRODUCT = "office"  # Change this to test different products

# Initialize S3 client
s3_client = boto3.client("s3")

def fetch_cve_data(vendor, product):
    """
    Fetch CVE data for a given vendor and product from the CIRCL CVE API.
    """
    url = f"{BASE_URL}/search/{vendor}/{product}"
    response = requests.get(url)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching CVE data for {vendor} - {product}: {response.status_code}")
        return None

def store_data_in_s3(data, vendor, product):
    """
    Store fetched CVE data in an S3 bucket.
    """
    if not data:
        print("No data to store in S3.")
        return

    # Generate a timestamped filename
    timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"raw_data/{vendor}_{product}_{timestamp}.json"

    # Convert data to JSON and upload to S3
    s3_client.put_object(
        Bucket=S3_BUCKET,
        Key=file_name,
        Body=json.dumps(data),
        ContentType="application/json"
    )

    print(f"Successfully stored data in S3: {S3_BUCKET}/{file_name}")

def lambda_handler(event, context):
    """
    AWS Lambda entry point
    """
    # Fetch data
    cve_data = fetch_cve_data(VENDOR, PRODUCT)

    # Store in S3
    store_data_in_s3(cve_data, VENDOR, PRODUCT)

    return {
        "statusCode": 200,
        "body": json.dumps("CVE data fetched and stored in S3 successfully!")
    }
