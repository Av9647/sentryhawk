import json
import os
import boto3
import requests

s3 = boto3.client('s3')

# Use environment variables for flexibility (set these in your Lambda configuration)
DRUID_HOST = os.environ.get("DRUID_HOST", "10.0.0.21")         # Use private IP of EC2 when lambda is within VPC
DRUID_PORT = os.environ.get("DRUID_PORT", "8081")
DRUID_ENDPOINT = f"http://{DRUID_HOST}:{DRUID_PORT}/druid/indexer/v1/task"
BUCKET_NAME = os.environ.get("BUCKET_NAME", "cve-code")        # Ensure gateway endpoint is setup for S3 access under VPC console 
PREFIX = os.environ.get("PREFIX", "druid/")

def lambda_handler(event, context):
    """
    Expected event format:
    {
      "filename": "ingestion_spec_lookup.json"
    }
    """
    try:
        # Step 1: Log receipt of the request
        filename = event["filename"]
        print(f"Step 1: Received request to submit ingestion spec: {filename}", flush=True)
    
        # Step 2: Construct the S3 key and attempt to download the file from S3
        key = f"{PREFIX}{filename}"
        print(f"Step 2: About to download the file from S3: bucket={BUCKET_NAME}, key={key}", flush=True)
        s3_object = s3.get_object(Bucket=BUCKET_NAME, Key=key)
        print("Step 2: S3 object retrieved successfully.", flush=True)
    
        # Step 3: Read and parse the file content from S3
        ingestion_spec_str = s3_object["Body"].read().decode("utf-8")
        print("Step 3: Successfully read file contents from S3.", flush=True)
        ingestion_spec = json.loads(ingestion_spec_str)
        print("Step 3: Successfully parsed the JSON ingestion spec.", flush=True)
    
    except Exception as e:
        print(f"Error in S3 retrieval/JSON parsing: {e}", flush=True)
        raise

    try:
        # Step 4: Submit the ingestion spec to the Druid Overlord
        headers = {"Content-Type": "application/json"}
        print(f"Step 4: About to POST the ingestion spec to Druid endpoint: {DRUID_ENDPOINT}", flush=True)
        
        # Set a timeout to avoid hanging indefinitely (adjust the timeout as needed)
        response = requests.post(DRUID_ENDPOINT, headers=headers, json=ingestion_spec, timeout=10)
        print("Step 4: Received a response from Druid.", flush=True)
    
    except requests.exceptions.Timeout as te:
        print(f"Step 4 Error: HTTP request timed out: {te}", flush=True)
        raise
    except Exception as e:
        print(f"Step 4 Error: Failed during the HTTP request to Druid: {e}", flush=True)
        raise

    try:
        # Step 5: Check the response for success or failure
        if response.status_code != 200:
            err_msg = f"Step 5 Error: Druid responded with HTTP {response.status_code}: {response.text}"
            print(err_msg, flush=True)
            raise Exception(err_msg)
    
        # Parse the response and extract the task_id
        data = response.json()
        task_id = data.get("task")
        if not task_id:
            raise Exception("Step 5 Error: No 'task' field returned from Druid ingestion submission.")
    
        print(f"Step 5: Successfully submitted the ingestion spec. Druid task ID: {task_id}", flush=True)
    
    except Exception as e:
        print(f"Error in processing Druid response: {e}", flush=True)
        raise
    
    # Step 6: Return the successful output to Step Functions
    return {
        "filename": filename,
        "task_id": task_id,
        "message": f"Submitted spec {filename} to Druid. Task ID: {task_id}"
    }
