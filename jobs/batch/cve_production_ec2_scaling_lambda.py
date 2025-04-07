import boto3
import json
import time
import requests

# ======= CONFIG =======
BUCKET_NAME = 'your-bucket'
PREFIX = 'druid-ingestion-specs/'  # folder containing .json ingestion specs
INSTANCE_ID = 'i-xxxxxxxxxxxxxxxxx'
DRUID_ROUTER_IP = 'http://<router-ip>:8888'
NEW_TYPE = 't3.large'
OLD_TYPE = 't3.medium'

# AWS clients
s3 = boto3.client('s3')
ec2 = boto3.client('ec2')

# ======= FUNCTIONS =======

def get_ingestion_specs():
    specs = []
    response = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=PREFIX)
    for obj in response.get('Contents', []):
        key = obj['Key']
        if key.endswith('.json'):
            data = s3.get_object(Bucket=BUCKET_NAME, Key=key)
            content = json.loads(data['Body'].read())
            specs.append((key, content))
    return specs

def change_instance_type(instance_id, new_type):
    print(f"Stopping instance {instance_id}...")
    ec2.stop_instances(InstanceIds=[instance_id])
    ec2.get_waiter('instance_stopped').wait(InstanceIds=[instance_id])
    
    print(f"Changing instance type to {new_type}...")
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        InstanceType={'Value': new_type}
    )
    
    print("Starting instance...")
    ec2.start_instances(InstanceIds=[instance_id])
    ec2.get_waiter('instance_running').wait(InstanceIds=[instance_id])
    time.sleep(60)  # Give time for Druid to fully come online

def submit_ingestion_task(spec):
    resp = requests.post(
        f"{DRUID_ROUTER_IP}/druid/indexer/v1/task",
        json=spec
    )
    return resp.json()['task']

def wait_for_task(task_id):
    while True:
        resp = requests.get(f"{DRUID_ROUTER_IP}/druid/indexer/v1/task/{task_id}/status").json()
        status = resp['status']['status']
        print(f"Task {task_id}: {status}")
        if status in ['SUCCESS', 'FAILED']:
            return status
        time.sleep(30)

# ======= MAIN HANDLER =======

def lambda_handler(event, context):
    specs = get_ingestion_specs()
    print(f"Found {len(specs)} ingestion specs.")

    # Scale up
    change_instance_type(INSTANCE_ID, NEW_TYPE)

    results = []
    for key, spec in specs:
        print(f"Submitting task from: {key}")
        try:
            task_id = submit_ingestion_task(spec)
            status = wait_for_task(task_id)
            results.append({'key': key, 'task_id': task_id, 'status': status})
        except Exception as e:
            results.append({'key': key, 'error': str(e)})

    # Scale back down
    change_instance_type(INSTANCE_ID, OLD_TYPE)

    return {
        'summary': results
    }
