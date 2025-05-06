import requests

DRUID_STATUS_ENDPOINT = "http://10.0.0.21:8081/druid/indexer/v1/task"

def lambda_handler(event, context):
    """
    Example Event:
    {
      "task_id": "index_parallel_cve_production_lookup_dmencfhp_2025-04-15T02:07:47.065Z"
    }
    """
    task_id = event.get("task_id")
    if not task_id:
        raise Exception("Missing task_id in the event payload.")

    url = f"{DRUID_STATUS_ENDPOINT}/{task_id}/status"
    response = requests.get(url)

    if response.status_code != 200:
        err_msg = f"Error polling Druid task {task_id} (HTTP {response.status_code}): {response.text}"
        raise Exception(err_msg)

    status_data = response.json()
    # Assume the JSON structure contains a nested status (adjust based on your actual response)
    druid_status = status_data["status"]["status"]
    
    # Return the current status for Step Functions to examine
    return {
        "task_id": task_id,
        "status": druid_status,
        "full_status": status_data
    }
