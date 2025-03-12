import boto3
import time
from datetime import datetime

# AWS Athena Config
ATHENA_DATABASE = "cve_db"
ATHENA_OUTPUT = "s3://cve-api-production-data/trino_results/"
DQ_TABLE = "cve_dq_logs"
PRODUCTION_TABLE = "cve_production"

# Initialize Athena client
athena_client = boto3.client("athena", region_name="us-east-1")

def run_athena_query(query):
    """Executes the given Athena (Trino) query and waits for completion."""
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": ATHENA_DATABASE},
        ResultConfiguration={"OutputLocation": ATHENA_OUTPUT}
    )
    
    query_execution_id = response["QueryExecutionId"]
    print(f"Query started with ID: {query_execution_id}")

    # Wait for query completion
    while True:
        status = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        state = status["QueryExecution"]["Status"]["State"]
        if state in ["SUCCEEDED", "FAILED", "CANCELLED"]:
            break
        time.sleep(2)

    if state == "SUCCEEDED":
        print("Query completed successfully.")
    else:
        print(f"Query failed: {state}")

# Step 1: Run DQ Check on Production Table
dq_query = f"""
INSERT INTO glue_catalog.cve_db.{DQ_TABLE}
SELECT 
    CURRENT_DATE AS dq_date,
    'production' AS dq_type,
    '{PRODUCTION_TABLE}' AS source_table,
    COUNT(*) AS total_records,
    SUM(CASE WHEN vendor IS NULL THEN 1 ELSE 0 END) AS null_vendor,
    SUM(CASE WHEN product IS NULL THEN 1 ELSE 0 END) AS null_product,
    SUM(CASE WHEN vulnStatus IS NULL THEN 1 ELSE 0 END) AS null_vulnStatus,
    SUM(CASE WHEN cvssData IS NULL THEN 1 ELSE 0 END) AS null_cvssData,
    SUM(CASE WHEN lastModified IS NULL THEN 1 ELSE 0 END) AS null_lastModified,
    SUM(CASE WHEN valid_from IS NULL THEN 1 ELSE 0 END) AS null_valid_from,
    SUM(CASE WHEN is_current IS NULL THEN 1 ELSE 0 END) AS null_is_current,
    -- Calculate percentages for monitoring thresholds
    (SUM(CASE WHEN vendor IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) AS pct_null_vendor,
    (SUM(CASE WHEN product IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) AS pct_null_product,
    (SUM(CASE WHEN vulnStatus IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) AS pct_null_vulnStatus,
    (SUM(CASE WHEN cvssData IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) AS pct_null_cvssData,
    (SUM(CASE WHEN lastModified IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) AS pct_null_lastModified
FROM glue_catalog.cve_db.{PRODUCTION_TABLE}
WHERE batch_date = CURRENT_DATE;
"""

# Run the DQ Query
run_athena_query(dq_query)
print("Production DQ results inserted into DQ logs table.")
