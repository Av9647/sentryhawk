import boto3
import time
from datetime import datetime

# AWS Athena Config
ATHENA_DATABASE = "cve_db"
ATHENA_OUTPUT = "s3://cve-staging/cve_dq_table/"
DQ_TABLE = "cve_dq_logs"

# Initialize Athena client
athena_client = boto3.client("athena", region_name="us-east-2")

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

# Step 1: Detect Latest Staging Table
query_detect_staging = """
SHOW TABLES IN glue_catalog.cve_db
"""
athena_client.start_query_execution(
    QueryString=query_detect_staging,
    QueryExecutionContext={"Database": ATHENA_DATABASE},
    ResultConfiguration={"OutputLocation": ATHENA_OUTPUT}
)

# Assuming the output of SHOW TABLES is manually reviewed or fetched externally
latest_staging_table = "cve_staging_2025_03_09"  # This would ideally be detected dynamically

# Step 2: Run DQ Check on Latest Staging Table
dq_query = f"""
INSERT INTO glue_catalog.cve_db.{DQ_TABLE}
SELECT 
    CURRENT_DATE AS dq_date,
    'staging' AS dq_type,
    '{latest_staging_table}' AS source_table,
    COUNT(*) AS total_records,
    SUM(CASE WHEN vendor IS NULL THEN 1 ELSE 0 END) AS null_vendor,
    SUM(CASE WHEN product IS NULL THEN 1 ELSE 0 END) AS null_product,
    SUM(CASE WHEN vulnStatus IS NULL THEN 1 ELSE 0 END) AS null_vulnStatus,
    SUM(CASE WHEN cvssData IS NULL THEN 1 ELSE 0 END) AS null_cvssData,
    SUM(CASE WHEN ingestionTimestamp IS NULL THEN 1 ELSE 0 END) AS null_ingestionTimestamp,
    -- Calculate percentages for monitoring thresholds
    (SUM(CASE WHEN vendor IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) AS pct_null_vendor,
    (SUM(CASE WHEN product IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) AS pct_null_product,
    (SUM(CASE WHEN vulnStatus IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) AS pct_null_vulnStatus,
    (SUM(CASE WHEN cvssData IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) AS pct_null_cvssData
FROM glue_catalog.cve_db.{latest_staging_table}
WHERE ingestionDate = CURRENT_DATE;
"""

# Run the DQ Query
run_athena_query(dq_query)
print("Staging DQ results inserted into DQ logs table.")
