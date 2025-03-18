import sys, re, time, boto3
from datetime import datetime, timezone
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import SparkSession, functions as F

# --------------- Configuration ---------------
DATABASE = "cve_db"  
DQ_TABLE = "cve_staging_dq"      # Final table will be glue_catalog.cve_db.cve_staging_dq
DQ_TABLE_LOCATION = "s3://cve-staging/cve_staging_dq/cve_staging_dq"  
# Base folder where Iceberg staging tables reside:
STAGING_BASE_PATH = "s3://cve-staging/cve_staging_tables/"
LOG_BUCKET = "cve-staging"
LOG_KEY = "cve_staging_dq_logs/cve_staging_dq_logs.txt"

args = getResolvedOptions(sys.argv, ["JOB_NAME"])

# --------------- Initialize Spark/Glue ---------------
sc = SparkContext()
glueContext = GlueContext(sc)
spark = SparkSession.builder \
    .config("spark.eventLog.enabled", "false") \
    .config("spark.sql.catalog.glue_catalog", "org.apache.iceberg.spark.SparkCatalog") \
    .config("spark.sql.catalog.glue_catalog.type", "glue") \
    .config("spark.sql.catalog.glue_catalog.warehouse", STAGING_BASE_PATH) \
    .config("spark.sql.iceberg.handle-timestamp-without-timezone", "true") \
    .getOrCreate()

job = Job(glueContext)
job.init(args["JOB_NAME"], args)

# --------------- Logging Helper ---------------
log_messages = []
def add_log(msg):
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    log_messages.append(f"{timestamp} - {msg}")
    print(f"{timestamp} - {msg}")

add_log("Starting DQ check script.")

# --------------- Step 1: Discover Latest Staging Table from S3 ---------------
s3_client = boto3.client("s3")
base_bucket = STAGING_BASE_PATH.split("s3://")[1].split("/")[0]
base_prefix = "/".join(STAGING_BASE_PATH.split("s3://")[1].split("/")[1:])
response = s3_client.list_objects_v2(Bucket=base_bucket, Prefix=base_prefix, Delimiter='/')
if 'CommonPrefixes' not in response:
    raise Exception("No subfolders found under " + STAGING_BASE_PATH)

latest_table = None
latest_date = None
for cp in response['CommonPrefixes']:
    # Expecting subfolder like "cve_staging_tables/cve_staging_2025_03_17/"
    folder = cp['Prefix'].rstrip('/')
    m = re.search(r"(cve_staging_\d{4}_\d{2}_\d{2})$", folder)
    if m:
        table_name = m.group(1)  # e.g. "cve_staging_2025_03_17"
        dmatch = re.search(r"(\d{4}_\d{2}_\d{2})", table_name)
        if dmatch:
            dt_str = dmatch.group(1).replace("_", "-")
            dt = datetime.strptime(dt_str, "%Y-%m-%d")
            if latest_date is None or dt > latest_date:
                latest_date = dt
                latest_table = table_name

if not latest_table:
    raise Exception("No staging table found in S3.")

add_log(f"Latest staging table discovered: {latest_table}")

# --------------- Step 2: Compute DQ Metrics from Latest Staging Table using Spark SQL ---------------
# Assumes your staging table is registered as glue_catalog.cve_db.<latest_table>
df = spark.table(f"glue_catalog.{DATABASE}.{latest_table}")

agg_df = df.agg(
    F.count("*").alias("total"),
    F.sum(F.when(F.col("vendor").isNull(), 1).otherwise(0)).alias("vendor_nulls"),
    F.sum(F.when(F.col("product").isNull(), 1).otherwise(0)).alias("product_nulls"),
    F.sum(F.when(F.col("cveId").isNull(), 1).otherwise(0)).alias("cveId_nulls"),
    F.sum(F.when(F.col("cweData").isNull(), 1).otherwise(0)).alias("cweData_nulls"),
    F.sum(F.when(F.col("capecData").isNull(), 1).otherwise(0)).alias("capecData_nulls"),
    F.sum(F.when(F.col("vulnStatus").isNull(), 1).otherwise(0)).alias("vulnStatus_nulls"),
    F.sum(F.when(F.col("cvssData").isNull(), 1).otherwise(0)).alias("cvssData_nulls"),
    F.sum(F.when(F.col("datePublished").isNull(), 1).otherwise(0)).alias("datePublished_nulls"),
    F.sum(F.when(F.col("dateReserved").isNull(), 1).otherwise(0)).alias("dateReserved_nulls"),
    F.sum(F.when(F.col("dateUpdated").isNull(), 1).otherwise(0)).alias("dateUpdated_nulls"),
    F.sum(F.when(F.col("datePublic").isNull(), 1).otherwise(0)).alias("datePublic_nulls"),
    F.sum(F.when(F.col("lastModified").isNull(), 1).otherwise(0)).alias("lastModified_nulls"),
    F.sum(F.when(F.col("Descriptions").isNull(), 1).otherwise(0)).alias("Descriptions_nulls")
)

dq_row = agg_df.collect()[0]
total = dq_row["total"]

def calc_percent(null_count):
    return round(100.0 * null_count / total, 2) if total > 0 else 0.0

add_log("DQ metrics computed.")

# --------------- Step 3: Create DQ Table if Not Exists using Spark SQL ---------------
create_dq_table_sql = f"""
CREATE TABLE IF NOT EXISTS glue_catalog.{DATABASE}.{DQ_TABLE} (
    dqcheckDate date,
    dqcheckTimestamp timestamp,
    stagingTableName string,
    totalRecords bigint,
    vendorPercentNull double,
    productPercentNull double,
    cveIdPercentNull double,
    cweDataPercentNull double,
    capecDataPercentNull double,
    vulnStatusPercentNull double,
    cvssDataPercentNull double,
    datePublishedPercentNull double,
    dateReservedPercentNull double,
    dateUpdatedPercentNull double,
    datePublicPercentNull double,
    lastModifiedPercentNull double,
    DescriptionsPercentNull double,
    vendorNulls bigint,
    productNulls bigint,
    cveIdNulls bigint,
    cweDataNulls bigint,
    capecDataNulls bigint,
    vulnStatusNulls bigint,
    cvssDataNulls bigint,
    datePublishedNulls bigint,
    dateReservedNulls bigint,
    dateUpdatedNulls bigint,
    datePublicNulls bigint,
    lastModifiedNulls bigint,
    DescriptionsNulls bigint
) USING ICEBERG
LOCATION '{DQ_TABLE_LOCATION}'
PARTITIONED BY (dqcheckDate)
"""
spark.sql(create_dq_table_sql)
add_log("DQ table ensured.")

# --------------- Step 4: Insert DQ Metrics into the DQ Table using Spark SQL ---------------
dqcheckTimestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
# For the dqcheckDate partition, we use the date part of dqcheckTimestamp
dqcheckDate = dqcheckTimestamp.split()[0]

insert_dq_sql = f"""
INSERT INTO glue_catalog.{DATABASE}.{DQ_TABLE}
VALUES (
    DATE('{dqcheckDate}'),
    TIMESTAMP '{dqcheckTimestamp}',
    '{latest_table}',
    {total},
    {calc_percent(dq_row['vendor_nulls'])},
    {calc_percent(dq_row['product_nulls'])},
    {calc_percent(dq_row['cveId_nulls'])},
    {calc_percent(dq_row['cweData_nulls'])},
    {calc_percent(dq_row['capecData_nulls'])},
    {calc_percent(dq_row['vulnStatus_nulls'])},
    {calc_percent(dq_row['cvssData_nulls'])},
    {calc_percent(dq_row['datePublished_nulls'])},
    {calc_percent(dq_row['dateReserved_nulls'])},
    {calc_percent(dq_row['dateUpdated_nulls'])},
    {calc_percent(dq_row['datePublic_nulls'])},
    {calc_percent(dq_row['lastModified_nulls'])},
    {calc_percent(dq_row['Descriptions_nulls'])},
    {dq_row['vendor_nulls']},
    {dq_row['product_nulls']},
    {dq_row['cveId_nulls']},
    {dq_row['cweData_nulls']},
    {dq_row['capecData_nulls']},
    {dq_row['vulnStatus_nulls']},
    {dq_row['cvssData_nulls']},
    {dq_row['datePublished_nulls']},
    {dq_row['dateReserved_nulls']},
    {dq_row['dateUpdated_nulls']},
    {dq_row['datePublic_nulls']},
    {dq_row['lastModified_nulls']},
    {dq_row['Descriptions_nulls']}
)
"""
spark.sql(insert_dq_sql)
add_log("DQ metrics inserted into DQ table.")

# --------------- Step 5: Write Run Details to S3 Log ---------------
log_content = "\n".join(log_messages)
boto3.client("s3").put_object(Bucket=LOG_BUCKET, Key=LOG_KEY, Body=log_content)
add_log("Run details logged to S3.")

add_log("DQ check completed successfully.")

job.commit()
