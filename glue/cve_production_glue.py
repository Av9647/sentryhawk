import sys, re, boto3
from datetime import datetime, timezone
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import SparkSession, functions as F

# --- Configuration ---
DATABASE = "cve_db"
PROD_TABLE = "cve_production_master"
PROD_PATH = "s3://cve-production/cve_production_tables/"
LOG_BUCKET = "cve-production"
LOG_KEY = "cve_production_logs/cve_production_log.txt"

# Initialize Spark with Iceberg (Glue Data Catalog)
args = getResolvedOptions(sys.argv, ["JOB_NAME"])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = SparkSession.builder \
    .config("spark.sql.catalog.glue_catalog", "org.apache.iceberg.spark.SparkCatalog") \
    .config("spark.sql.catalog.glue_catalog.type", "glue") \
    .config("spark.sql.catalog.glue_catalog.warehouse", PROD_PATH) \
    .config("spark.sql.iceberg.handle-timestamp-without-timezone", "true") \
    .getOrCreate()
job = Job(glueContext)
job.init(args["JOB_NAME"], args)

# Logging helper
log_msgs = []
def log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    log_msgs.append(f"{ts} - {msg}")
    print(f"{ts} - {msg}")

log("Starting CVE production pipeline job.")

# Step 1: Discover latest staging table
STAGING_BASE = "s3://cve-staging/cve_staging_tables/"
s3 = boto3.client("s3")
bucket = STAGING_BASE.split("s3://")[1].split("/")[0]
prefix = "/".join(STAGING_BASE.split("s3://")[1].split("/")[1:])  # "cve_staging_tables/"
resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, Delimiter='/')
if 'CommonPrefixes' not in resp:
    raise Exception(f"No subfolders under {STAGING_BASE}")
latest_table = None
latest_date = None
for cp in resp['CommonPrefixes']:
    folder = cp['Prefix'].rstrip('/')
    m = re.search(r"cve_staging_(\d{4}_\d{2}_\d{2})$", folder)
    if m:
        date_str = m.group(1)  # e.g. "2025_03_17"
        dt = datetime.strptime(date_str, "%Y_%m_%d")
        if latest_date is None or dt > latest_date:
            latest_date = dt
            latest_table = f"cve_staging_{date_str}"
if not latest_table:
    raise Exception("No staging table found.")
log(f"Latest staging table found: {latest_table}")

# Step 2: Read new CVE data from latest staging table
new_df = spark.table(f"glue_catalog.{DATABASE}.{latest_table}")
new_count = new_df.count()
log(f"New staging records loaded: {new_count}")

# Step 3: Dynamic Approach for ANY CVSS version (CVSS score & severity)
# We'll pick the single CVSS entry with the highest baseScore, ignoring version strings.
new_df = new_df.withColumn(
    "chosenCvss",
    F.expr("""
      CASE 
        WHEN cvssData IS NULL OR size(cvssData) = 0 THEN 
          named_struct('source','', 'type','', 'version','', 'vectorString','', 'baseScore', CAST(NULL AS DOUBLE), 'impactScore', CAST(NULL AS DOUBLE), 'exploitabilityScore', CAST(NULL AS DOUBLE))
        ELSE aggregate(
          filter(coalesce(cvssData, array()), x -> x IS NOT NULL AND x.baseScore IS NOT NULL),
          cast(null as struct<source:string, type:string, version:string, vectorString:string, baseScore:double, impactScore:double, exploitabilityScore:double>),
          (acc, x) -> CASE WHEN acc IS NULL OR x.baseScore > acc.baseScore THEN x ELSE acc END,
          acc -> acc
        )
      END
    """)
).withColumn(
    "cvssScore",
    F.col("chosenCvss.baseScore")
).withColumn(
    "cvssVersion",
    F.col("chosenCvss.version")
).withColumn(
    "severity",
    F.when(F.col("cvssScore") >= 9.0, "Critical")
     .when(F.col("cvssScore") >= 7.0, "High")
     .when(F.col("cvssScore") >= 4.0, "Medium")
     .when(F.col("cvssScore").isNotNull(), "Low")
     .otherwise(F.lit(None))
)

# Add SCD2 metadata columns for new records
current_ts = datetime.now(timezone.utc)
new_df = new_df.withColumn("validFrom", F.lit(current_ts)) \
               .withColumn("validTo", F.lit(None).cast("timestamp")) \
               .withColumn("currentFlag", F.lit(True))

new_df.createOrReplaceTempView("new_data")

# Step 4: Create production table if not exists (Iceberg, SCD2 schema)
spark.sql(f"""
CREATE TABLE IF NOT EXISTS glue_catalog.{DATABASE}.{PROD_TABLE} (
    vendor              string,
    product             string,
    cveId               string,
    cweData             ARRAY<STRUCT<cweId:string, cweDescription:string>>,
    capecData           ARRAY<STRUCT<capecId:string, capecDescription:string>>,
    vulnStatus          string,
    cvssData            ARRAY<STRUCT<source:string, type:string, version:string,
                                     vectorString:string, baseScore:double,
                                     impactScore:double, exploitabilityScore:double>>,
    datePublished       timestamp,
    dateReserved        timestamp,
    dateUpdated         timestamp,
    datePublic          timestamp,
    lastModified        timestamp,
    descriptions        string,
    -- SCD Type 2 fields:
    validFrom           timestamp,
    validTo             timestamp,
    currentFlag         boolean,
    -- Derived classification fields:
    cvssScore           double,
    cvssVersion         string,
    severity            string
) 
USING ICEBERG 
PARTITIONED BY (years(datePublished))
LOCATION '{PROD_PATH}{PROD_TABLE}'
""")
log(f"Production table {PROD_TABLE} is ready (created if not exists).")

# Step 5: Merge incremental changes into production table (SCD Type 2 logic)
# Step 5a: Expire old “current” rows only when source.lastModified is non-null
spark.sql(f"""
MERGE INTO glue_catalog.{DATABASE}.{PROD_TABLE} AS target
USING new_data AS source
  ON target.cveId      = source.cveId
 AND target.vendor     = source.vendor
 AND target.product    = source.product
 AND target.currentFlag = true
WHEN MATCHED AND (
     source.lastModified IS NOT NULL
  AND (target.lastModified IS NULL
       OR target.lastModified < source.lastModified)
)
THEN UPDATE SET
     target.validTo      = source.validFrom,
     target.currentFlag = false
""")
log("Expired old records where CVE data changed.")

# Step 5b: Insert new rows (new CVEs or updated CVEs)
spark.sql(f"""
MERGE INTO glue_catalog.{DATABASE}.{PROD_TABLE} AS target
USING new_data AS source
  ON target.cveId      = source.cveId
 AND target.vendor     = source.vendor
 AND target.product    = source.product
 AND target.currentFlag = true
WHEN NOT MATCHED
THEN INSERT *
""")
log("Inserted new current records (new or updated CVEs).")

# Step 6: Logging the execution details to S3
try:
    # Fetch existing log content (to append)
    prev_log = ""
    s3_obj = s3.get_object(Bucket=LOG_BUCKET, Key=LOG_KEY)
    prev_log = s3_obj['Body'].read().decode('utf-8')
except Exception as e:
    prev_log = ""
new_log_content = prev_log + "\n" + "\n".join(log_msgs) + "\n"
s3.put_object(Bucket=LOG_BUCKET, Key=LOG_KEY, Body=new_log_content.encode('utf-8'))
print("Log updated in S3 at s3://cve-production/cve_production_logs/cve_production_log.txt")
job.commit()
