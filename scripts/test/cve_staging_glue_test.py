import sys
import re
import os
import boto3
from datetime import datetime, timezone
from functools import reduce
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.functions import (explode, col, upper, from_json, lit, expr, struct, 
                                   collect_list, array_distinct, map_keys, trim, regexp_replace, input_file_name)
from pyspark.sql.types import StructType, StructField, StringType, ArrayType, DoubleType, MapType

# S3 bucket definitions
SOURCE_BUCKET = "s3://cve-ingestion/cve_json/"
STAGING_BUCKET = "s3://cve-staging/cve_staging_tables/"
STAGING_LOG_BUCKET = "s3://cve-staging/"

args = getResolvedOptions(sys.argv, ["JOB_NAME"])
sc = SparkContext()
glueContext = GlueContext(sc)

# Configure Spark with Iceberg settings and s3a for S3 access
spark = SparkSession.builder \
    .config("spark.sql.catalog.glue_catalog", "org.apache.iceberg.spark.SparkCatalog") \
    .config("spark.sql.catalog.glue_catalog.type", "glue") \
    .config("spark.sql.catalog.glue_catalog.warehouse", STAGING_BUCKET) \
    .config("spark.sql.iceberg.handle-timestamp-without-timezone", "true") \
    .config("hive.metastore.client.factory.class", "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory") \
    .config("spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem") \
    .config("spark.hadoop.fs.s3a.fast.upload", "true") \
    .getOrCreate()

job = Job(glueContext)
job.init(args["JOB_NAME"], args)

# Initialize log messages list with timestamped logging
log_messages = []
def add_log(msg):
    log_messages.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

add_log("Starting main processing script.")

# Get current date and set staging table name and location
current_date = datetime.now(timezone.utc).strftime("%Y_%m_%d")
staging_table_name = f"cve_staging_{current_date}"
staging_table_location = f"{STAGING_BUCKET}{staging_table_name}"

#--------------------------------------------------------------------------------------------------#
# Create staging table (if not exists) with dynamic name based on the current date
#--------------------------------------------------------------------------------------------------#
try:
    spark.sql(f"""
        CREATE TABLE IF NOT EXISTS glue_catalog.cve_db.{staging_table_name} (
            ingestionDate date,
            vendor string,
            product string,
            cveId string,
            vulnStatus string,
            cvssData ARRAY<STRUCT<
                source string,
                type string,
                version string,
                vectorString string,
                baseScore double,
                impactScore double,
                exploitabilityScore double
            >>,
            datePublished timestamp,
            dateReserved timestamp,
            dateUpdated timestamp,
            datePublic timestamp,
            lastModified timestamp,
            Descriptions string,
            ingestionTimestamp timestamp
        ) USING ICEBERG
        LOCATION '{STAGING_BUCKET}{staging_table_name}'
        PARTITIONED BY (ingestionDate)
    """)
    add_log(f"Staging table glue_catalog.cve_db.{staging_table_name} created or already exists.")
except Exception as e:
    add_log(f"Error creating staging table: {str(e)}")
    raise

#--------------------------------------------------------------------------------------------------#
# STEP 1: Read all JSON files from the entire directory for the latest ingestion day using a wildcard
#--------------------------------------------------------------------------------------------------#
try:
    # Determine the latest ingestion day from the folder structure using boto3
    add_log("Listing ingestion folders using boto3...")
    s3_client = boto3.client('s3')
    bucket_name = "cve-ingestion"
    prefix = "cve_json/"
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix, Delimiter='/')
    folders = [cp['Prefix'] for cp in response.get('CommonPrefixes', [])]
    add_log(f"Found folders: {folders}")
    
    ingestion_days = []
    for folder in folders:
        m = re.search(r"cve_json/(\d{4}-\d{2}-\d{2})/", folder)
        if m:
            ingestion_days.append(m.group(1))
    if not ingestion_days:
        raise Exception("No ingestion day folders found in S3.")
    latest_day = max(ingestion_days)
    add_log(f"Latest ingestion day determined: {latest_day}")
except Exception as e:
    add_log(f"Error determining ingestion day: {str(e)}")
    raise

# Use wildcard to let Spark list files internally
latest_directory = f"s3a://cve-ingestion/cve_json/{latest_day}/*.json"
add_log(f"Reading all JSON files from directory (wildcard): {latest_directory}")
df_raw = spark.read.option("multiline", "true").json(latest_directory)
df_raw = df_raw.withColumn("source_file", input_file_name())

#--------------------------------------------------------------------------------------------------#
# STEP 2: Extract metadata (vendor, product, ingestionTimestamp) from file names
#--------------------------------------------------------------------------------------------------#
df_raw = df_raw.withColumn("file_name", F.regexp_extract("source_file", r"([^/]+)$", 1))
df_raw = df_raw.withColumn(
    "vendor", F.regexp_extract("file_name", r"^(.+)_cve_.+_raw_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.json$", 1)
).withColumn(
    "product", F.regexp_extract("file_name", r"^.+_cve_(.+)_raw_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.json$", 1)
).withColumn(
    "ingestionTimestamp_str", F.regexp_extract("file_name", r"_raw_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.json$", 1)
)

if df_raw.filter((F.col("vendor") == "") | (F.col("product") == "") | (F.col("ingestionTimestamp_str") == "")).count() > 0:
    add_log("Warning: Some records have missing vendor, product, or ingestionTimestamp_str values.")

df_raw = df_raw.withColumn("ingestionTimestamp", 
                           F.to_timestamp(F.regexp_replace("ingestionTimestamp_str", "_", " "), "yyyy-MM-dd HH-mm-ss")
                          ).drop("ingestionTimestamp_str")
df_raw = df_raw.withColumn("ingestionDate", F.to_date("ingestionTimestamp"))

#--------------------------------------------------------------------------------------------------#
# STEP 3: Process JSON structures (transform cvelistv5 and fkie_nvd) in parallel
#--------------------------------------------------------------------------------------------------#
# --- Process cvelistv5 data ---
cvelistv5_df = df_raw.select(explode("cvelistv5").alias("item")).select(
    col("item")[0].alias("cveId"),
    col("item")[1].alias("details_str")
)
cvelist_schema = StructType([
    StructField("cveMetadata", StructType([
        StructField("datePublished", StringType(), True),
        StructField("dateReserved", StringType(), True),
        StructField("dateUpdated", StringType(), True)
    ]), True),
    StructField("containers", StructType([
        StructField("cna", StructType([
            StructField("datePublic", StringType(), True)
        ]), True)
    ]), True)
])
cvelistv5_df = cvelistv5_df.withColumn("details", from_json(col("details_str"), cvelist_schema)).select(
    "cveId",
    col("details.cveMetadata.datePublished").alias("datePublished"),
    col("details.cveMetadata.dateReserved").alias("dateReserved"),
    col("details.cveMetadata.dateUpdated").alias("dateUpdated"),
    col("details.containers.cna.datePublic").alias("datePublic")
)
cvelistv5_df = cvelistv5_df.withColumn("datePublished", F.to_timestamp("datePublished")) \
                           .withColumn("dateReserved", F.to_timestamp("dateReserved")) \
                           .withColumn("dateUpdated", F.to_timestamp("dateUpdated")) \
                           .withColumn("datePublic", F.to_timestamp("datePublic"))

# --- Process fkie_nvd data ---
fkie_df = df_raw.select(explode("fkie_nvd").alias("item")).select(
    col("item")[0].alias("id"),
    col("item")[1].alias("details_str")
)
fkie_schema = StructType([
    StructField("id", StringType(), True),
    StructField("lastModified", StringType(), True),
    StructField("vulnStatus", StringType(), True),
    StructField("descriptions", ArrayType(StructType([
        StructField("lang", StringType(), True),
        StructField("value", StringType(), True)
    ])), True),
    StructField("metrics", MapType(StringType(), ArrayType(StructType([
        StructField("source", StringType(), True),
        StructField("type", StringType(), True),
        StructField("cvssData", StructType([
            StructField("version", StringType(), True),
            StructField("vectorString", StringType(), True),
            StructField("baseScore", DoubleType(), True)
        ]), True),
        StructField("exploitabilityScore", DoubleType(), True),
        StructField("impactScore", DoubleType(), True)
    ])), True))
])
fkie_df = fkie_df.withColumn("details", from_json(col("details_str"), fkie_schema))
fkie_df = fkie_df.withColumn(
    "englishDescription",
    explode(expr("filter(details.descriptions, x -> x.lang = 'en')"))
).select(
    col("details.id").alias("cveId"),
    col("details.lastModified").alias("lastModified"),
    col("details.vulnStatus").alias("vulnStatus"),
    col("englishDescription.value").alias("Descriptions"),
    col("details.metrics").alias("cvssMetrics")
)
fkie_df = fkie_df.withColumn("lastModified", F.to_timestamp("lastModified"))

cvss_versions = [row["cvssVersion"] for row in fkie_df.select(explode(map_keys(col("cvssMetrics"))).alias("cvssVersion")).distinct().collect()]
cvss_dfs = []
for version in cvss_versions:
    cvss_dfs.append(
        fkie_df.select(
            "cveId", "lastModified", "vulnStatus", "Descriptions",
            explode(col(f"cvssMetrics.{version}")).alias("cvssEntry")
        ).select(
            "cveId", "lastModified", "vulnStatus", "Descriptions",
            struct(
                col("cvssEntry.source").alias("source"),
                col("cvssEntry.type").alias("type"),
                col("cvssEntry.cvssData.version").alias("version"),
                col("cvssEntry.cvssData.vectorString").alias("vectorString"),
                col("cvssEntry.cvssData.baseScore").alias("baseScore"),
                col("cvssEntry.exploitabilityScore").alias("exploitabilityScore"),
                col("cvssEntry.impactScore").alias("impactScore")
            ).alias("cvssData")
        )
    )
df_cvss_flattened = cvss_dfs[0]
for df in cvss_dfs[1:]:
    df_cvss_flattened = df_cvss_flattened.unionByName(df)
df_cvss_combined = df_cvss_flattened.groupBy("cveId", "lastModified", "vulnStatus", "Descriptions").agg(
    collect_list("cvssData").alias("cvssData")
).withColumn("cvssData", array_distinct(col("cvssData")))

cvelistv5_df = cvelistv5_df.withColumn(
    "cveId", F.regexp_replace(upper(trim(col("cveId"))), "[^\\x00-\\x7F]", "")
)
df_cvss_combined = df_cvss_combined.withColumn(
    "cveId", F.regexp_replace(upper(trim(col("cveId"))), "[^\\x00-\\x7F]", "")
)

# Join datasets and add metadata columns
final_df = cvelistv5_df.join(df_cvss_combined, "cveId", "outer") \
    .withColumn("vendor", lit(col("vendor"))) \
    .withColumn("product", lit(col("product"))) \
    .withColumn("ingestionTimestamp", lit(df_raw.select("ingestionTimestamp").first()[0])) \
    .withColumn("ingestionDate", lit(df_raw.select("ingestionDate").first()[0]))

final_columns = [
    "ingestionDate", "vendor", "product",
    "cveId", "vulnStatus", "cvssData", "datePublished", "dateReserved", "dateUpdated", "datePublic",
    "lastModified", "Descriptions", "ingestionTimestamp"
]
final_df = final_df.select(*final_columns)

#--------------------------------------------------------------------------------------------------#
# STEP 4: Merge the processed data into the staging Iceberg table in a single operation
#--------------------------------------------------------------------------------------------------#
final_df.createOrReplaceTempView("final_data")
merge_sql = f"""
MERGE INTO glue_catalog.cve_db.{staging_table_name} as target
USING final_data as source
ON target.cveId = source.cveId
WHEN MATCHED AND (target.dateUpdated <> source.dateUpdated OR target.lastModified <> source.lastModified)
  THEN UPDATE SET *
WHEN NOT MATCHED
  THEN INSERT *
"""
spark.sql(merge_sql)
add_log("Merge executed for all records.")

#--------------------------------------------------------------------------------------------------#
# STEP 5: Write log messages to a log file in the staging_logs folder
#--------------------------------------------------------------------------------------------------#
try:
    log_content = "\n".join(log_messages)
    log_file_key = f"cve_staging_logs/staging_log_{current_date}.txt"
    s3_client.put_object(Bucket=STAGING_LOG_BUCKET.replace("s3://", "").split("/")[0],
                         Key=log_file_key, Body=log_content)
    add_log("Log file written successfully to staging bucket.")
except Exception as log_ex:
    add_log("Failed writing log file: " + str(log_ex))

print("Processing completed. Check cve_staging_logs folder in the staging bucket for log details.")
job.commit()
