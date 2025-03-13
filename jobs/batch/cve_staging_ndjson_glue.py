import sys
import re
import os
import boto3
from datetime import datetime, timezone
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import SparkSession, functions as F, types as T
from pyspark.sql.functions import col, explode, from_json, lit, input_file_name

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

# Initialize logging
log_messages = []
def add_log(msg):
    log_messages.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

add_log("Starting main processing script.")

#--------------------------------------------------------------------------------------------------#
# Determine the latest ingestion day from S3 (folders under "cve_json/")
#--------------------------------------------------------------------------------------------------#
try:
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

# Use wildcard to read all gzipped NDJSON files for the latest ingestion day
latest_directory = f"s3a://cve-ingestion/cve_json/{latest_day}/*.ndjson.gz"
add_log(f"Reading all JSON files from directory: {latest_directory}")
# Each line is a complete JSON record; Spark can read gzipped NDJSON files natively.
df_raw = spark.read.option("multiline", "false").json(latest_directory)
df_raw = df_raw.withColumn("source_file", input_file_name())

# Our records now have vendor, product, cvelistv5, fkie_nvd, ingestionTimestamp, ingestionDate at the root.
df_raw = df_raw.withColumn("vendor", col("vendor")) \
               .withColumn("product", col("product")) \
               .withColumn("cvelistv5", col("cvelistv5")) \
               .withColumn("fkie_nvd", col("fkie_nvd")) \
               .withColumn("ingestionTimestamp", col("ingestionTimestamp")) \
               .withColumn("ingestionDate", col("ingestionDate"))

#--------------------------------------------------------------------------------------------------#
# Define schemas for processing nested JSON data (if needed)
#--------------------------------------------------------------------------------------------------#
cvelist_schema = T.StructType([
    T.StructField("cveMetadata", T.StructType([
        T.StructField("datePublished", T.StringType(), True),
        T.StructField("dateReserved", T.StringType(), True),
        T.StructField("dateUpdated", T.StringType(), True)
    ]), True),
    T.StructField("containers", T.StructType([
        T.StructField("cna", T.StructType([
            T.StructField("datePublic", T.StringType(), True)
        ]), True)
    ]), True)
])

fkie_schema = T.StructType([
    T.StructField("id", T.StringType(), True),
    T.StructField("lastModified", T.StringType(), True),
    T.StructField("vulnStatus", T.StringType(), True),
    T.StructField("descriptions", T.ArrayType(T.StructType([
        T.StructField("lang", T.StringType(), True),
        T.StructField("value", T.StringType(), True)
    ])), True),
    T.StructField("metrics", T.MapType(T.StringType(), T.ArrayType(T.StructType([
        T.StructField("source", T.StringType(), True),
        T.StructField("type", T.StringType(), True),
        T.StructField("cvssData", T.StructType([
            T.StructField("version", T.StringType(), True),
            T.StructField("vectorString", T.StringType(), True),
            T.StructField("baseScore", T.DoubleType(), True)
        ]), True),
        T.StructField("exploitabilityScore", T.DoubleType(), True),
        T.StructField("impactScore", T.DoubleType(), True)
    ]))), True)
])

#--------------------------------------------------------------------------------------------------#
# Process cvelistv5 data
#--------------------------------------------------------------------------------------------------#
cvelistv5_df = df_raw.select("vendor", "product", explode("cvelistv5").alias("cvelist_item"))
cvelistv5_df = cvelistv5_df.select(
    "vendor",
    "product",
    col("cvelist_item")[0].alias("cveId"),
    col("cvelist_item")[1].alias("details_str")
)
cvelistv5_df = cvelistv5_df.withColumn("details", from_json(col("details_str"), cvelist_schema)) \
                           .select(
                                "vendor", "product",
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

#--------------------------------------------------------------------------------------------------#
# Process fkie_nvd data
#--------------------------------------------------------------------------------------------------#
fkie_df = df_raw.select("vendor", "product", explode("fkie_nvd").alias("fkie_item"))
fkie_df = fkie_df.select(
    "vendor",
    "product",
    col("fkie_item")[0].alias("id"),
    col("fkie_item")[1].alias("details_str")
)
fkie_df = fkie_df.withColumn("details", from_json(col("details_str"), fkie_schema))
fkie_df = fkie_df.withColumn(
    "englishDescription",
    explode(F.expr("filter(details.descriptions, x -> x.lang = 'en')"))
).select(
    "vendor", "product",
    col("details.id").alias("cveId"),
    col("details.lastModified").alias("lastModified"),
    col("details.vulnStatus").alias("vulnStatus"),
    col("englishDescription.value").alias("Descriptions"),
    col("details.metrics").alias("cvssMetrics")
)
fkie_df = fkie_df.withColumn("lastModified", F.to_timestamp("lastModified"))

#--------------------------------------------------------------------------------------------------#
# Join datasets and add ingestion metadata if needed (they're already present)
#--------------------------------------------------------------------------------------------------#
final_df = cvelistv5_df.join(fkie_df, "cveId", "outer") \
    .withColumn("vendor", F.coalesce(cvelistv5_df.vendor, fkie_df.vendor)) \
    .withColumn("product", F.coalesce(cvelistv5_df.product, fkie_df.product))

final_columns = [
    "ingestionDate", "vendor", "product",
    "cveId", "vulnStatus", "cvssMetrics", "datePublished", "dateReserved", "dateUpdated", "datePublic",
    "lastModified", "Descriptions", "ingestionTimestamp"
]
final_df = final_df.select(*final_columns)

#--------------------------------------------------------------------------------------------------#
# Merge the processed data into the staging Iceberg table
#--------------------------------------------------------------------------------------------------#
staging_table_name = f"cve_staging_{datetime.now(timezone.utc).strftime('%Y_%m_%d')}"
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
    add_log(f"Staging table glue_catalog.cve_db.{staging_table_name} created or exists.")
except Exception as e:
    add_log(f"Error creating staging table: {str(e)}")
    raise

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
# Write log messages to S3 staging logs
#--------------------------------------------------------------------------------------------------#
try:
    log_content = "\n".join(log_messages)
    current_date_str = datetime.now(timezone.utc).strftime("%Y_%m_%d")
    log_file_key = f"cve_staging_logs/staging_log_{current_date_str}.txt"
    s3_client.put_object(Bucket=STAGING_LOG_BUCKET.replace("s3://", "").split("/")[0],
                         Key=log_file_key, Body=log_content)
    add_log("Log file written successfully to staging bucket.")
except Exception as log_ex:
    add_log("Failed writing log file: " + str(log_ex))

print("Processing completed. Check staging logs for details.")
job.commit()
