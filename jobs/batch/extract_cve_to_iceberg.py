
import sys
import re
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.functions import col, expr, from_json, current_timestamp
from pyspark.sql.types import StructType, StructField, StringType, DoubleType

# AWS S3 Paths
RAW_S3_BUCKET = "s3://cve-api-raw-data/raw_data/"
STAGING_S3_BUCKET = "s3://cve-api-staging-data/iceberg_tables/"

# Glue Job Arguments
args = getResolvedOptions(sys.argv, ["JOB_NAME"])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args["JOB_NAME"], args)

spark = SparkSession.builder \
    .config("spark.sql.catalog.glue_catalog", "org.apache.iceberg.spark.SparkCatalog") \
    .config("spark.sql.catalog.glue_catalog.type", "glue") \
    .config("spark.sql.catalog.glue_catalog.warehouse", STAGING_S3_BUCKET) \
    .config("spark.sql.iceberg.handle-timestamp-without-timezone", "true") \
    .config("hive.metastore.client.factory.class", "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory") \
    .enableHiveSupport() \
    .getOrCreate()

# -------------------------------
# Step 1. Determine Latest File per Vendor-Product
# -------------------------------
all_files = spark.read.format("json").load(RAW_S3_BUCKET)
file_names_df = all_files.select(F.input_file_name().alias("file_path"))

# Extract timestamp and vendor_product from filename pattern: vendor_product_YYYY-MM-DD_HH-MM-SS.json
file_names_df = file_names_df.withColumn(
    "timestamp", F.regexp_extract("file_path", r"(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})", 1)
).withColumn(
    "vendor_product", F.regexp_extract("file_path", r"([^/]+)_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.json", 1)
)

latest_files = file_names_df.groupBy("vendor_product").agg(F.max("timestamp").alias("latest_timestamp"))
latest_files = latest_files.withColumn(
    "latest_file_path",
    F.concat(F.lit(RAW_S3_BUCKET), F.col("vendor_product"), F.lit("_"), F.col("latest_timestamp"), F.lit(".json"))
)

latest_files_paths = [row.latest_file_path for row in latest_files.collect()]

# -------------------------------
# Step 2. Load Latest Files and Add Source File Info
# -------------------------------
df_raw = spark.read.option("multiline", "true").json(latest_files_paths) \
    .withColumn("source_file", F.input_file_name())

# -------------------------------
# Step 3. Extract Vendor and Product from Filename
# -------------------------------
df_raw = df_raw.withColumn("file_name", F.regexp_extract("source_file", r"([^/]+)$", 1))
df_raw = df_raw.withColumn("vendor", F.regexp_extract("file_name", r"^([a-zA-Z]+)_", 1)) \
               .withColumn("product", F.regexp_extract("file_name", r"^[a-zA-Z]+_([a-zA-Z]+)_", 1))

# -------------------------------
# Step 4. Explode the JSON Array and Extract CVE Details
# -------------------------------
df_exploded = df_raw.select("vendor", "product", F.explode("cvelistv5").alias("cve_entry"))
df_exploded = df_exploded.withColumn("cveId", col("cve_entry").getItem(0)) \
    .withColumn("details", col("cve_entry").getItem(1))

# -------------------------------
# Step 5. Parse the 'details' JSON String into a Struct
# -------------------------------
details_schema = StructType([
    StructField("cveMetadata", StructType([
        StructField("datePublished", StringType(), True),
        StructField("dateUpdated", StringType(), True)
    ]), True),
    StructField("containers", StructType([
        StructField("cna", StructType([
            StructField("metrics", StructType([
                StructField("cvssV3_1", StructType([
                    StructField("baseScore", DoubleType(), True),
                    StructField("baseSeverity", StringType(), True)
                ]), True),
                StructField("cvssV3", StructType([
                    StructField("baseScore", DoubleType(), True),
                    StructField("baseSeverity", StringType(), True)
                ]), True),
                StructField("cvssV2", StructType([
                    StructField("baseScore", DoubleType(), True),
                    StructField("baseSeverity", StringType(), True)
                ]), True)
            ]), True)
        ]), True)
    ]), True)
])

df_exploded = df_exploded.withColumn("details", from_json("details", details_schema))

# -------------------------------
# Step 6. Extract Nested Fields and Add Ingestion Timestamp
# -------------------------------
df_exploded = df_exploded.withColumn("datePublished", col("details.cveMetadata.datePublished")
    ).withColumn("dateUpdated", col("details.cveMetadata.dateUpdated")
    ).withColumn("baseScore",
        F.expr("coalesce(details.containers.cna.metrics.cvssV3_1.baseScore, details.containers.cna.metrics.cvssV3.baseScore, details.containers.cna.metrics.cvssV2.baseScore)")
    ).withColumn("baseSeverity",
        F.expr("coalesce(details.containers.cna.metrics.cvssV3_1.baseSeverity, details.containers.cna.metrics.cvssV3.baseSeverity, details.containers.cna.metrics.cvssV2.baseSeverity)")
    ).withColumn("ingestion_ts", current_timestamp())

# -------------------------------
# Step 7. Select Final Fields in the Desired Order
# -------------------------------
final_df = df_exploded.select("ingestion_ts", "vendor", "product", "cveId", "datePublished", "dateUpdated", "baseScore", "baseSeverity")

# -------------------------------
# Step 8. Create Iceberg Table if It Does Not Exist
# -------------------------------
spark.sql("""
    CREATE TABLE IF NOT EXISTS glue_catalog.cve_db.iceberg_staging (
        ingestion_ts timestamp,
        vendor string,
        product string,
        cveId string,
        datePublished string,
        dateUpdated string,
        baseScore double,
        baseSeverity string
    ) USING ICEBERG
    LOCATION '{}'
    PARTITIONED BY (datePublished)
""".format(STAGING_S3_BUCKET + "cve_iceberg_table/"))

# -------------------------------
# Step 9. Append New Data into the Iceberg Table
# -------------------------------
df_append = final_df.dropDuplicates(["cveId", "datePublished"])
df_append.write \
    .format("iceberg") \
    .mode("append") \
    .save("glue_catalog.cve_db.iceberg_staging")

print("Data successfully extracted, deduplicated, and appended to Iceberg!")
job.commit()
