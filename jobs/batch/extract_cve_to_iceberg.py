import sys
import re
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StructType, StructField, StringType, ArrayType, MapType

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

# Enable Iceberg Support in Spark
spark = SparkSession.builder \
    .config("spark.sql.catalog.glue_catalog", "org.apache.iceberg.spark.SparkCatalog") \
    .config("spark.sql.catalog.glue_catalog.type", "hive") \
    .config("spark.sql.catalog.glue_catalog.warehouse", STAGING_S3_BUCKET) \
    .getOrCreate()

# Extract Latest File per Product (Avoid Duplicates)
all_files = spark.read.format("json").load(RAW_S3_BUCKET)
file_names_df = all_files.select(F.input_file_name().alias("file_path"))

# Extract timestamp and product from filename pattern `{VENDOR}_{PRODUCT}_{YYYY-MM-DD}_{HH-MM-SS}.json`
file_names_df = file_names_df.withColumn(
    "timestamp", F.regexp_extract("file_path", r"(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})", 1)
).withColumn(
    "vendor_product", F.regexp_extract("file_path", r"([^/]+)_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.json", 1)
)

# Keep only the latest file per vendor-product
latest_files = file_names_df.groupBy("vendor_product").agg(F.max("timestamp").alias("latest_timestamp"))
latest_files = latest_files.withColumn("latest_file_path", F.concat(F.lit(RAW_S3_BUCKET), F.col("vendor_product"), F.lit("_"), F.col("latest_timestamp"), F.lit(".json")))

# Load only the latest files into DataFrame
latest_files_paths = [row.latest_file_path for row in latest_files.collect()]
df_raw = spark.read.option("multiline", "true").json(latest_files_paths)

# Explode Nested JSON Properly
df = df_raw.select(F.explode("cvelistv5").alias("cve_pair"))

# Fix: Ensure `cve_pair[1]` is read as a STRUCT instead of STRING
df = df.withColumn("cve_details", F.col("cve_pair")[1].cast(
    "STRUCT<"
    "containers: MAP<STRING, STRUCT<"
    "   cna: STRUCT<"
    "       metrics: ARRAY<STRUCT<"
    "           cvssV3_1: STRUCT<baseScore: DOUBLE, baseSeverity: STRING>, "
    "           cvssV3: STRUCT<baseScore: DOUBLE, baseSeverity: STRING>, "
    "           cvssV2: STRUCT<baseScore: DOUBLE, baseSeverity: STRING>"
    "       >>"
    "   >>"
    ">>, "
    "cveMetadata: STRUCT<datePublished: STRING, dateUpdated: STRING>, "
    "affected: ARRAY<STRUCT<product: STRING, vendor: STRING>>, "
    "descriptions: ARRAY<STRUCT<value: STRING>>"
    ">"
))

# Extract Key Fields Correctly
df_cleaned = df.select(
    F.col("cve_pair[0]").alias("cve_id"),  # Extract first element (CVE ID)
    
    # Extract Nested Fields
    F.col("cve_details.cveMetadata.datePublished").alias("published_date"),
    F.col("cve_details.cveMetadata.dateUpdated").alias("date_updated"),
    
    # Extract Base Score (Handling Multiple CVSS Variations)
    F.when(F.col("cve_details.containers.cna.metrics.cvssV3_1.baseScore").isNotNull(),
           F.col("cve_details.containers.cna.metrics.cvssV3_1.baseScore"))
     .when(F.col("cve_details.containers.cna.metrics.cvssV3.baseScore").isNotNull(),
           F.col("cve_details.containers.cna.metrics.cvssV3.baseScore"))
     .when(F.col("cve_details.containers.cna.metrics.cvssV2.baseScore").isNotNull(),
           F.col("cve_details.containers.cna.metrics.cvssV2.baseScore"))
     .otherwise(0.0).alias("base_score"),

    # Extract Base Severity (Handling Multiple CVSS Variations)
    F.when(F.col("cve_details.containers.cna.metrics.cvssV3_1.baseSeverity").isNotNull(),
           F.col("cve_details.containers.cna.metrics.cvssV3_1.baseSeverity"))
     .when(F.col("cve_details.containers.cna.metrics.cvssV3.baseSeverity").isNotNull(),
           F.col("cve_details.containers.cna.metrics.cvssV3.baseSeverity"))
     .when(F.col("cve_details.containers.cna.metrics.cvssV2.baseSeverity").isNotNull(),
           F.col("cve_details.containers.cna.metrics.cvssV2.baseSeverity"))
     .otherwise("UNKNOWN").alias("base_severity"),

    # Extract Vendor and Product (If Available)
    F.expr("cve_details.containers.cna.affected[0].vendor").alias("vendor"),
    F.expr("cve_details.containers.cna.affected[0].product").alias("product"),

    # Extract Description
    F.expr("cve_details.containers.cna.descriptions[0].value").alias("description")
)

# Handle Missing Values
df_cleaned = df_cleaned.fillna({"base_score": 0.0, "base_severity": "UNKNOWN"})

# Create Iceberg Table (If Not Exists)
spark.sql("""
    CREATE TABLE IF NOT EXISTS glue_catalog.cve_db.iceberg_staging (
        cve_id STRING,
        published_date STRING,
        date_updated STRING,
        base_score DOUBLE,
        base_severity STRING,
        vendor STRING,
        product STRING,
        description STRING
    ) USING ICEBERG
    LOCATION '{}'
    PARTITIONED BY (published_date)
""".format(STAGING_S3_BUCKET))

# Merge into Iceberg to Prevent Duplicate Inserts
df_cleaned.createOrReplaceTempView("staging_data")

spark.sql("""
    MERGE INTO glue_catalog.cve_db.iceberg_staging AS target
    USING staging_data AS source
    ON target.cve_id = source.cve_id AND target.published_date = source.published_date
    WHEN MATCHED THEN 
        UPDATE SET 
            target.date_updated = source.date_updated,
            target.base_score = source.base_score,
            target.base_severity = source.base_severity,
            target.vendor = source.vendor,
            target.product = source.product,
            target.description = source.description
    WHEN NOT MATCHED THEN 
        INSERT (cve_id, published_date, date_updated, base_score, base_severity, vendor, product, description) 
        VALUES (source.cve_id, source.published_date, source.date_updated, source.base_score, source.base_severity, source.vendor, source.product, source.description)
""")

print("Data successfully extracted, deduplicated, and stored in Iceberg!")

job.commit()
