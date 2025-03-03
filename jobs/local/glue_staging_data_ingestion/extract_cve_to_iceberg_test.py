import sys
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
    .config("spark.sql.catalog.glue_catalog.type", "glue") \
    .config("spark.sql.catalog.glue_catalog.warehouse", STAGING_S3_BUCKET) \
    .config("spark.sql.iceberg.handle-timestamp-without-timezone", "true") \
    .config("hive.metastore.client.factory.class", "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory") \
    .enableHiveSupport() \
    .getOrCreate()

# Extract Latest File per Product (Avoid Duplicates)
all_files = spark.read.format("json").load(RAW_S3_BUCKET)
file_names_df = all_files.select(F.input_file_name().alias("file_path"))

# Extract timestamp and product from filename pattern
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

# Print schema for debugging
print("Raw Data Schema:")
df_raw.printSchema()

# Fix: Double explode to handle nested array structure
df = df_raw.withColumn("cve_pair", F.explode("cvelistv5"))  # First explode
df = df.withColumn("cve_pair", F.explode("cve_pair"))  # Second explode

df.printSchema()  # Debugging: Print schema after transformation

df_cleaned = df.select(
    F.col("cve_pair").alias("cve_id")  # Extract CVE ID
)

df_cleaned.show(truncate=False)  # Debugging: Print sample data

# Handle Missing Values
df_cleaned = df_cleaned.fillna({"cve_id": "UNKNOWN"})

spark.sql("CREATE DATABASE IF NOT EXISTS glue_catalog.cve_db")

# Create Iceberg Table (If Not Exists)
spark.sql(f"""
    CREATE TABLE IF NOT EXISTS glue_catalog.cve_db.iceberg_staging (
        cve_id STRING
    ) USING ICEBERG
    LOCATION '{STAGING_S3_BUCKET}'
""")

# Merge into Iceberg to Prevent Duplicate Inserts
df_cleaned.createOrReplaceTempView("staging_data")

spark.sql("""
    MERGE INTO glue_catalog.cve_db.iceberg_staging AS target
    USING staging_data AS source
    ON target.cve_id = source.cve_id
    WHEN NOT MATCHED THEN 
        INSERT (cve_id) 
        VALUES (source.cve_id)
""")

print("Data successfully extracted, deduplicated, and stored in Iceberg!")

job.commit()
