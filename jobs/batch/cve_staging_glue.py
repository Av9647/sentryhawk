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
import pyspark.sql.functions as F
from pyspark.sql.functions import (
    explode, explode_outer, col, upper, from_json, lit, expr, struct, 
    collect_list, array_distinct, map_keys, trim, regexp_replace, input_file_name, concat, when, flatten, size
)
from pyspark.sql.types import (
    StructType, StructField, StringType, ArrayType, 
    DoubleType, TimestampType, DateType, MapType
)

# S3 bucket definitions
SOURCE_BUCKET = "s3://cve-ingestion/cve_json/"
STAGING_BUCKET = "s3://cve-staging/cve_staging_tables/"
STAGING_LOG_PREFIX = "cve_staging_logs/"

args = getResolvedOptions(sys.argv, ["JOB_NAME"])
sc = SparkContext()
glueContext = GlueContext(sc)

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

# Initialize log messages list
log_messages = []
def add_log(msg):
    log_messages.append(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

add_log("Starting main processing script.")

current_date = datetime.now(timezone.utc).strftime("%Y_%m_%d")
staging_table_name = f"cve_staging_{current_date}"
staging_table_location = f"{STAGING_BUCKET}{staging_table_name}"

#------------------------------------------------------------------------------
# Create staging table (if not exists)
#------------------------------------------------------------------------------
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
        LOCATION '{staging_table_location}'
        PARTITIONED BY (ingestionDate)
    """)
    add_log(f"Staging table glue_catalog.cve_db.{staging_table_name} created or already exists.")
except Exception as e:
    add_log(f"Error creating staging table: {str(e)}")
    raise

#------------------------------------------------------------------------------
# STEP 1: Determine latest ingestion folder in S3 and read files
#------------------------------------------------------------------------------
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
        m = re.search(r"cve_json/(\d{4}-\d{2}-\d{2})/?", folder)
        if m:
            ingestion_days.append(m.group(1))
    if not ingestion_days:
        raise Exception("No ingestion day folders found in S3.")
    latest_day = max(ingestion_days)
    add_log(f"Latest ingestion day determined: {latest_day}")
    
    latest_directory = f"s3a://{bucket_name}/cve_json/{latest_day}/*.gz"
    add_log(f"Reading all NDJSON files from directory (wildcard): {latest_directory}")
except Exception as e:
    add_log(f"Error determining ingestion day: {str(e)}")
    raise

#------------------------------------------------------------------------------
# STEP 2: Define explicit schema for NDJSON files
#------------------------------------------------------------------------------
# NOTE: 'metrics' is an array of objects, each may have 'cvssV3_1' as a single struct
cvelist_schema = StructType([
    StructField("cveMetadata", StructType([
        StructField("datePublished", StringType(), True),
        StructField("dateReserved", StringType(), True),
        StructField("dateUpdated", StringType(), True)
    ]), True),
    StructField("containers", StructType([
        StructField("cna", StructType([
            StructField("datePublic", StringType(), True),
            StructField("descriptions", ArrayType(StructType([
                StructField("lang", StringType(), True),
                StructField("value", StringType(), True)
            ])), True),
            StructField("metrics", ArrayType(StructType([
                StructField("format", StringType(), True),
                StructField("scenarios", ArrayType(StructType([
                    StructField("lang", StringType(), True),
                    StructField("value", StringType(), True)
                ])), True),
                StructField("cvssV3_1", StructType([
                    StructField("version", StringType(), True),
                    StructField("vectorString", StringType(), True),
                    StructField("baseScore", DoubleType(), True),
                    StructField("impactScore", DoubleType(), True),
                    StructField("exploitabilityScore", DoubleType(), True)
                ]), True)
            ])), True)
        ]), True)
    ]), True)
])

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

ndjson_schema = StructType([
    StructField("vendor", StringType(), True),
    StructField("product", StringType(), True),
    StructField("ingestionTimestamp", StringType(), True),
    StructField("ingestionDate", StringType(), True),
    StructField("cvelistv5", ArrayType(ArrayType(StringType())), True),
    StructField("fkie_nvd", ArrayType(ArrayType(StringType())), True)
])

#------------------------------------------------------------------------------
# STEP 3: Read NDJSON files (each line is a JSON object)
#------------------------------------------------------------------------------
df_raw = spark.read.option("multiline", "false").schema(ndjson_schema).json(latest_directory)
df_raw = df_raw.withColumn("source_file", input_file_name())

df_raw = df_raw.withColumn(
    "ingestionTimestamp", 
    F.to_timestamp("ingestionTimestamp", "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX")
).withColumn(
    "ingestionDate", 
    F.to_date("ingestionDate", "yyyy-MM-dd")
)
raw_count = df_raw.count()
add_log(f"JSON chunk count: {raw_count}")

#------------------------------------------------------------------------------
# STEP 4a: Process cvelistv5 (pull cvssV3_1 as fallback)
#------------------------------------------------------------------------------
cvelistv5_df = df_raw.select(
    "vendor", "product", "ingestionTimestamp", "ingestionDate",
    explode("cvelistv5").alias("item")
)

# Parse JSON details
cvelistv5_df = cvelistv5_df.withColumn(
    "cveId",
    regexp_replace(upper(trim(col("item")[0])), "[^\\x00-\\x7F]", "")
).withColumn(
    "details",
    from_json(col("item")[1], cvelist_schema)
)

cvelistv5_df = cvelistv5_df.select(
    "vendor", "product", "ingestionTimestamp", "ingestionDate", "cveId",
    col("details.cveMetadata.datePublished").alias("datePublished"),
    col("details.cveMetadata.dateReserved").alias("dateReserved"),
    col("details.cveMetadata.dateUpdated").alias("dateUpdated"),
    col("details.containers.cna.datePublic").alias("datePublic"),
    col("details.containers.cna.descriptions").alias("raw_alt_descriptions"),
    # Rename metrics to raw_metrics
    col("details.containers.cna.metrics").alias("raw_metrics")
)

# Explode metrics array (outer to keep rows even if empty)
cvelistv5_df = cvelistv5_df.withColumn("metric_item", explode_outer("raw_metrics"))

# Extract cvssV3_1 from each metric_item
cvelistv5_df = cvelistv5_df.withColumn("raw_alt_cvss", col("metric_item.cvssV3_1"))

# Convert date fields to timestamp
cvelistv5_df = cvelistv5_df.withColumn("datePublished", F.to_timestamp("datePublished")) \
                           .withColumn("dateReserved", F.to_timestamp("dateReserved")) \
                           .withColumn("dateUpdated", F.to_timestamp("dateUpdated")) \
                           .withColumn("datePublic", F.to_timestamp("datePublic"))

# Filter descriptions for 'en%'
cvelistv5_df = cvelistv5_df.withColumn(
    "alt_descriptions",
    expr("filter(raw_alt_descriptions, x -> x.lang like 'en%')")
)

# Transform cvssV3_1 struct into a single-element array alt_cvssData
cvelistv5_df = cvelistv5_df.withColumn(
    "alt_cvssData",
    when(
        col("raw_alt_cvss").isNotNull(),
        F.array(
            expr("""
              named_struct(
                'source', cast(null as string),
                'type', cast(null as string),
                'version', raw_alt_cvss.version,
                'vectorString', raw_alt_cvss.vectorString,
                'baseScore', raw_alt_cvss.baseScore,
                'exploitabilityScore', raw_alt_cvss.exploitabilityScore,
                'impactScore', raw_alt_cvss.impactScore
              )
            """)
        )
    ).otherwise(F.array())
)

# Group by (vendor, product, cveId, etc.) so multiple metrics become a single array
cvelistv5_grouped = cvelistv5_df.groupBy(
    "vendor", "product", "cveId",
    "ingestionTimestamp", "ingestionDate",
    "datePublished", "dateReserved", "dateUpdated", "datePublic",
    "alt_descriptions"
).agg(
    array_distinct(flatten(collect_list("alt_cvssData"))).alias("alt_cvssData")
)

cvelist_count = cvelistv5_grouped.count()
add_log(f"cvelistv5_df record count after grouping: {cvelist_count}")

#------------------------------------------------------------------------------
# STEP 4b: Process fkie_nvd
#------------------------------------------------------------------------------
fkie_df = df_raw.select(
    "vendor", "product", "ingestionTimestamp", "ingestionDate",
    explode("fkie_nvd").alias("item")
)

fkie_df = fkie_df.withColumn("raw_details", col("item")[1]) \
                 .withColumn("details", from_json(col("raw_details"), fkie_schema))

fkie_df = fkie_df.withColumn(
    "englishDescription",
    explode(expr("filter(details.descriptions, x -> x.lang like 'en%')"))
).select(
    "vendor", "product", "ingestionTimestamp", "ingestionDate",
    col("details.id").alias("cveId"),
    col("details.lastModified").alias("lastModified"),
    col("details.vulnStatus").alias("vulnStatus"),
    col("englishDescription.value").alias("Descriptions"),
    col("details.metrics").alias("cvssMetrics")
)

fkie_df = fkie_df.withColumn("lastModified", F.to_timestamp("lastModified"))
fkie_count = fkie_df.count()
add_log(f"fkie_df record count: {fkie_count}")

# Flatten CVSS data from fkie_nvd
cvss_versions = [
    row["cvssVersion"]
    for row in fkie_df.select(explode(map_keys(col("cvssMetrics"))).alias("cvssVersion")).distinct().collect()
]

cvss_dfs = []
for version in cvss_versions:
    tmp_df = fkie_df.select(
        "vendor", "product", "ingestionTimestamp", "ingestionDate", "cveId",
        "lastModified", "vulnStatus", "Descriptions",
        explode(col(f"cvssMetrics.{version}")).alias("cvssEntry")
    ).select(
        "vendor", "product", "ingestionTimestamp", "ingestionDate", "cveId",
        "lastModified", "vulnStatus", "Descriptions",
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
    cvss_dfs.append(tmp_df)

if cvss_dfs:
    df_cvss_flattened = cvss_dfs[0]
    for tmp_df in cvss_dfs[1:]:
        df_cvss_flattened = df_cvss_flattened.unionByName(tmp_df)
    df_cvss_combined = df_cvss_flattened.groupBy(
        "vendor", "product", "ingestionTimestamp", "ingestionDate",
        "cveId", "lastModified", "vulnStatus", "Descriptions"
    ).agg(
        array_distinct(collect_list("cvssData")).alias("cvssData")
    )
else:
    df_cvss_combined = fkie_df.withColumn("cvssData", F.array()).distinct()

cvss_count = df_cvss_combined.count()
add_log(f"CVSS combined record count: {cvss_count}")

#------------------------------------------------------------------------------
# STEP 5: Merge cvelistv5 (cv_df) and fkie_nvd (nvd_df)
#------------------------------------------------------------------------------
cv_df = cvelistv5_grouped.select(
    "vendor", "product", "cveId",
    F.col("ingestionTimestamp").alias("cv_ingestionTimestamp"),
    F.col("ingestionDate").alias("cv_ingestionDate"),
    "datePublished", "dateReserved", "dateUpdated", "datePublic",
    "alt_descriptions", "alt_cvssData"
).alias("cv")

nvd_df = df_cvss_combined.select(
    "vendor", "product", "cveId",
    F.col("ingestionTimestamp").alias("nvd_ingestionTimestamp"),
    F.col("ingestionDate").alias("nvd_ingestionDate"),
    "lastModified", "vulnStatus", "Descriptions", "cvssData"
).alias("nvd")

combined_df = cv_df.join(nvd_df, on=["vendor", "product", "cveId"], how="outer") \
    .withColumn(
        "ingestionTimestamp", 
        F.coalesce(F.col("cv.cv_ingestionTimestamp"), F.col("nvd.nvd_ingestionTimestamp"))
    ).withColumn(
        "ingestionDate", 
        F.coalesce(F.col("cv.cv_ingestionDate"), F.col("nvd.nvd_ingestionDate"))
    ).withColumn(
        "datePublished", F.col("cv.datePublished")
    ).withColumn(
        "dateReserved", F.col("cv.dateReserved")
    ).withColumn(
        "dateUpdated", F.col("cv.dateUpdated")
    ).withColumn(
        "datePublic", F.col("cv.datePublic")
    ).withColumn(
        "vulnStatus", F.col("nvd.vulnStatus")
    ).withColumn(
        "lastModified", F.col("nvd.lastModified")
    ).withColumn(
        "Descriptions",
        F.coalesce(
            F.col("nvd.Descriptions"),
            expr("element_at(filter(cv.alt_descriptions, x -> x.lang like 'en%'), 1).value")
        )
    ).withColumn(
        "cvssData",
        when(
            (F.col("nvd.cvssData").isNotNull()) & (F.size(F.col("nvd.cvssData")) > 0),
            F.col("nvd.cvssData")
        ).otherwise(
            F.col("cv.alt_cvssData")
        )
    )

combined_count = combined_df.count()
add_log(f"Combined DataFrame record count: {combined_count}")

#------------------------------------------------------------------------------
# STEP 6: Combine rows if same vendor-product-cveId appears in multiple chunks
#------------------------------------------------------------------------------
final_df = combined_df.groupBy(
    "vendor", "product", "cveId", "ingestionTimestamp", "ingestionDate"
).agg(
    F.first("vulnStatus").alias("vulnStatus"),
    F.first("datePublished").alias("datePublished"),
    F.first("dateReserved").alias("dateReserved"),
    F.first("dateUpdated").alias("dateUpdated"),
    F.first("datePublic").alias("datePublic"),
    F.first("lastModified").alias("lastModified"),
    F.first("Descriptions").alias("Descriptions"),
    array_distinct(flatten(collect_list("cvssData"))).alias("cvssData")
)

final_count = final_df.count()
add_log(f"Final grouped record count: {final_count}")

final_columns = [
    "ingestionDate", "vendor", "product",
    "cveId", "vulnStatus", "cvssData", "datePublished", "dateReserved", "dateUpdated", "datePublic",
    "lastModified", "Descriptions", "ingestionTimestamp"
]
final_df = final_df.select(*final_columns)

# Remove html elements from Descriptions
final_df = final_df.withColumn("Descriptions", regexp_replace(col("Descriptions"), "<[^>]*>", ""))

#------------------------------------------------------------------------------
# STEP 7: Write final data to the Iceberg table
#------------------------------------------------------------------------------
final_df.write.format("iceberg")\
    .mode("append")\
    .saveAsTable(f"glue_catalog.cve_db.{staging_table_name}")
add_log("Insert executed for all records.")

#------------------------------------------------------------------------------
# STEP 8: Write log messages to a text file in the staging logs folder
#------------------------------------------------------------------------------
try:
    log_content = "\n".join(log_messages)
    log_file_key = f"cve_staging_logs/staging_log_{current_date}.txt"
    s3_client.put_object(Bucket="cve-staging",
                         Key=log_file_key, Body=log_content)
    add_log("Log file written successfully to staging bucket under cve_staging_logs.")
except Exception as log_ex:
    add_log("Failed writing log file: " + str(log_ex))

print("Processing completed. Check the 'cve_staging_logs' folder in the staging bucket for log details.")
job.commit()
