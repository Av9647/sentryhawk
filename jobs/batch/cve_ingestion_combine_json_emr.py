#!/usr/bin/env python3
import sys
from pyspark.sql import SparkSession
from pyspark.sql.types import (
    StructType, StructField,
    StringType, BooleanType,
    ArrayType
)
from pyspark.sql.functions import to_json, struct

# 1) Get date from argv or default
if len(sys.argv) > 1:
    date_str = sys.argv[1]
else:
    date_str = "2025-05-03_sanitized"
    print(f"No date provided; defaulting to {date_str}")

# 2) Build S3 paths
INPUT_PATH  = f"s3a://cve-ingestion/cve_json/{date_str}/*/*.json.gz"
OUTPUT_PATH = f"s3a://cve-ingestion/cve_batch/{date_str}/"

# 3) Spark session with S3 configs
spark = (
    SparkSession.builder
        .appName(f"BatchNDJSON_{date_str}")
        .config("spark.eventLog.enabled",           "true")
        .config("spark.eventLog.dir",               "s3a://cve-ingestion/emr-event-logs/")
        .config("spark.hadoop.fs.s3a.impl",         "org.apache.hadoop.fs.s3a.S3AFileSystem")
        .config("spark.hadoop.fs.s3a.fast.upload",  "true")
        .config("spark.dynamicAllocation.enabled",  "false")
        .config("spark.executor.instances",         "16")
        .config("spark.sql.shuffle.partitions",     "80")
        .config("spark.sql.files.maxPartitionBytes","134217728")
        .getOrCreate()
)

# 4) Define your schema in the exact order you want
schema = StructType([
    StructField("ingestionDate",      StringType(),                       True),
    StructField("ingestionTimestamp", StringType(),                       True),
    StructField("vendor",             StringType(),                       True),
    StructField("product",            StringType(),                       True),
    StructField("cveDataAvailable",   BooleanType(),                      True),
    StructField("cvelistv5",          ArrayType(ArrayType(StringType())), True),
    StructField("fkie_nvd",           ArrayType(ArrayType(StringType())), True),
])

# 5) Read with that schema (no inferring/reordering)
df = (
    spark.read
         .schema(schema)                    # enforce your column order
         .option("mode",        "PERMISSIVE")
         .option("multiline",   "false")    # NDJSON
         .option("compression", "gzip")
         .json(INPUT_PATH)
)

print(f"→ Read {df.count():,} records from {INPUT_PATH}")
print(f"→ Input partitions: {df.rdd.getNumPartitions()}")

# 6) Re‑select to guarantee order (if you do other transforms)
df = df.select([f.name for f in schema.fields])

# 7) Serialize each row to a JSON string in that order
json_ds = df.select(
    to_json(struct(*df.columns)).alias("value")
)

# 8) Repartition & write true NDJSON to S3
#    writing via the text sink gives you exactly one JSON object per line
json_ds.repartition(80) \
       .write \
         .mode("overwrite") \
         .text(OUTPUT_PATH)

print(f"→ Wrote 80 NDJSON shards to {OUTPUT_PATH}/part-*")

spark.stop()
