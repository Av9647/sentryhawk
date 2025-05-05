import sys
import uuid
import time
from pyspark.context import SparkContext
from awsglue.context import GlueContext
import boto3

# 1) Hard‑coded ingestion date (or fetch via getResolvedOptions if you prefer)
ingestion_date = "2025-05-03"

# 2) Spark + Glue setup
sc = SparkContext.getOrCreate()
glueContext = GlueContext(sc)
spark = glueContext.spark_session

# 3) S3 client & paths
s3 = boto3.client("s3")
bucket = "cve-ingestion"
input_prefix = f"cve_json/{ingestion_date}/"
temp_prefix  = f"cve_batch/{ingestion_date}/_temp/"
final_prefix = f"cve_batch/{ingestion_date}/"

# 4) Count files & bytes
p = s3.get_paginator("list_objects_v2")
total_bytes = 0
file_count  = 0
for pg in p.paginate(Bucket=bucket, Prefix=input_prefix):
    for o in pg.get("Contents", []):
        total_bytes += o["Size"]
        file_count  += 1

if file_count == 0:
    print("No files to process, exiting.")
    sys.exit(0)

print(f"Found {file_count} files, {total_bytes/1024**3:.1f} GiB")

# 5) Decide partitions
MAX_SHARDS = 10
num_parts = file_count if file_count < MAX_SHARDS else MAX_SHARDS
print(f"Repartitioning into {num_parts} partitions")

# 6) Read all lines (raw text) recursively
df = (spark.read
           .option("recursiveFileLookup", "true")
           .text(f"s3://{bucket}/{input_prefix}"))

# 7) Repartition & write gzipped NDJSON to temp
df2 = df.repartition(num_parts)
temp_path = f"s3://{bucket}/{temp_prefix}"
(df2.write
    .mode("overwrite")
    .option("compression", "gzip")
    .text(temp_path)
)
print(f"Wrote temp shards to {temp_path}")

# 8) Give S3 a moment
time.sleep(5)

# 9) Atomically copy & rename into final with UUIDs
for pg in p.paginate(Bucket=bucket, Prefix=temp_prefix):
    for o in pg.get("Contents", []):
        key = o["Key"]
        if not key.lower().endswith(".gz"):
            continue
        new_key = f"{final_prefix}{ingestion_date}_{uuid.uuid4()}.json.gz"
        try:
            s3.copy_object(
                Bucket=bucket,
                CopySource={"Bucket":bucket, "Key":key},
                Key=new_key
            )
            s3.delete_object(Bucket=bucket, Key=key)
            print(f"Moved {key} → {new_key}")
        except Exception as e:
            print(f"Error moving {key}: {e}")

# 10) Clean up any leftovers
for pg in p.paginate(Bucket=bucket, Prefix=temp_prefix):
    for o in pg.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=o["Key"])

print("Compaction complete.")
