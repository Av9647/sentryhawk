import sys
import math
import uuid
import boto3
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext

# 1) Fetch job args
args = getResolvedOptions(sys.argv, ["JOB_NAME", "INGESTION_DATE"])
ingestion_date = args["INGESTION_DATE"]  # e.g. "2025-05-02"

# 2) Initialize Glue/Spark
sc = SparkContext.getOrCreate()
glueContext = GlueContext(sc)
spark = glueContext.spark_session

# 3) S3 locations
bucket             = "cve-ingestion"
input_prefix       = f"cve_json/{ingestion_date}/"
temp_output_prefix = f"cve_batch/{ingestion_date}/_temp/"
final_prefix       = f"cve_batch/{ingestion_date}/"

s3 = boto3.client("s3")

# 4) Sum total bytes under the input prefix (includes all vendor sub‑folders)
paginator = s3.get_paginator("list_objects_v2")
total_bytes = 0
for page in paginator.paginate(Bucket=bucket, Prefix=input_prefix):
    for obj in page.get("Contents", []):
        total_bytes += obj["Size"]

# 5) Determine number of 1 GiB partitions
ONE_GIB = 1024**3
num_partitions = max(1, math.ceil(total_bytes / ONE_GIB))
print(f"Total bytes = {total_bytes:,}, using {num_partitions} partition(s).")

# 6) Read *all* gzipped JSON lines under every vendor folder
#    Use recursiveFileLookup so we pick up deeper sub‑paths
input_path = f"s3://{bucket}/{input_prefix}"
df = (spark.read
       .option("recursiveFileLookup", "true")
       .text(input_path)
    )

# 7) Repartition to approximately 1 GiB chunks and write to temp
df_repart = df.repartition(num_partitions)
temp_path  = f"s3://{bucket}/{temp_output_prefix}"
(df_repart.write
    .mode("overwrite")
    .option("compression", "gzip")
    .text(temp_path)
)

# 8) Rename part‑files to {date}_{UUID}.json.gz under final_prefix
paginator = s3.get_paginator("list_objects_v2")
for page in paginator.paginate(Bucket=bucket, Prefix=temp_output_prefix):
    for obj in page.get("Contents", []):
        key = obj["Key"]
        if not key.lower().endswith(".gz"):
            continue
        new_key = f"{final_prefix}{ingestion_date}_{uuid.uuid4()}.json.gz"
        s3.copy_object(
            Bucket=bucket,
            CopySource={"Bucket": bucket, "Key": key},
            Key=new_key
        )
        s3.delete_object(Bucket=bucket, Key=key)

# 9) Clean up any leftovers in the temp folder
for page in paginator.paginate(Bucket=bucket, Prefix=temp_output_prefix):
    for obj in page.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])

print("Batch compaction complete.")
