#!/usr/bin/env python3
import sys
import logging
from time import perf_counter
from pyspark.sql.types import (
    StructType, StructField,
    StringType, BooleanType,
    ArrayType
)
from pyspark.sql.functions import to_json, struct

from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
import boto3

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("BatchNDJSON")

# Glue Job Params
args = getResolvedOptions(
    sys.argv,
    ["JOB_NAME"]
)
JOB_NAME = args["JOB_NAME"]

DO_COMPRESS = True
BUCKET = "cve-ingestion"

# Determine latest DATE_STR from S3 prefixes under cve_json/
s3 = boto3.client("s3")
resp = s3.list_objects_v2(
    Bucket=BUCKET,
    Prefix="cve_json/",
    Delimiter='/'
)
common = resp.get("CommonPrefixes", [])
if not common:
    raise RuntimeError(f"No date folders found under s3://{BUCKET}/cve_json/")
dates = [cp['Prefix'].rstrip('/').split('/')[-1] for cp in common]
DATE_STR = sorted(dates)[-1]
logger.info(f"Discovered latest folder DATE_STR={DATE_STR}")

# Paths & Prefixes
INPUT_PATH    = f"s3://{BUCKET}/cve_json/{DATE_STR}/*/*.json"
UNCOMP_PREFIX = f"cve_batch/{DATE_STR}/"
COMP_PREFIX   = f"cve_batch_gzip/{DATE_STR}/"
UNCOMP_PATH   = f"s3://{BUCKET}/{UNCOMP_PREFIX}"
COMP_PATH     = f"s3://{BUCKET}/{COMP_PREFIX}"

def main():
    start_total = perf_counter()
    logger.info(f"Starting BatchNDJSON for {DATE_STR}")

    # 1) Initialize GlueContext & SparkSession
    sc = SparkContext.getOrCreate()
    glueContext = GlueContext(sc)
    spark = glueContext.spark_session

    # 1a) Glue Job init
    job = Job(glueContext)
    job.init(JOB_NAME, args)

    # 1b) Set shuffle partitions only (other cluster configs done in Glue console)
    spark.conf.set("spark.sql.shuffle.partitions", "4")
    logger.info("SparkSession initialized with shuffle.partitions=4")

    # 2) Schema definition
    schema = StructType([
        StructField("ingestionDate",      StringType(),                       True),
        StructField("ingestionTimestamp", StringType(),                       True),
        StructField("vendor",             StringType(),                       True),
        StructField("product",            StringType(),                       True),
        StructField("cveDataAvailable",   BooleanType(),                      True),
        StructField("cvelistv5",          ArrayType(ArrayType(StringType())), True),
        StructField("fkie_nvd",           ArrayType(ArrayType(StringType())), True),
    ])

    # 3) Read JSON
    t1 = perf_counter()
    df = (
        spark.read
             .schema(schema)
             .option("mode",      "PERMISSIVE")
             .option("multiline","false")
             .option("wholeFile","true")
             .option("compression","none")
             .json(INPUT_PATH)
    )
    count = df.count()
    logger.info(f"Read {count:,} records in {perf_counter()-t1:.1f}s from {INPUT_PATH}")

    # 4) Serialize to NDJSON strings & repartition
    t2 = perf_counter()
    df = df.select([f.name for f in schema.fields])
    json_ds = (
        df.select(to_json(struct(*df.columns)).alias("value"))
          .repartition(4)
    )
    logger.info(f"Prepared 4 partitions of NDJSON in {perf_counter()-t2:.1f}s")

    # 5) Write uncompressed
    t3 = perf_counter()
    json_ds.write.mode("overwrite").text(UNCOMP_PATH)
    logger.info(f"Wrote 4 uncompressed shards to {UNCOMP_PATH} in {perf_counter()-t3:.1f}s")

    # 6) Optionally write compressed
    if DO_COMPRESS:
        t4 = perf_counter()
        json_ds.write \
               .mode("overwrite") \
               .option("compression","gzip") \
               .text(COMP_PATH)
        logger.info(f"Wrote 4 compressed shards to {COMP_PATH} in {perf_counter()-t4:.1f}s")

    # 7) Rename with Hadoop FS
    t5 = perf_counter()
    hadoop_conf = sc._jsc.hadoopConfiguration()

    def spark_rename(prefix_uri: str, from_ext: str, to_ext: str):
        dir_path    = sc._jvm.org.apache.hadoop.fs.Path(prefix_uri)
        fs_for_path = dir_path.getFileSystem(hadoop_conf)
        for status in fs_for_path.listStatus(dir_path):
            path = status.getPath()
            name = path.getName()
            if not (name.startswith("part-") and name.endswith(from_ext)):
                continue
            new_name = name[:-len(from_ext)] + to_ext
            new_path = sc._jvm.org.apache.hadoop.fs.Path(dir_path, new_name)
            if fs_for_path.rename(path, new_path):
                logger.info(f"Renamed {name} → {new_name}")
            else:
                logger.error(f"Failed to rename {name} → {new_name}")

    spark_rename(UNCOMP_PATH, ".txt",     ".ndjson")
    logger.info(f"Renamed uncompressed shards in {perf_counter()-t5:.1f}s")

    if DO_COMPRESS:
        t6 = perf_counter()
        spark_rename(COMP_PATH, ".txt.gz", ".ndjson.gz")
        logger.info(f"Renamed compressed shards in {perf_counter()-t6:.1f}s")

    # 8) Finish up
    spark.stop()
    logger.info(f"All done in {perf_counter()-start_total:.1f}s")

    job.commit()

if __name__ == "__main__":
    main()
