#!/usr/bin/env python3
import sys
import logging
from time import perf_counter
from pyspark.sql import SparkSession
from pyspark.sql.types import (
    StructType, StructField,
    StringType, BooleanType,
    ArrayType
)
from pyspark.sql.functions import to_json, struct

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("BatchNDJSON")

# CONFIG
DATE_STR     = "2025-05-06"     # The date folder to process
DO_COMPRESS  = True             # Set False to skip writing GZIP shards

BUCKET        = "cve-ingestion"
INPUT_PATH    = f"s3a://{BUCKET}/cve_json/{DATE_STR}/*/*.json"
UNCOMP_PREFIX = f"cve_batch/{DATE_STR}/"
COMP_PREFIX   = f"cve_batch_gzip/{DATE_STR}/"
UNCOMP_PATH   = f"s3a://{BUCKET}/{UNCOMP_PREFIX}"
COMP_PATH     = f"s3a://{BUCKET}/{COMP_PREFIX}"

def main():
    start_total = perf_counter()
    logger.info(f"Starting BatchNDJSON for {DATE_STR}")

    # 1) Start Spark
    t0 = perf_counter()
    spark = (
        SparkSession.builder
            .appName(f"BatchNDJSON_{DATE_STR}")
            .config("spark.hadoop.fs.s3a.impl",        "org.apache.hadoop.fs.s3a.S3AFileSystem")
            .config("spark.hadoop.fs.s3a.fast.upload", "true")
            .config("spark.dynamicAllocation.enabled", "false")
            .config("spark.eventLog.enabled",          "false")
            .config("spark.executor.instances",        "16")
            .config("spark.sql.shuffle.partitions",    "80")
            .getOrCreate()
    )
    sc = spark.sparkContext
    logger.info(f"SparkSession initialized in {perf_counter()-t0:.1f}s")

    # 2) Define schema
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

    # 4) Serialize to NDJSON strings
    t2 = perf_counter()
    df = df.select([f.name for f in schema.fields])
    json_ds = (
        df.select(to_json(struct(*df.columns)).alias("value"))
          .repartition(80)
    )
    logger.info(f"Prepared 80 partitions of NDJSON in {perf_counter()-t2:.1f}s")

    # 5) Write uncompressed
    t3 = perf_counter()
    json_ds.write.mode("overwrite").text(UNCOMP_PATH)
    logger.info(f"Wrote 80 uncompressed shards to s3://{BUCKET}/{UNCOMP_PREFIX} in {perf_counter()-t3:.1f}s")

    # 6) Optionally write compressed
    if DO_COMPRESS:
        t4 = perf_counter()
        json_ds.write \
               .mode("overwrite") \
               .option("compression","gzip") \
               .text(COMP_PATH)
        logger.info(f"Wrote 80 compressed shards to s3://{BUCKET}/{COMP_PREFIX} in {perf_counter()-t4:.1f}s")

    # 7) Rename via Hadoop FS
    t5 = perf_counter()
    hadoop_conf = sc._jsc.hadoopConfiguration()

    def spark_rename(prefix_uri: str, from_ext: str, to_ext: str):
        dir_path = sc._jvm.org.apache.hadoop.fs.Path(prefix_uri)
        fs_for_path = dir_path.getFileSystem(hadoop_conf)
        for fileStatus in fs_for_path.listStatus(dir_path):
            path = fileStatus.getPath()
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
    uncmp_time = perf_counter() - t5
    logger.info(f"Renamed uncompressed shards in {uncmp_time:.1f}s")

    if DO_COMPRESS:
        t6 = perf_counter()
        spark_rename(COMP_PATH, ".txt.gz", ".ndjson.gz")
        cmp_time = perf_counter() - t6
        logger.info(f"Renamed compressed shards in {cmp_time:.1f}s")

    spark.stop()
    logger.info(f"All done in {perf_counter()-start_total:.1f}s")

if __name__ == "__main__":
    main()
