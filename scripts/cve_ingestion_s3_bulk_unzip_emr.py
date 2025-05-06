#!/usr/bin/env python3
import os
import tempfile
import boto3
import gzip
from pyspark.sql import SparkSession

# CONFIG
BUCKET      = "cve-ingestion"
SRC_PREFIX  = "cve_json/2025-05-03_sanitized/"
DEST_PREFIX = "cve_json/2025-05-03/"

def process_partition(keys_iter):
    """
    For each key:
      1) build dest_key
      2) stream-download + decompress in chunks to a local temp file
      3) upload uncompressed JSON via boto3.upload_file (multipart-safe)
    Yields tuples of (src_key, dest_key, success_bool, error_msg_or_None).
    """
    s3 = boto3.client("s3")
    for key in keys_iter:
        if not key.endswith(".json.gz"):
            continue

        rel_path = key[len(SRC_PREFIX):]           # e.g. "vendor/file.json.gz"
        dest_key = DEST_PREFIX + rel_path[:-3]     # drop ".gz"

        print(f"[DEBUG executor] Processing {key} → {dest_key}")
        tmp_path = None
        try:
            # 1) Stream-download the gzipped object
            resp = s3.get_object(Bucket=BUCKET, Key=key)
            gz = gzip.GzipFile(fileobj=resp["Body"])

            # 2) Decompress in chunks to a temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
                tmp_path = tmp.name
                for chunk in iter(lambda: gz.read(8 * 1024 * 1024), b""):
                    tmp.write(chunk)
                tmp.flush()

            # 3) Upload from disk (boto3 will multipart if large)
            s3.upload_file(
                Filename=tmp_path,
                Bucket=BUCKET,
                Key=dest_key,
                ExtraArgs={"ContentType": "application/x-ndjson"}
            )
            print(f"[DEBUG executor] Uploaded {dest_key}")
            yield (key, dest_key, True, None)

        except Exception as e:
            print(f"[ERROR executor] Failed {key} → {dest_key}: {e}")
            yield (key, dest_key, False, str(e))

        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)

def main():
    spark = (
        SparkSession.builder
            .appName("S3GzipUncompress-Debug")
            .config("spark.hadoop.fs.s3a.impl",        "org.apache.hadoop.fs.s3a.S3AFileSystem")
            .config("spark.hadoop.fs.s3a.fast.upload", "true")
            .getOrCreate()
    )
    sc = spark.sparkContext

    # 1) List keys
    print(f"[DEBUG driver] Listing s3://{BUCKET}/{SRC_PREFIX} …")
    s3 = boto3.client("s3")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix=SRC_PREFIX):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
    total = len(keys)
    print(f"[DEBUG driver] Found {total:,} objects to process.")

    # 2) Parallelize into ~4× defaultParallelism partitions
    nparts = sc.defaultParallelism * 4
    rdd = sc.parallelize(keys, numSlices=nparts)
    print(f"[DEBUG driver] Sharding into {nparts} partitions (~{total//nparts:,} keys/partition).")

    # 3) Process partitions and collect results
    results = rdd.mapPartitions(process_partition).collect()

    # 4) Summarize in driver
    successes = [dst for (_src, dst, ok, _err) in results if ok]
    failures  = [(src, err) for (src, _dst, ok, err) in results if not ok]

    print(f"[DEBUG driver] Finished. {len(successes):,} succeeded, {len(failures):,} failed.")

    if successes:
        print("[DEBUG driver] Sample uploaded keys:")
        for k in successes[:10]:
            print("  ", k)
    else:
        print("[DEBUG driver] No successful uploads—check the executor logs!")

    if failures:
        print("[DEBUG driver] Sample failures:")
        for src, err in failures[:10]:
            print("  ", src, "→", err)

    spark.stop()

if __name__ == "__main__":
    main()
