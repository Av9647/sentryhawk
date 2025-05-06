#!/usr/bin/env python3
import glob, os
from pyspark.sql.functions import to_json, struct
from pyspark.sql import SparkSession
from pyspark.sql.types import (
    StructType, StructField,
    StringType, BooleanType,
    ArrayType
)

# Environment Configuration
os.environ["JAVA_HOME"]             = "C:\\Program Files\\Java\\jdk-11"
os.environ["HADOOP_HOME"]           = "C:\\hadoop"
os.environ["PYSPARK_PYTHON"]        = "C:\\Users\\athul\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
os.environ["PYSPARK_DRIVER_PYTHON"] = os.environ["PYSPARK_PYTHON"]

# Parameters
DATE_STR    = "2025-05-03"
INPUT_ROOT  = r"D:\cve_json"
OUTPUT_ROOT = r"D:\cve_json"
NUM_SHARDS  = 2

def main():
    input_pattern = os.path.join(INPUT_ROOT, DATE_STR, "*", "*.json.gz")
    output_path   = os.path.join(OUTPUT_ROOT, f"{DATE_STR}_sharded")

    spark = (
        SparkSession.builder
            .appName(f"CombineJSON_{DATE_STR}")
            .config("spark.master", "local[*]")
            .config("spark.driver.host", "127.0.0.1")
            .getOrCreate()
    )

    # 1) Define schema in desired order
    schema = StructType([
        StructField("ingestionDate",      StringType(),                       True),
        StructField("ingestionTimestamp", StringType(),                       True),
        StructField("vendor",             StringType(),                       True),
        StructField("product",            StringType(),                       True),
        StructField("cveDataAvailable",   BooleanType(),                      True),
        StructField("cvelistv5",          ArrayType(ArrayType(StringType())), True),
        StructField("fkie_nvd",           ArrayType(ArrayType(StringType())), True),
    ])

    # 2) Read with explicit schema
    df = (
        spark.read
             .schema(schema)
             .option("multiline", "false")
             .json(input_pattern)
    )
    print(f"Read {df.count():,} records from {input_pattern}")
    df.printSchema()  # will show your schema in the exact order above

    # 3) (Optional) re‑select to enforce order if you do other transforms
    df = df.select([f.name for f in schema.fields])

    # 4) Repartition & write uncompressed NDJSON
    json_ds = (
        df.coalesce(NUM_SHARDS)
        .select(
            to_json(
            struct(*df.columns)
            ).alias("value")
        )
    )

    # write out as plain text (one JSON string per line, no compression)
    json_ds.write \
        .mode("overwrite") \
        .text(output_path)

    # ─── 5) Rename parts to .ndjson ─────────────────────────────────────────────
    for f in glob.glob(os.path.join(output_path, "part-*")):
        os.rename(f, f + ".ndjson")

    print(f"Wrote {NUM_SHARDS} NDJSON shards to {output_path}/*.ndjson")

if __name__ == "__main__":
    main()
