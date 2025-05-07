#!/usr/bin/env python3

import logging, sys, boto3
from datetime import datetime, timezone

from pyspark.sql import SparkSession
import pyspark.sql.functions as F
from pyspark.sql.functions import (
    input_file_name, regexp_replace,
    explode, explode_outer, col, upper, from_json, expr,
    struct, collect_list, array_distinct, flatten, size,
    to_date, to_timestamp, when
)
from pyspark.sql.types import (
    StructType, StructField,
    StringType, BooleanType,
    ArrayType, DoubleType, MapType
)

# Configuration
DATE_STR           = "2025-05-03"
SOURCE_BUCKET      = "cve-ingestion"
NDJSON_PATH        = f"s3a://{SOURCE_BUCKET}/cve_batch/{DATE_STR}/*.ndjson"
STAGING_BUCKET     = "s3://cve-staging/cve_staging_tables/"
STAGING_LOG_PREFIX = "cve_staging_logs"
AWS_REGION         = "us-east-2"

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("CVE_Transform")
log_messages = []
def add_log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    log_messages.append(f"{ts} - {msg}")
    logger.info(msg)

add_log(f"Starting CVE transformation for {DATE_STR}")

# SparkSession
spark = (
    SparkSession.builder
      .appName(f"CVE_Transform_{DATE_STR}")

      # Enable Iceberg SQL extensions
      .config("spark.sql.extensions",
              "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")

      # Glue catalog via Iceberg
      .config("spark.sql.catalog.glue_catalog",           "org.apache.iceberg.spark.SparkCatalog")
      .config("spark.sql.catalog.glue_catalog.catalog-impl",
              "org.apache.iceberg.aws.glue.GlueCatalog")
      .config("spark.sql.catalog.glue_catalog.io-impl",
              "org.apache.iceberg.aws.s3.S3FileIO")
      .config("spark.sql.catalog.glue_catalog.warehouse", STAGING_BUCKET)
      .config("spark.sql.iceberg.handle-timestamp-without-timezone", "true")

      # Point Spark’s Hive metastore client at AWS Glue
      .config("hive.metastore.client.factory.class",
              "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory")

      # S3A tuning
      .config("spark.hadoop.fs.s3a.impl",        "org.apache.hadoop.fs.s3a.S3AFileSystem")
      .config("spark.hadoop.fs.s3a.fast.upload", "true")

      # Fixed executors to match 6 × r5.xlarge workers
      .config("spark.dynamicAllocation.enabled", "false")
      .config("spark.eventLog.enabled",          "false")
      .config("spark.executor.instances",        "6")
      .config("spark.executor.cores",            "4")
      .config("spark.executor.memory",           "20g")
      .config("spark.executor.memoryOverhead",   "4096")
      .config("spark.speculation",               "true")
      .config("spark.sql.shuffle.partitions",    "80")

      .enableHiveSupport()
      .getOrCreate()
)
spark.sparkContext.setLogLevel("WARN")
add_log("SparkSession initialized")

# Step 1: Read & filter NDJSON
ndjson_schema = StructType([
    StructField("ingestionDate",      StringType(),                       True),
    StructField("ingestionTimestamp", StringType(),                       True),
    StructField("vendor",             StringType(),                       True),
    StructField("product",            StringType(),                       True),
    StructField("cveDataAvailable",   BooleanType(),                      True),
    StructField("cvelistv5",          ArrayType(ArrayType(StringType())), True),
    StructField("fkie_nvd",           ArrayType(ArrayType(StringType())), True),
])

add_log(f"Reading NDJSON from {NDJSON_PATH}")
df_raw = (
    spark.read
         .schema(ndjson_schema)
         .option("multiline","false")
         .json(NDJSON_PATH)
         .filter(col("cveDataAvailable") == True)
         .withColumn("source_file", input_file_name())
         .withColumn("ingestionTimestamp",
             to_timestamp("ingestionTimestamp", "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX")
         )
         .withColumn("ingestionDate",
             to_date("ingestionDate", "yyyy-MM-dd")
         )
         .drop("cveDataAvailable")
)
add_log(f"Loaded raw rows: {df_raw.count():,}")

# Step 2: Define CVE schemas
cvelist_schema = StructType([
    StructField("cveMetadata", StructType([
        StructField("datePublished", StringType(), True),
        StructField("dateReserved",  StringType(), True),
        StructField("dateUpdated",   StringType(), True)
    ]), True),
    StructField("containers", StructType([
        StructField("cna", StructType([
            StructField("datePublic",   StringType(), True),
            StructField("descriptions", ArrayType(StructType([
                StructField("lang",  StringType(), True),
                StructField("value", StringType(), True)
            ])), True),
            StructField("impacts", ArrayType(StructType([
                StructField("capecId",      StringType(), True),
                StructField("descriptions", ArrayType(StructType([
                    StructField("lang",  StringType(), True),
                    StructField("value", StringType(), True)
                ])), True)
            ])), True),
            StructField("metrics", ArrayType(StructType([
                StructField("cvssV3_1", StructType([
                    StructField("version",      StringType(), True),
                    StructField("vectorString", StringType(), True),
                    StructField("baseScore",     DoubleType(), True)
                ]), True)
            ])), True),
            StructField("problemTypes", ArrayType(StructType([
                StructField("descriptions", ArrayType(StructType([
                    StructField("cweId",       StringType(), True),
                    StructField("description", StringType(), True),
                    StructField("lang",        StringType(), True),
                    StructField("type",        StringType(), True)
                ])), True)
            ])), True)
        ]), True),
        StructField("adp", ArrayType(StructType([
            StructField("problemTypes", ArrayType(StructType([
                StructField("descriptions", ArrayType(StructType([
                    StructField("type",        StringType(), True),
                    StructField("cweId",       StringType(), True),
                    StructField("lang",        StringType(), True),
                    StructField("description", StringType(), True)
                ])), True)
            ])), True),
            StructField("metrics", ArrayType(StructType([
                StructField("cvssV3_1", StructType([
                    StructField("version",      StringType(), True),
                    StructField("vectorString", StringType(), True),
                    StructField("baseScore",     DoubleType(), True)
                ]), True)
            ])), True)
        ])), True)
    ]), True)
])

fkie_schema = StructType([
    StructField("id",           StringType(), True),
    StructField("published",    StringType(), True),
    StructField("lastModified", StringType(), True),
    StructField("vulnStatus",   StringType(), True),
    StructField("descriptions", ArrayType(StructType([
        StructField("lang",  StringType(), True),
        StructField("value", StringType(), True)
    ])), True),
    StructField("metrics", MapType(
        StringType(),
        ArrayType(StructType([
            StructField("source",              StringType(), True),
            StructField("type",                StringType(), True),
            StructField("cvssData", StructType([
                StructField("version",      StringType(), True),
                StructField("vectorString", StringType(), True),
                StructField("baseScore",     DoubleType(), True)
            ]), True),
            StructField("exploitabilityScore", DoubleType(), True),
            StructField("impactScore",          DoubleType(), True)
        ]))
    ), True),
    StructField("weaknesses", ArrayType(StructType([
        StructField("source",      StringType(), True),
        StructField("type",        StringType(), True),
        StructField("description", ArrayType(StructType([
            StructField("lang",  StringType(), True),
            StructField("value", StringType(), True)
        ])), True)
    ])), True)
])

# Step 3: Process cvelistv5
add_log("Processing cvelistv5")
cvelistv5_df = (
    df_raw.select(
      "vendor","product","ingestionTimestamp","ingestionDate",
      explode("cvelistv5").alias("item")
    )
    .withColumn("cveId",
        regexp_replace(upper(col("item")[0]), "[^\\x00-\\x7F]","")
    )
    .withColumn("details",
        from_json(col("item")[1], cvelist_schema)
    )
)

cvelistv5_df = cvelistv5_df.select(
    "vendor","product","ingestionTimestamp","ingestionDate","cveId",
    col("details.cveMetadata.datePublished").alias("datePublished"),
    col("details.cveMetadata.dateReserved").alias("dateReserved"),
    col("details.cveMetadata.dateUpdated").alias("dateUpdated"),
    col("details.containers.cna.datePublic").alias("datePublic"),
    col("details.containers.cna.descriptions").alias("raw_alt_descriptions"),
    col("details.containers.cna.impacts").alias("impacts"),
    col("details.containers.cna.metrics").alias("cna_metrics"),
    col("details.containers.cna.problemTypes").alias("cna_problemTypes"),
    col("details.containers.adp").alias("adp_array")
)

cvelistv5_df = (
    cvelistv5_df
    .withColumn("cna_impact",      explode_outer("impacts"))
    .withColumn("cna_metric",      explode_outer("cna_metrics"))
    .withColumn("cna_problemType", explode_outer("cna_problemTypes"))
    .withColumn("adp_item",        explode_outer("adp_array"))
    .withColumn("adp_metrics",     col("adp_item.metrics"))
    .withColumn("adp_problemTypes",col("adp_item.problemTypes"))
    .withColumn("adp_problemType", explode_outer("adp_problemTypes"))
    .withColumn("adp_metric",      explode_outer("adp_metrics"))
    .withColumn("raw_alt_cvss",
                F.coalesce(col("cna_metric.cvssV3_1"),
                           col("adp_metric.cvssV3_1"))
    )
    .withColumn("raw_alt_problemtype",
        array_distinct(flatten(expr("""
          array(
            transform(
              filter(cna_problemType.descriptions, x -> x.type='CWE' and x.lang like 'en%'),
              x -> named_struct(
                'type',x.type,'cweId',x.cweId,
                'lang',x.lang,'description',x.description
              )
            ),
            transform(
              filter(adp_problemType.descriptions, x -> x.type='CWE' and x.lang like 'en%'),
              x -> named_struct(
                'type',x.type,'cweId',x.cweId,
                'lang',x.lang,'description',x.description
              )
            )
          )
        """)))
    )
    .withColumn("capec_struct",
        when(col("cna_impact.capecId").isNotNull(),
             F.transform(
               expr("filter(cna_impact.descriptions, x -> x.lang like 'en%')"),
               lambda x: struct(
                 col("cna_impact.capecId").alias("capecId"),
                 x["value"].alias("capecDescription")
               )
             )
        ).otherwise(F.array())
    )
    .withColumn("cwe_struct",
        expr("""
          transform(
            filter(raw_alt_problemtype, x -> x.cweId is not null),
            x -> named_struct('cweId',x.cweId,'cweDescription',x.description)
          )
        """)
    )
    .withColumn("datePublished", to_timestamp("datePublished"))
    .withColumn("dateReserved",  to_timestamp("dateReserved"))
    .withColumn("dateUpdated",   to_timestamp("dateUpdated"))
    .withColumn("datePublic",    to_timestamp("datePublic"))
    .withColumn("alt_descriptions",
                expr("filter(raw_alt_descriptions, x -> x.lang like 'en%')"))
    .withColumn("alt_cvssData",
        when(col("raw_alt_cvss").isNotNull(),
             F.array(expr("""
               named_struct(
                 'source',cast(null as string),
                 'type',  cast(null as string),
                 'version',         raw_alt_cvss.version,
                 'vectorString',    raw_alt_cvss.vectorString,
                 'baseScore',       raw_alt_cvss.baseScore,
                 'exploitabilityScore', cast(null as double),
                 'impactScore',     cast(null as double)
               )
             """))
        ).otherwise(F.array())
    )
)

cvelistv5_grouped = (
    cvelistv5_df.groupBy(
      "vendor","product","cveId","ingestionTimestamp","ingestionDate",
      "datePublished","dateReserved","dateUpdated","datePublic","alt_descriptions"
    )
    .agg(
      array_distinct(flatten(collect_list("alt_cvssData"))).alias("alt_cvssData"),
      array_distinct(flatten(collect_list("capec_struct"))).alias("alt_capecData"),
      array_distinct(flatten(collect_list("cwe_struct"))).alias("alt_cweData")
    )
)
add_log(f"cvelistv5 grouped rows: {cvelistv5_grouped.count():,}")

# Step 4: Process fkie_nvd
add_log("Processing fkie_nvd")
fkie_df = (
    df_raw.select(
      "vendor","product","ingestionTimestamp","ingestionDate",
      explode("fkie_nvd").alias("item")
    )
    .withColumn("raw_details", col("item")[1])
    .withColumn("details", from_json(col("raw_details"), fkie_schema))
    .withColumn("englishDescription",
        explode(expr("filter(details.descriptions, x -> x.lang like 'en%')"))
    )
    .select(
      "vendor","product","ingestionTimestamp","ingestionDate",
      col("details.id").alias("cveId"),
      col("details.published").alias("published"),
      col("details.lastModified").alias("lastModified"),
      col("details.vulnStatus").alias("vulnStatus"),
      col("englishDescription.value").alias("Descriptions"),
      col("details.metrics").alias("cvssMetrics"),
      col("details.weaknesses").alias("weaknesses")
    )
    .withColumn("lastModified", to_timestamp("lastModified"))
    .withColumn("published",    to_timestamp("published"))
)
add_log(f"fkie_nvd rows: {fkie_df.count():,}")

# explode each CVSS version
versions = [
    r["cvssVersion"] for r in
    fkie_df.select(F.explode(F.map_keys(col("cvssMetrics"))).alias("cvssVersion"))
           .distinct().collect()
]

cvss_dfs = []
for ver in versions:
    tmp = (
      fkie_df
      .select(
        "vendor","product","ingestionTimestamp","ingestionDate","cveId",
        "lastModified","vulnStatus","Descriptions","weaknesses","published",
        explode(col(f"cvssMetrics.{ver}")).alias("e")
      )
      .select(
        "vendor","product","ingestionTimestamp","ingestionDate","cveId",
        "lastModified","vulnStatus","Descriptions","weaknesses","published",
        struct(
          col("e.source").alias("source"),
          col("e.type").alias("type"),
          col("e.cvssData.version").alias("version"),
          col("e.cvssData.vectorString").alias("vectorString"),
          col("e.cvssData.baseScore").alias("baseScore"),
          col("e.exploitabilityScore").alias("exploitabilityScore"),
          col("e.impactScore").alias("impactScore")
        ).alias("cvssData")
      )
    )
    cvss_dfs.append(tmp)

if cvss_dfs:
    df_cvss_flattened = cvss_dfs[0]
    for more in cvss_dfs[1:]:
        df_cvss_flattened = df_cvss_flattened.unionByName(more)
    df_cvss_combined = (
      df_cvss_flattened
      .groupBy(
        "vendor","product","ingestionTimestamp","ingestionDate",
        "cveId","lastModified","vulnStatus","Descriptions","published","weaknesses"
      )
      .agg(array_distinct(collect_list("cvssData")).alias("cvssData"))
    )
else:
    df_cvss_combined = fkie_df.withColumn("cvssData", F.array()).distinct()

df_cvss_combined = (
    df_cvss_combined
    .withColumn("weakness", explode_outer("weaknesses"))
    .withColumn("fkie_cweData", expr("""
      transform(
        filter(weakness.description, x -> x.lang like 'en%' and x.value like 'CWE%'),
        x -> named_struct('cweId',x.value,'cweDescription',cast(null as string))
      )
    """))
    .groupBy(
      "vendor","product","ingestionTimestamp","ingestionDate",
      "cveId","lastModified","vulnStatus","Descriptions","published"
    )
    .agg(
      array_distinct(collect_list("cvssData")).alias("cvssData"),
      array_distinct(flatten(collect_list("fkie_cweData"))).alias("fkie_cweData")
    )
)
add_log(f"fkie_nvd combined rows: {df_cvss_combined.count():,}")

# Step 5: Merge both sides
add_log("Merging CVE sides")

cv_df = cvelistv5_grouped.select(
    "vendor", "product", "cveId",
    col("ingestionTimestamp").alias("cv_ingestionTimestamp"),
    col("ingestionDate").alias("cv_ingestionDate"),
    "datePublished", "dateReserved", "dateUpdated", "datePublic",
    "alt_descriptions", "alt_cvssData", "alt_capecData", "alt_cweData"
).alias("cv")

nvd_df = df_cvss_combined.select(
    "vendor", "product", "cveId",
    col("ingestionTimestamp").alias("nvd_ingestionTimestamp"),
    col("ingestionDate").alias("nvd_ingestionDate"),
    "published", "lastModified", "vulnStatus", "Descriptions",
    "cvssData", "fkie_cweData"
).alias("nvd")

combined_df = (
    cv_df.join(nvd_df, ["vendor", "product", "cveId"], "outer")
         .withColumn(
             "ingestionTimestamp",
             F.coalesce(col("cv.cv_ingestionTimestamp"), col("nvd.nvd_ingestionTimestamp"))
         )
         .withColumn(
             "ingestionDate",
             F.coalesce(col("cv.cv_ingestionDate"),      col("nvd.nvd_ingestionDate"))
         )
         .withColumn(
             "datePublished",
             F.coalesce(col("cv.datePublished"), col("nvd.published"))
         )
         .withColumn("vulnStatus",   col("nvd.vulnStatus"))
         .withColumn("lastModified", col("nvd.lastModified"))
         .withColumn(
             "Descriptions",
             F.coalesce(
                 col("nvd.Descriptions"),
                 expr("element_at(filter(cv.alt_descriptions, x -> x.lang like 'en%'), 1).value")
             )
         )
         .withColumn(
             "cvssData",
             when(
                 size(col("nvd.cvssData")) > 0,
                 flatten(col("nvd.cvssData"))
             ).otherwise(
                 col("cv.alt_cvssData")
             )
         )
         .withColumn("capecData", col("cv.alt_capecData"))
         .drop(
             "cv_ingestionTimestamp",
             "cv_ingestionDate",
             "nvd_ingestionTimestamp",
             "nvd_ingestionDate"
         )
)

cwe_from_cv  = combined_df.select("vendor","product","cveId", explode("cv.alt_cweData").alias("cwe"))
cwe_from_nvd = combined_df.select("vendor","product","cveId", explode("nvd.fkie_cweData").alias("cwe"))
all_cwe      = cwe_from_cv.unionByName(cwe_from_nvd)

deduped_cwe = (
    all_cwe
      .groupBy("vendor","product","cveId", col("cwe.cweId"))
      .agg(F.max("cwe.cweDescription").alias("cweDescription"))
)

cwe_agg = (
    deduped_cwe
      .groupBy("vendor","product","cveId")
      .agg(collect_list(struct("cweId","cweDescription")).alias("cweData"))
)

combined_df = combined_df.join(cwe_agg, ["vendor","product","cveId"], "left")
add_log(f"Combined rows: {combined_df.count():,}")

# Step 6: Final aggregation & cleanup
final_df = (
    combined_df.groupBy(
      "vendor","product","cveId","ingestionTimestamp","ingestionDate"
    )
    .agg(
      F.first("vulnStatus").alias("vulnStatus"),
      F.first("datePublished").alias("datePublished"),
      F.first("dateReserved").alias("dateReserved"),
      F.first("dateUpdated").alias("dateUpdated"),
      F.first("datePublic").alias("datePublic"),
      F.first("lastModified").alias("lastModified"),
      F.first("Descriptions").alias("Descriptions"),
      array_distinct(flatten(collect_list("cvssData"))).alias("cvssData"),
      F.first("capecData").alias("capecData"),
      F.first("cweData").alias("cweData")
    )
    .select(
      "ingestionDate","vendor","product","cveId",
      "cweData","capecData","vulnStatus","cvssData",
      "datePublished","dateReserved","dateUpdated","datePublic",
      "lastModified","Descriptions","ingestionTimestamp"
    )
    .withColumn("Descriptions", regexp_replace(col("Descriptions"), "<[^>]*>", ""))
    .withColumn("cvssData",     when(size("cvssData")==0, None).otherwise(col("cvssData")))
    .withColumn("capecData",    when(size("capecData")==0, None).otherwise(col("capecData")))
    .withColumn("cweData",      when(size("cweData")==0, None).otherwise(col("cweData")))
)
add_log(f"Final rows: {final_df.count():,}")

# Step 7: Write to Iceberg via Glue catalog
today    = datetime.now(timezone.utc).strftime("%Y_%m_%d")
table    = f"cve_staging_{today}"
location = STAGING_BUCKET.rstrip("/") + "/" + table

spark.sql(f"""
  CREATE TABLE IF NOT EXISTS glue_catalog.cve_db.{table} (
    ingestionDate date,
    vendor string, product string, cveId string,
    cweData array<struct<cweId:string,cweDescription:string>>,
    capecData array<struct<capecId:string,capecDescription:string>>,
    vulnStatus string,
    cvssData array<struct<
      source:string,type:string,version:string,
      vectorString:string,baseScore:double,
      impactScore:double,exploitabilityScore:double
    >>,
    datePublished timestamp, dateReserved timestamp,
    dateUpdated timestamp, datePublic timestamp,
    lastModified timestamp, Descriptions string,
    ingestionTimestamp timestamp
  ) USING ICEBERG
  LOCATION '{location}'
  PARTITIONED BY (ingestionDate)
""")
final_df.write.format("iceberg")\
     .mode("append")\
     .saveAsTable(f"glue_catalog.cve_db.{table}")
add_log(f"Wrote Iceberg table: glue_catalog.cve_db.{table}")

# Step 8: Upload logs to S3
logs = "\n".join(log_messages)

bucket_name = STAGING_BUCKET.replace("s3://", "").split("/")[0]

log_key = f"{STAGING_LOG_PREFIX}/cve_staging_log_{today}.txt"

s3 = boto3.client("s3", region_name=AWS_REGION)
s3.put_object(
    Bucket=bucket_name,
    Key=log_key,
    Body=logs
)
add_log("Uploaded logs")

spark.stop()
add_log("Transformation job completed")
