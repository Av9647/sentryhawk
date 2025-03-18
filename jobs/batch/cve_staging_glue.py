import sys, re, boto3
from datetime import datetime, timezone
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import SparkSession
import pyspark.sql.functions as F
from pyspark.sql.functions import (
    explode, explode_outer, col, upper, from_json, expr, struct,
    collect_list, array, array_distinct, map_keys, trim, regexp_replace,
    input_file_name, when, flatten, size
)
from pyspark.sql.types import (
    StructType, StructField, StringType, ArrayType, DoubleType, MapType
)

# --- S3 Definitions ---
SOURCE_BUCKET = "s3://cve-ingestion/cve_json/"
STAGING_BUCKET = "s3://cve-staging/cve_staging_tables/"
STAGING_LOG_PREFIX = "cve_staging_logs/"

# --- Initialize Spark/Glue ---
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

# --- Logging Helper ---
log_messages = []
def add_log(msg):
    log_messages.append(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

add_log("Starting main processing script.")

# --- Step 1: Find latest ingestion folder in S3 ---
try:
    add_log("Listing ingestion folders using boto3...")
    s3_client = boto3.client('s3')
    bucket_name = "cve-ingestion"
    prefix = "cve_json/"
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    ingestion_days = set()
    for obj in response.get("Contents", []):
        match = re.search(r"cve_json/(\d{4}-\d{2}-\d{2})/", obj["Key"])
        if match:
            ingestion_days.add(match.group(1))
    if not ingestion_days:
        raise Exception("No valid ingestion day folders found in S3.")
    latest_day = max(ingestion_days)
    latest_directory = f"s3a://{bucket_name}/cve_json/{latest_day}/*.gz"
    add_log(f"Latest ingestion day determined: {latest_day}")
    add_log(f"Reading NDJSON from: {latest_directory}")
except Exception as e:
    add_log(f"Error determining ingestion day: {str(e)}")
    raise

# --- Step 2: Define schemas ---
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
            StructField("impacts", ArrayType(StructType([
                StructField("capecId", StringType(), True),
                StructField("descriptions", ArrayType(StructType([
                    StructField("lang", StringType(), True),
                    StructField("value", StringType(), True)
                ])), True)
            ])), True),
            StructField("metrics", ArrayType(StructType([
                StructField("cvssV3_1", StructType([
                    StructField("version", StringType(), True),
                    StructField("vectorString", StringType(), True),
                    StructField("baseScore", DoubleType(), True)
                ]), True)
            ])), True),
            StructField("problemTypes", ArrayType(StructType([
                StructField("descriptions", ArrayType(StructType([
                    StructField("cweId", StringType(), True),
                    StructField("description", StringType(), True),
                    StructField("lang", StringType(), True),
                    StructField("type", StringType(), True)
                ])), True)
            ])), True)
        ]), True),
        StructField("adp", ArrayType(StructType([
            StructField("problemTypes", ArrayType(StructType([
                StructField("descriptions", ArrayType(StructType([
                    StructField("type", StringType(), True),
                    StructField("cweId", StringType(), True),
                    StructField("lang", StringType(), True),
                    StructField("description", StringType(), True)
                ])), True)
            ]), True)),
            StructField("metrics", ArrayType(StructType([
                StructField("cvssV3_1", StructType([
                    StructField("version", StringType(), True),
                    StructField("vectorString", StringType(), True),
                    StructField("baseScore", DoubleType(), True)
                ]), True)
            ])), True)
        ])), True)
    ]), True)
])

fkie_schema = StructType([
    StructField("id", StringType(), True),
    StructField("published", StringType(), True),
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
    ])), True)),
    StructField("weaknesses", ArrayType(StructType([
        StructField("source", StringType(), True),
        StructField("type", StringType(), True),
        StructField("description", ArrayType(StructType([
            StructField("lang", StringType(), True),
            StructField("value", StringType(), True)
        ])), True)
    ])), True)
])

ndjson_schema = StructType([
    StructField("vendor", StringType(), True),
    StructField("product", StringType(), True),
    StructField("ingestionTimestamp", StringType(), True),
    StructField("ingestionDate", StringType(), True),
    StructField("cvelistv5", ArrayType(ArrayType(StringType())), True),
    StructField("fkie_nvd", ArrayType(ArrayType(StringType())), True)
])

# --- Step 3: Read NDJSON files ---
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

# --- Step 4a: Process cvelistv5 ---
cvelistv5_df = df_raw.select(
    "vendor", "product", "ingestionTimestamp", "ingestionDate",
    explode("cvelistv5").alias("item")
).withColumn(
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
    col("details.containers.cna.impacts").alias("impacts"),  
    col("details.containers.cna.metrics").alias("cna_metrics"),
    col("details.containers.cna.problemTypes").alias("cna_problemTypes"),
    col("details.containers.adp").alias("adp_array")
)

cvelistv5_df = (
    cvelistv5_df
    .withColumn("cna_impact", explode_outer("impacts"))
    .withColumn("cna_metric", explode_outer("cna_metrics"))
    .withColumn("cna_problemType", explode_outer("cna_problemTypes"))
    .withColumn("adp_item", explode_outer("adp_array"))
    .withColumn("adp_metrics", col("adp_item.metrics"))
    .withColumn("adp_problemTypes", col("adp_item.problemTypes"))
    .withColumn("adp_problemType", explode_outer("adp_problemTypes"))
    .withColumn("adp_metric", explode_outer("adp_metrics"))
    .withColumn(
        "raw_alt_cvss", 
        F.coalesce(col("cna_metric.cvssV3_1"), col("adp_metric.cvssV3_1"))
    )
    .withColumn(
        "raw_alt_problemtype",
        array_distinct(
            flatten(
                array(
                    expr("""
                      transform(
                        filter(cna_problemType.descriptions, x -> x.type = 'CWE' and x.lang like 'en%'),
                        x -> named_struct(
                            'type', x.type,
                            'cweId', x.cweId,
                            'lang', x.lang,
                            'description', x.description
                        )
                      )
                    """),
                    expr("""
                      transform(
                        filter(adp_problemType.descriptions, x -> x.type = 'CWE' and x.lang like 'en%'),
                        x -> named_struct(
                            'type', x.type,
                            'cweId', x.cweId,
                            'lang', x.lang,
                            'description', x.description
                        )
                      )
                    """)
                )
            )
        )
    )
    .withColumn(
        "capec_struct",
        when(
            col("cna_impact.capecId").isNotNull(),
            F.transform(
                expr("filter(cna_impact.descriptions, x -> x.lang like 'en%')"),
                lambda x: struct(
                    col("cna_impact.capecId").alias("capecId"),
                    x["value"].alias("capecDescription")
                )
            )
        ).otherwise(F.array())
    )
    .withColumn(
        "cwe_struct",
        expr("""
            transform(
              filter(raw_alt_problemtype, x -> x.cweId is not null),
              x -> named_struct(
                    'cweId', x.cweId,
                    'cweDescription', x.description
              )
            )
        """)
    )
    .withColumn("datePublished", F.to_timestamp("datePublished"))
    .withColumn("dateReserved", F.to_timestamp("dateReserved"))
    .withColumn("dateUpdated", F.to_timestamp("dateUpdated"))
    .withColumn("datePublic", F.to_timestamp("datePublic"))
    .withColumn(
        "alt_descriptions", 
        expr("filter(raw_alt_descriptions, x -> x.lang like 'en%')")
    )
    .withColumn(
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
                    'exploitabilityScore', cast(null as double),
                    'impactScore', cast(null as double)
                  )
                """)
            )
        ).otherwise(F.array())
    )
)

cvelistv5_grouped = cvelistv5_df.groupBy(
    "vendor", "product", "cveId", "ingestionTimestamp", "ingestionDate",
    "datePublished", "dateReserved", "dateUpdated", "datePublic", "alt_descriptions"
).agg(
    array_distinct(flatten(collect_list("alt_cvssData"))).alias("alt_cvssData"),
    array_distinct(flatten(collect_list("capec_struct"))).alias("alt_capecData"),
    array_distinct(flatten(collect_list("cwe_struct"))).alias("alt_cweData")
)

add_log(f"cvelistv5_df record count after grouping: {cvelistv5_grouped.count()}")

# --- Step 4b: Process fkie_nvd ---
fkie_df = df_raw.select(
    "vendor", "product", "ingestionTimestamp", "ingestionDate",
    explode("fkie_nvd").alias("item")
).withColumn("raw_details", col("item")[1]) \
 .withColumn("details", from_json(col("raw_details"), fkie_schema)) \
 .withColumn("englishDescription", explode(expr("filter(details.descriptions, x -> x.lang like 'en%')"))) \
 .select(
    "vendor", "product", "ingestionTimestamp", "ingestionDate",
    col("details.id").alias("cveId"),
    col("details.published").alias("published"),
    col("details.lastModified").alias("lastModified"),
    col("details.vulnStatus").alias("vulnStatus"),
    col("englishDescription.value").alias("Descriptions"),
    col("details.metrics").alias("cvssMetrics"),
    col("details.weaknesses").alias("weaknesses")
).withColumn("lastModified", F.to_timestamp("lastModified")) \
 .withColumn("published", F.to_timestamp("published"))

add_log(f"fkie_df record count: {fkie_df.count()}")

cvss_versions = [
    row["cvssVersion"]
    for row in fkie_df.select(explode(map_keys(col("cvssMetrics"))).alias("cvssVersion")).distinct().collect()
]

cvss_dfs = []
for version in cvss_versions:
    tmp_df = fkie_df.select(
        "vendor", "product", "ingestionTimestamp", "ingestionDate", "cveId",
        "lastModified", "vulnStatus", "Descriptions", "weaknesses", "published",
        explode(col(f"cvssMetrics.{version}")).alias("cvssEntry")
    ).select(
        "vendor", "product", "ingestionTimestamp", "ingestionDate", "cveId",
        "lastModified", "vulnStatus", "Descriptions", "weaknesses", "published",
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
        "cveId", "lastModified", "vulnStatus", "Descriptions", "published", "weaknesses"
    ).agg(
        array_distinct(collect_list("cvssData")).alias("cvssData")
    )
else:
    df_cvss_combined = fkie_df.withColumn("cvssData", F.array()).distinct()

add_log(f"CVSS combined record count: {df_cvss_combined.count()}")

# --- Process CWE from fkie_nvd ---
df_cvss_combined = df_cvss_combined.withColumn("weakness", explode_outer("weaknesses")).withColumn(
    "fkie_cwe_struct",
    expr("""
       transform(
         filter(weakness.description, x -> x.lang like 'en%' and x.value like 'CWE%'),
         x -> named_struct(
             'cweId', x.value,
             'cweDescription', cast(null as string)
         )
       )
    """)
)

df_cvss_combined = df_cvss_combined.groupBy(
    "vendor", "product", "ingestionTimestamp", "ingestionDate",
    "cveId", "lastModified", "vulnStatus", "Descriptions", "published"
).agg(
    array_distinct(flatten(collect_list("cvssData"))).alias("cvssData"),
    array_distinct(flatten(collect_list("fkie_cwe_struct"))).alias("fkie_cweData")
)

# --- Step 5: Merge cvelistv5 & fkie_nvd ---
cv_df = cvelistv5_grouped.select(
    "vendor", "product", "cveId",
    F.col("ingestionTimestamp").alias("cv_ingestionTimestamp"),
    F.col("ingestionDate").alias("cv_ingestionDate"),
    "datePublished", "dateReserved", "dateUpdated", "datePublic",
    "alt_descriptions", "alt_cvssData", "alt_capecData", "alt_cweData"
).alias("cv")

nvd_df = df_cvss_combined.select(
    "vendor", "product", "cveId",
    F.col("ingestionTimestamp").alias("nvd_ingestionTimestamp"),
    F.col("ingestionDate").alias("nvd_ingestionDate"),
    "lastModified", "vulnStatus", "Descriptions", "cvssData", "fkie_cweData",
    "published"
).alias("nvd")

combined_df = cv_df.join(nvd_df, ["vendor", "product", "cveId"], "outer") \
    .withColumn("ingestionTimestamp", F.coalesce(col("cv.cv_ingestionTimestamp"), col("nvd.nvd_ingestionTimestamp"))) \
    .withColumn("ingestionDate", F.coalesce(col("cv.cv_ingestionDate"), col("nvd.nvd_ingestionDate"))) \
    .withColumn("datePublished", F.coalesce(col("cv.datePublished"), col("nvd.published"))) \
    .withColumn("dateReserved", col("cv.dateReserved")) \
    .withColumn("dateUpdated", col("cv.dateUpdated")) \
    .withColumn("datePublic", col("cv.datePublic")) \
    .withColumn("vulnStatus", col("nvd.vulnStatus")) \
    .withColumn("lastModified", col("nvd.lastModified")) \
    .withColumn(
        "Descriptions",
        F.coalesce(
            col("nvd.Descriptions"),
            expr("element_at(filter(cv.alt_descriptions, x -> x.lang like 'en%'), 1).value")
        )
    ).withColumn(
        "cvssData",
        when(
            (col("nvd.cvssData").isNotNull()) & (F.size(col("nvd.cvssData")) > 0),
            col("nvd.cvssData")
        ).otherwise(col("cv.alt_cvssData"))
    ).withColumn("capecData", col("cv.alt_capecData"))

# --- Combine CWE from both sides ---
cwe_from_cv = combined_df.select("vendor", "product", "cveId", F.explode("cv.alt_cweData").alias("cwe"))
cwe_from_nvd = combined_df.select("vendor", "product", "cveId", F.explode("nvd.fkie_cweData").alias("cwe"))
all_cwe = cwe_from_cv.unionByName(cwe_from_nvd)

deduped_cwe = all_cwe.groupBy("vendor", "product", "cveId", "cwe.cweId").agg(
    F.max("cwe.cweDescription").alias("cweDescription")
)

cwe_agg = deduped_cwe.groupBy("vendor", "product", "cveId").agg(
    F.collect_list(F.struct("cweId", "cweDescription")).alias("cweData")
)

combined_df = combined_df.join(cwe_agg, ["vendor", "product", "cveId"], "left")
add_log(f"Combined DataFrame record count: {combined_df.count()}")

# --- Step 6: Combine rows if same vendor-product-cveId appears in multiple chunks ---
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
    array_distinct(flatten(collect_list("cvssData"))).alias("cvssData"),
    F.first("capecData").alias("capecData"),
    F.first("cweData").alias("cweData")
)

final_df = final_df.select(
    "ingestionDate", "vendor", "product", "cveId", "cweData", "capecData",
    "vulnStatus", "cvssData", "datePublished", "dateReserved", "dateUpdated",
    "datePublic", "lastModified", "Descriptions", "ingestionTimestamp"
).withColumn(
    "Descriptions",
    regexp_replace(col("Descriptions"), "<[^>]*>", "")
)

# --- Enforce consistent cvssData field order and transform empty arrays to null ---
final_df = final_df.withColumn(
    "cvssData",
    expr("""
      transform(
        cvssData,
        x -> named_struct(
          'source', x.source,
          'type', x.type,
          'version', x.version,
          'vectorString', x.vectorString,
          'baseScore', x.baseScore,
          'impactScore', x.impactScore,
          'exploitabilityScore', x.exploitabilityScore
        )
      )
    """)
).withColumn(
    "cvssData",
    expr("""
      CASE 
        WHEN size(cvssData) = 0 
        THEN cast(NULL as array<struct<
          source:string,
          type:string,
          version:string,
          vectorString:string,
          baseScore:double,
          impactScore:double,
          exploitabilityScore:double
        >>)
        ELSE cvssData
      END
    """)
).withColumn(
    "capecData",
    when(
        size("capecData") == 0,
        F.lit(None).cast("array<struct<capecId:string,capecDescription:string>>")
    ).otherwise(col("capecData"))
).withColumn(
    "cweData",
    when(
        size("cweData") == 0,
        F.lit(None).cast("array<struct<cweId:string,cweDescription:string>>")
    ).otherwise(col("cweData"))
)

# --- Step 7: Write to Iceberg table ---
current_date = datetime.now(timezone.utc).strftime("%Y_%m_%d")
staging_table_name = f"cve_staging_{current_date}"
staging_table_location = f"{STAGING_BUCKET}{staging_table_name}"
try:
    spark.sql(f"""
        CREATE TABLE IF NOT EXISTS glue_catalog.cve_db.{staging_table_name} (
            ingestionDate date,
            vendor string,
            product string,
            cveId string,
            cweData ARRAY<STRUCT<cweId string, cweDescription string>>,
            capecData ARRAY<STRUCT<capecId string, capecDescription string>>,
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

final_df.write.format("iceberg") \
    .mode("append") \
    .saveAsTable(f"glue_catalog.cve_db.{staging_table_name}")

add_log("Insert executed for all records.")

# --- Step 8: Write logs to S3 ---
try:
    log_content = "\n".join(log_messages)
    log_file_key = f"{STAGING_LOG_PREFIX}cve_staging_log_{current_date}.txt"
    boto3.client("s3").put_object(Bucket="cve-staging", Key=log_file_key, Body=log_content)
    add_log("Log file written successfully.")
except Exception as log_ex:
    add_log("Failed writing log file: " + str(log_ex))

print("Processing completed. Check logs in the staging bucket.")
job.commit()
