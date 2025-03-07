import os
import re
from pyspark.sql import SparkSession
from pyspark.sql.functions import explode, col, upper, from_json, lit, expr, struct, collect_list, array_distinct, map_keys, trim, regexp_replace
from pyspark.sql.types import StructType, StructField, StringType, ArrayType, DoubleType, MapType

# Set environment variables
os.environ["JAVA_HOME"] = "C:\\Program Files\\Java\\jdk-11"
os.environ["HADOOP_HOME"] = "C:\\hadoop"
os.environ["PYSPARK_PYTHON"] = "C:\\Users\\athul\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
os.environ["PYSPARK_DRIVER_PYTHON"] = "C:\\Users\\athul\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"

# Create SparkSession
spark = SparkSession.builder.appName("MergeCVEData").getOrCreate()

# Define file path
file_path = "C:/Users/athul/Downloads/microsoft_office_2025-03-02_19-55-48.json"

# Extract vendor, product, and ingestion timestamp from filename
filename_pattern = r"([a-zA-Z0-9]+)_([a-zA-Z0-9]+)_([0-9-]+)_([0-9-]+)\.json"
match = re.search(filename_pattern, os.path.basename(file_path))
if match:
    vendor, product, date_part, time_part = match.groups()
    ingestion_timestamp = f"{date_part} {time_part.replace('-', ':')}"
else:
    vendor, product, ingestion_timestamp = "unknown", "unknown", "unknown"

# Read JSON file
df = spark.read.json(file_path)

# Process cvelistv5 Data
cvelistv5_df = df.select(explode("cvelistv5").alias("item")).select(
    col("item")[0].alias("cveId"),
    col("item")[1].alias("details_str")
)

cvelist_schema = StructType([
    StructField("cveMetadata", StructType([
        StructField("datePublished", StringType(), True),
        StructField("dateReserved", StringType(), True),
        StructField("dateUpdated", StringType(), True)
    ]), True),
    StructField("containers", StructType([
        StructField("cna", StructType([
            StructField("datePublic", StringType(), True)
        ]), True)
    ]), True)
])

cvelistv5_df = cvelistv5_df.withColumn("details", from_json(col("details_str"), cvelist_schema)).select(
    "cveId",
    col("details.cveMetadata.datePublished").alias("datePublished"),
    col("details.cveMetadata.dateReserved").alias("dateReserved"),
    col("details.cveMetadata.dateUpdated").alias("dateUpdated"),
    col("details.containers.cna.datePublic").alias("datePublic")
)

# Process fkie_nvd Data
fkie_df = df.select(explode("fkie_nvd").alias("item")).select(
    col("item")[0].alias("id"),
    col("item")[1].alias("details_str")
)

fkie_schema = StructType([
    StructField("id", StringType(), True),
    StructField("lastModified", StringType(), True),
    StructField("vulnStatus", StringType(), True),
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
    StructField("descriptions", ArrayType(StructType([
        StructField("lang", StringType(), True),
        StructField("value", StringType(), True)
    ])), True)
])

fkie_df = fkie_df.withColumn("details", from_json(col("details_str"), fkie_schema))
fkie_df = fkie_df.withColumn(
    "englishDescription",
    explode(expr("filter(details.descriptions, x -> x.lang = 'en')")).alias("Descriptions")
).select(
    col("details.id").alias("cveId"),
    col("details.lastModified").alias("lastModified"),
    col("details.vulnStatus").alias("vulnStatus"),
    col("details.metrics").alias("cvssMetrics"),
    col("englishDescription.value").alias("Descriptions")
)

# Extract CVSS versions dynamically
cvss_versions = [row["cvssVersion"] for row in fkie_df.select(explode(map_keys(col("cvssMetrics"))).alias("cvssVersion")).distinct().collect()]

cvss_dfs = []
for version in cvss_versions:
    cvss_dfs.append(
        fkie_df.select(
            "cveId", "lastModified", "vulnStatus",
            explode(col(f"cvssMetrics.{version}")).alias("cvssEntry"), "Descriptions"
        ).select(
            "cveId", "lastModified", "vulnStatus",
            struct(
                col("cvssEntry.source"),
                col("cvssEntry.type"),
                col("cvssEntry.cvssData.version"),
                col("cvssEntry.cvssData.vectorString"),
                col("cvssEntry.cvssData.baseScore"),
                col("cvssEntry.exploitabilityScore"),
                col("cvssEntry.impactScore")
            ).alias("cvssData"), "Descriptions"
        )
    )

df_cvss_flattened = cvss_dfs[0]
for df in cvss_dfs[1:]:
    df_cvss_flattened = df_cvss_flattened.union(df)

df_cvss_combined = df_cvss_flattened.groupBy("cveId", "lastModified", "vulnStatus", "Descriptions").agg(
    collect_list("cvssData").alias("cvssData")
).withColumn("cvssData", array_distinct(col("cvssData")))

# Check for Leading/Trailing Whitespaces or Extra Characters and Verifying Case Sensitivity Before Joining on cveId
cvelistv5_df = cvelistv5_df.withColumn(
    "cveId", regexp_replace(upper(trim(col("cveId"))), "[^\\x00-\\x7F]", "")
)

df_cvss_combined = df_cvss_combined.withColumn(
    "cveId", regexp_replace(upper(trim(col("cveId"))), "[^\\x00-\\x7F]", "")
)

# Check for Null Values in cveId Columns
print("Null cveId values in cvelistv5_df:", cvelistv5_df.filter(col("cveId").isNull()).count())
print("Null cveId values in df_cvss_combined:", df_cvss_combined.filter(col("cveId").isNull()).count())

# Merge DataFrames
final_df = cvelistv5_df.join(df_cvss_combined, "cveId", "outer").withColumn("vendor", lit(vendor))\
    .withColumn("product", lit(product))\
    .withColumn("ingestion_timestamp", lit(ingestion_timestamp))

# Reorder Columns
final_columns = ["vendor", "product", "ingestion_timestamp"] + [col for col in final_df.columns if col not in ["vendor", "product", "ingestion_timestamp"]]
final_df = final_df.select(*final_columns)

# Show result
# final_df.show(100, truncate=False)
filtered_value = final_df.filter(final_df["cveId"] == "CVE-2020-1483")#.select("cvssData")
filtered_value.show(truncate=False)
