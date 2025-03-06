import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, explode, from_json, expr, map_keys, struct, collect_list, array_distinct
from pyspark.sql.types import StructType, StructField, StringType, ArrayType, DoubleType, MapType

# Set environment variables
os.environ["JAVA_HOME"] = "C:\\Program Files\\Java\\jdk-11"
os.environ["HADOOP_HOME"] = "C:\\hadoop"
os.environ["PYSPARK_PYTHON"] = "C:\\Users\\athul\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
os.environ["PYSPARK_DRIVER_PYTHON"] = "C:\\Users\\athul\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"

# Create SparkSession
spark = SparkSession.builder.appName("ExtractFKIENVD").getOrCreate()

# Read the JSON file
df = spark.read.json("C:/Users/athul/Downloads/microsoft_office_2025-03-02_19-55-48.json")

# Explode "fkie_nvd" array into individual records
df_exploded = df.select(explode("fkie_nvd").alias("item"))

# Extract the structured part of each record
df_extracted = df_exploded.select(
    col("item")[0].alias("id"),  # Extract CVE ID
    col("item")[1].alias("details_str")  # Extract details as a raw string
)

# Define schema for CVSS Data (ensuring version is extracted properly)
cvss_data_schema = StructType([
    StructField("version", StringType(), True),
    StructField("vectorString", StringType(), True),
    StructField("baseScore", DoubleType(), True)
])

# Define schema for CVSS Metric (Ensures outer values like `source` & `type` are retained)
cvss_metric_schema = StructType([
    StructField("cvssData", cvss_data_schema, True),  # Extracts cvssData properly
    StructField("exploitabilityScore", DoubleType(), True),
    StructField("impactScore", DoubleType(), True)
])

# Define schema for `fkie_nvd` data
fkie_nvd_schema = StructType([
    StructField("id", StringType(), True),  
    StructField("lastModified", StringType(), True),
    StructField("vulnStatus", StringType(), True),
    StructField("descriptions", ArrayType(StructType([
        StructField("lang", StringType(), True),
        StructField("value", StringType(), True)
    ])), True),
    StructField("metrics", MapType(StringType(), ArrayType(cvss_metric_schema), True))  # Retains entire metrics
])

# Convert details_str to structured JSON
df_parsed = df_extracted.withColumn("details", from_json(col("details_str"), fkie_nvd_schema))

# Extract English descriptions properly
df_with_description = df_parsed.withColumn(
    "englishDescription",
    explode(expr("filter(details.descriptions, x -> x.lang = 'en')")).alias("Descriptions")
).select(
    col("details.id").alias("cveId"),
    col("details.lastModified").alias("lastModified"),
    col("details.vulnStatus").alias("vulnStatus"),
    col("englishDescription.value").alias("Descriptions"),
    col("details.metrics").alias("cvssMetrics")  # Retains entire CVSS map
)

# Extract available CVSS versions dynamically
cvss_versions = df_with_description.select(explode(map_keys(col("cvssMetrics"))).alias("cvssVersion")).distinct().collect()
cvss_versions = [row["cvssVersion"] for row in cvss_versions]  # Extracts versions dynamically

# Dynamically extract and explode CVSS data
cvss_dfs = []
for version in cvss_versions:
    cvss_dfs.append(
        df_with_description.select(
            "cveId", "lastModified", "vulnStatus", "Descriptions",
            explode(col(f"cvssMetrics.{version}")).alias("cvssEntry")  # Explodes each metric version
        ).select(
            "cveId", "lastModified", "vulnStatus", "Descriptions",
            struct(
                col("cvssEntry.cvssData.version"),
                col("cvssEntry.cvssData.vectorString"),
                col("cvssEntry.cvssData.baseScore"),
                # Retain Outer Values from `cvssMetric` level
                col("cvssEntry.exploitabilityScore"),
                col("cvssEntry.impactScore")
            ).alias("cvssData")
        )
    )

# Merge all CVSS versions dynamically
df_cvss_flattened = cvss_dfs[0]
for df in cvss_dfs[1:]:
    df_cvss_flattened = df_cvss_flattened.union(df)

# Group by CVE ID and collect all CVSS data into an array of arrays
df_cvss_combined = df_cvss_flattened.groupBy("cveId", "lastModified", "vulnStatus", "Descriptions").agg(
    collect_list("cvssData").alias("cvssData")  # Collects all versions dynamically
)

# Remove duplicate values within cvssData array
df_cvss_combined = df_cvss_combined.withColumn("cvssData", array_distinct(col("cvssData")))

# Show the result
df_cvss_combined.show(20, truncate=False)
