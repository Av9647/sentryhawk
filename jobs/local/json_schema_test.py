import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, explode, from_json, coalesce
from pyspark.sql.types import StructType, ArrayType, StructField, StringType

os.environ["JAVA_HOME"] = "C:\\Program Files\\Java\\jdk-11"
os.environ["HADOOP_HOME"] = "C:\\hadoop"
os.environ["PYSPARK_PYTHON"] = "C:\\Users\\athul\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
os.environ["PYSPARK_DRIVER_PYTHON"] = "C:\\Users\\athul\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"

# Create SparkSession
spark = SparkSession.builder.appName("ExtractCVE").getOrCreate()

# Read the JSON file
df = spark.read.json("C:/Users/athul/Downloads/microsoft_office_2025-03-02_19-55-48.json")

# Explode the top-level "cvelistv5" array.
df_exploded = df.select(explode("cvelistv5").alias("cve"))

# Extract the CVE ID and the details as a JSON string
df_extracted = df_exploded.select(
    col("cve")[0].alias("cveId"),
    col("cve")[1].alias("details_str")
)

# Define a schema for the metrics section.
# Here we assume that the field we're interested in is "baseScore" (a string)
# and that it may appear under any of the keys: cvssV3_1, cvssV3, or cvssV2.
metrics_schema = StructType([
    StructField("cvssV3_1", StructType([
        StructField("baseScore", StringType(), True)
    ]), True),
    StructField("cvssV3", StructType([
        StructField("baseScore", StringType(), True)
    ]), True),
    StructField("cvssV2", StructType([
        StructField("baseScore", StringType(), True)
    ]), True)
])

# Define a schema for the details.
# Note that in the file, the second element is an object with a "containers" field,
# and inside "containers" there is an "adp" array.
details_schema = StructType([
    StructField("containers", StructType([
        StructField("adp", ArrayType(
            StructType([
                StructField("metrics", ArrayType(metrics_schema), True)
            ])
        ), True)
    ]), True)
])

# Parse the details string into a struct using the defined schema.
df_parsed = df_extracted.withColumn("details", from_json(col("details_str").cast("string"), details_schema))

# Extract baseScore by checking for the field in cvssV3_1, then cvssV3, and finally cvssV2.
df_result = df_parsed.withColumn(
    "baseScore",
    coalesce(
        col("details.containers.adp")[0].getItem("metrics")[0].getItem("cvssV3_1").getItem("baseScore"),
        col("details.containers.adp")[0].getItem("metrics")[0].getItem("cvssV3").getItem("baseScore"),
        col("details.containers.adp")[0].getItem("metrics")[0].getItem("cvssV2").getItem("baseScore")
    )
).select("cveId", "baseScore")

# Show the result
df_result.show(truncate=False)
