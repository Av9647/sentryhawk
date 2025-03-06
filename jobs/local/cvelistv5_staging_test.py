import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import explode, col, from_json
from pyspark.sql.types import StructType, StructField, StringType

# Set environment variables (adjust paths as needed)
os.environ["JAVA_HOME"] = "C:\\Program Files\\Java\\jdk-11"
os.environ["HADOOP_HOME"] = "C:\\hadoop"
os.environ["PYSPARK_PYTHON"] = "C:\\Users\\athul\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
os.environ["PYSPARK_DRIVER_PYTHON"] = "C:\\Users\\athul\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"

# Create SparkSession
spark = SparkSession.builder.appName("ExtractCVE").getOrCreate()

# Read the JSON file
df = spark.read.json("C:/Users/athul/Downloads/microsoft_office_2025-03-02_19-55-48.json")

# Explode the "cvelistv5" array into rows
df_exploded = df.select(explode("cvelistv5").alias("item"))

# Extract cveId and details
df_extracted = df_exploded.select(
    col("item")[0].alias("cveId"),
    col("item")[1].alias("details_str")  # Read details as a string initially
)

# Define schema for details
details_schema = StructType([
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

# Parse details_str into structured JSON format
df_parsed = df_extracted.withColumn("details", from_json(col("details_str"), details_schema))

# Extract fields from the structured column
cvelistv5_df = df_parsed.select(
    "cveId",
    col("details.cveMetadata.datePublished").alias("datePublished"),
    col("details.cveMetadata.dateReserved").alias("dateReserved"),
    col("details.cveMetadata.dateUpdated").alias("dateUpdated"),
    col("details.containers.cna.datePublic").alias("datePublic")
)

# Show the result
cvelistv5_df.show(truncate=False)
