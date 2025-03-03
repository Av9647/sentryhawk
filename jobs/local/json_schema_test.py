import os
from pyspark.sql import SparkSession

# Set Java and Hadoop paths
os.environ["JAVA_HOME"] = "C:\\Program Files\\Java\\jdk-11"  # Update with your Java path
os.environ["HADOOP_HOME"] = "C:\\hadoop"

# Initialize Spark
spark = SparkSession.builder \
    .appName("SchemaExtractor") \
    .config("spark.sql.catalogImplementation", "hive") \
    .getOrCreate()

print("Spark Session Created Successfully!")

# Load JSON (for testing, replace with actual file path)
df = spark.read.json("C:\\Users\\athul\\Downloads\\microsoft_office_2025-03-02_19-55-48.json")
df.printSchema()
