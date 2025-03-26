import sys
from pyspark.sql import SparkSession, functions as F
from pyspark.sql.functions import when, to_date, col, count, sum as _sum, avg
from awsglue.utils import getResolvedOptions
from awsglue.context import GlueContext
from pyspark.context import SparkContext

# --- Initialize Glue and Spark ---
args = getResolvedOptions(sys.argv, ['JOB_NAME'])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = SparkSession.builder \
    .config("spark.sql.catalog.spark_catalog", "org.apache.iceberg.spark.SparkCatalog") \
    .config("spark.sql.catalog.spark_catalog.catalog-impl", "org.apache.iceberg.aws.glue.GlueCatalog") \
    .config("spark.sql.catalog.spark_catalog.warehouse", "s3://cve-production/") \
    .config("spark.sql.iceberg.handle-timestamp-without-timezone", "true") \
    .getOrCreate()

# Set database name
database_name = "cve_db"

# Read production table (assumed to be updated via SCD Type 2, and only current records are marked with current_flag = true)
production_df = spark.table(f"{database_name}.cve_production_master").filter("current_flag = true")

# Define the weighted score expression
weighted_score = when(col("severity") == "Critical", col("max_cvss_score") * 1.0) \
    .when(col("severity") == "High", col("max_cvss_score") * 0.75) \
    .when(col("severity") == "Medium", col("max_cvss_score") * 0.50) \
    .when(col("severity") == "Low", col("max_cvss_score") * 0.25) \
    .otherwise(0)

# ---------------------------
# A. Cumulative Vendor Table
# ---------------------------
cumulative_vendor = (
    production_df
    .withColumn("datePublished", to_date(col("datePublished")))
    .groupBy("vendor", "datePublished")
    .agg(
        count("*").alias("total_cves"),
        F.round(_sum(weighted_score), 2).alias("threat_index"),
        F.round(avg(col("max_cvss_score")), 2).alias("avg_cvss"),
        _sum(when(col("severity") == "Critical", 1).otherwise(0)).alias("critical_count"),
        _sum(when(col("severity") == "High", 1).otherwise(0)).alias("high_count"),
        _sum(when(col("severity") == "Medium", 1).otherwise(0)).alias("medium_count"),
        _sum(when(col("severity") == "Low", 1).otherwise(0)).alias("low_count")
    )
    # Add average threat per CVE
    .withColumn("avg_threat_per_cve", F.round(col("threat_index") / col("total_cves"), 2))
    # Add risk rating
    .withColumn(
        "risk_rating",
        when(col("threat_index") >= 200, "Severe")
        .when(col("threat_index") >= 100, "High")
        .when(col("threat_index") >= 50,  "Moderate")
        .when(col("threat_index") > 0,    "Low")
        .otherwise("None")
    )
)

# Write the vendor cumulative table as an Iceberg table
cumulative_vendor.write.format("iceberg") \
    .mode("overwrite") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_cumulative_vendor/") \
    .saveAsTable(f"{database_name}.cve_production_cumulative_vendor")

# ---------------------------
# B. Cumulative Product Table
# ---------------------------
cumulative_product = (
    production_df
    .withColumn("datePublished", to_date(col("datePublished")))
    .groupBy("vendor", "product", "datePublished")
    .agg(
        count("*").alias("total_cves"),
        F.round(_sum(weighted_score), 2).alias("threat_index"),
        F.round(avg(col("max_cvss_score")), 2).alias("avg_cvss"),
        _sum(when(col("severity") == "Critical", 1).otherwise(0)).alias("critical_count"),
        _sum(when(col("severity") == "High", 1).otherwise(0)).alias("high_count"),
        _sum(when(col("severity") == "Medium", 1).otherwise(0)).alias("medium_count"),
        _sum(when(col("severity") == "Low", 1).otherwise(0)).alias("low_count")
    )
    .withColumn("avg_threat_per_cve", F.round(col("threat_index") / col("total_cves"), 2))
    .withColumn(
        "risk_rating",
        when(col("threat_index") >= 200, "Severe")
        .when(col("threat_index") >= 100, "High")
        .when(col("threat_index") >= 50,  "Moderate")
        .when(col("threat_index") > 0,    "Low")
        .otherwise("None")
    )
)

# Write the product cumulative table as an Iceberg table
cumulative_product.write.format("iceberg") \
    .mode("overwrite") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_cumulative_product/") \
    .saveAsTable(f"{database_name}.cve_production_cumulative_product")

# ---------------------------
# C. Global Summary Table
# ---------------------------
global_summary = (
    production_df
    .withColumn("datePublished", to_date(col("datePublished")))
    .groupBy("datePublished")
    .agg(
        count("*").alias("total_cves"),
        F.round(_sum(weighted_score), 2).alias("threat_index"),
        F.round(avg(col("max_cvss_score")), 2).alias("avg_cvss"),
        _sum(when(col("severity") == "Critical", 1).otherwise(0)).alias("critical_count"),
        _sum(when(col("severity") == "High", 1).otherwise(0)).alias("high_count"),
        _sum(when(col("severity") == "Medium", 1).otherwise(0)).alias("medium_count"),
        _sum(when(col("severity") == "Low", 1).otherwise(0)).alias("low_count")
    )
    .withColumn("avg_threat_per_cve", F.round(col("threat_index") / col("total_cves"), 2))
    .withColumn(
        "risk_rating",
        when(col("threat_index") >= 200, "Severe")
        .when(col("threat_index") >= 100, "High")
        .when(col("threat_index") >= 50,  "Moderate")
        .when(col("threat_index") > 0,    "Low")
        .otherwise("None")
    )
)

# Write the global summary table as an Iceberg table
global_summary.write.format("iceberg") \
    .mode("overwrite") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_global_summary/") \
    .saveAsTable(f"{database_name}.cve_production_global_summary")

print("Cumulative tables created successfully.")
