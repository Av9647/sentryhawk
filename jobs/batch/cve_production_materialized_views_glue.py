import sys
from pyspark.sql import SparkSession, functions as F
from pyspark.sql.functions import (
    when, to_date, col, count, sum as _sum, avg, regexp_extract, expr, lit
)
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

# Read production table (assumed to be updated via SCD Type 2; only current records)
production_df = spark.table(f"{database_name}.cve_production_master").filter("currentFlag = true")

# -----------------------------------------------------
# Step 1: Extract the Best CVSS Vector Based on Latest Version
# -----------------------------------------------------
# We use cvssVersion from the production table to filter the cvssData array.
# First, compute the maximum version among the cvssData entries.
production_df = production_df.withColumn("latest_version", expr(
    "array_max(transform(cvssData, x -> x.version))"
))

# Then, aggregate only those entries that have a matching version and non-null baseScore,
# picking the one with the highest baseScore.
production_df = production_df.withColumn("latest_entry", expr("""
aggregate(
  filter(cvssData, x -> x.version = latest_version and x.baseScore is not null),
  named_struct('bestScore', cast(0.0 as decimal(10,2)), 'bestVector', cast(null as string)),
  (acc, x) -> IF(x.baseScore > acc.bestScore,
                  named_struct('bestScore', cast(x.baseScore as decimal(10,2)), 'bestVector', x.vectorString),
                  acc)
)
"""))

# Split the struct into separate columns
production_df = production_df.withColumn("latest_baseScore", col("latest_entry.bestScore")) \
                               .withColumn("latest_vector", col("latest_entry.bestVector"))

# -----------------------------------------------------
# Step 2: Parse the Latest CVSS Vector Depending on Version
# -----------------------------------------------------
# For CVSS v3, the expected format is: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# For CVSS v2, the expected format is: "AV:N/AC:M/Au:N/C:P/I:P/A:P"
# We extract common fields for both formats (AV, AC, C, I, A)
production_df = production_df.withColumn("AV", regexp_extract(col("latest_vector"), "AV:([^/]+)", 1)) \
    .withColumn("AC", regexp_extract(col("latest_vector"), "AC:([^/]+)", 1)) \
    .withColumn("C",  regexp_extract(col("latest_vector"), "C:([^/]+)", 1)) \
    .withColumn("I",  regexp_extract(col("latest_vector"), "I:([^/]+)", 1)) \
    .withColumn("A",  regexp_extract(col("latest_vector"), "A:([^/]+)", 1))

# For CVSS v3, extract PR, UI, S; for CVSS v2, extract Au
production_df = production_df.withColumn("PR", when(col("cvssVersion") != "2.0",
                                                      regexp_extract(col("latest_vector"), "PR:([^/]+)", 1))
                                         .otherwise(lit(None))) \
    .withColumn("UI", when(col("cvssVersion") != "2.0",
                           regexp_extract(col("latest_vector"), "UI:([^/]+)", 1))
                .otherwise(lit(None))) \
    .withColumn("S", when(col("cvssVersion") != "2.0",
                          regexp_extract(col("latest_vector"), "S:([^/]+)", 1))
                .otherwise(lit(None))) \
    .withColumn("Au", when(col("cvssVersion") == "2.0",
                           regexp_extract(col("latest_vector"), "Au:([^/]+)", 1))
                .otherwise(lit(None)))

# -----------------------------------------------------
# Step 3: Define Risk Flags Using CVSS Components
# -----------------------------------------------------
# For CVSS v3, use PR, UI; for CVSS v2, use Au (treat Au = "N" as no authentication)
production_df = production_df.withColumn("is_network_based", when(col("AV") == "N", True).otherwise(False)) \
    .withColumn("is_no_ui", when(
        (col("cvssVersion") != "2.0") & (col("UI") == "N") |
        (col("cvssVersion") == "2.0") & (col("Au") == "N"),
        True).otherwise(False)) \
    .withColumn("is_low_priv", when(
        (col("cvssVersion") != "2.0") & (col("PR").isin("N", "L")),
        True).when(
        (col("cvssVersion") == "2.0") & (col("Au") == "N"),
        True).otherwise(False)) \
    .withColumn("is_scope_changed", when(col("cvssVersion") != "2.0", when(col("S") == "C", True).otherwise(False))
                .otherwise(lit(False))) \
    .withColumn("is_high_conf", when(col("C") == "H", True).otherwise(False)) \
    .withColumn("is_high_int", when(col("I") == "H", True).otherwise(False)) \
    .withColumn("is_high_avail", when(col("A") == "H", True).otherwise(False))
    
# Composite flag for fully critical vulnerability:
# For CVSS v3, require network, no UI, low privileges, scope change, and at least one high impact.
# For CVSS v2, since there's no separate UI/S, treat Au = "N" as covering low privilege and no user requirement.
production_df = production_df.withColumn("is_fully_critical",
    when(
        (col("is_network_based") == True) &
        (col("is_no_ui") == True) &
        (col("is_low_priv") == True) &
        ((col("cvssVersion") != "2.0") & (col("is_scope_changed") == True) |
         (col("cvssVersion") == "2.0")),  # for v2, we don't have scope info
        when((col("is_high_conf") == True) | (col("is_high_int") == True) | (col("is_high_avail") == True), True)
    ).otherwise(False)
)

# -----------------------------------------------------
# Step 4: Define Weighted Score Expression
# -----------------------------------------------------
weighted_score = when(col("severity") == "Critical", col("cvssScore") * 1.0) \
    .when(col("severity") == "High", col("cvssScore") * 0.75) \
    .when(col("severity") == "Medium", col("cvssScore") * 0.50) \
    .when(col("severity") == "Low", col("cvssScore") * 0.25) \
    .otherwise(0)

# -----------------------------------------------------
# Step 5: Build Specialized Cumulative (Materialized) Tables
# -----------------------------------------------------

# A. Cumulative Vendor Table
cumulative_vendor = (
    production_df
    .withColumn("datePublished", to_date(col("datePublished")))
    .groupBy("vendor", "datePublished")
    .agg(
        count("*").alias("total_cves"),
        F.round(_sum(weighted_score), 2).alias("threat_index"),
        F.round(avg(col("cvssScore")), 2).alias("avg_cvss"),
        _sum(when(col("severity") == "Critical", 1).otherwise(0)).alias("critical_count"),
        _sum(when(col("severity") == "High", 1).otherwise(0)).alias("high_count"),
        _sum(when(col("severity") == "Medium", 1).otherwise(0)).alias("medium_count"),
        _sum(when(col("severity") == "Low", 1).otherwise(0)).alias("low_count"),
        # Specialized metrics
        F.round(_sum(when(col("is_network_based"), weighted_score).otherwise(0))).alias("network_threat_index"),
        _sum(when(col("is_network_based"), 1).otherwise(0)).alias("network_cves"),
        _sum(when(col("is_no_ui"), 1).otherwise(0)).alias("no_ui_cves"),
        _sum(when(col("is_low_priv"), 1).otherwise(0)).alias("low_priv_cves"),
        _sum(when(col("is_fully_critical"), 1).otherwise(0)).alias("fully_critical_cves")
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

cumulative_vendor.write.format("iceberg") \
    .mode("overwrite") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_cumulative_vendor/") \
    .saveAsTable(f"{database_name}.cve_production_cumulative_vendor")

# B. Cumulative Product Table
cumulative_product = (
    production_df
    .withColumn("datePublished", to_date(col("datePublished")))
    .groupBy("vendor", "product", "datePublished")
    .agg(
        count("*").alias("total_cves"),
        F.round(_sum(weighted_score), 2).alias("threat_index"),
        F.round(avg(col("cvssScore")), 2).alias("avg_cvss"),
        _sum(when(col("severity") == "Critical", 1).otherwise(0)).alias("critical_count"),
        _sum(when(col("severity") == "High", 1).otherwise(0)).alias("high_count"),
        _sum(when(col("severity") == "Medium", 1).otherwise(0)).alias("medium_count"),
        _sum(when(col("severity") == "Low", 1).otherwise(0)).alias("low_count"),
        F.round(_sum(when(col("is_network_based"), weighted_score).otherwise(0))).alias("network_threat_index"),
        _sum(when(col("is_network_based"), 1).otherwise(0)).alias("network_cves"),
        _sum(when(col("is_no_ui"), 1).otherwise(0)).alias("no_ui_cves"),
        _sum(when(col("is_low_priv"), 1).otherwise(0)).alias("low_priv_cves"),
        _sum(when(col("is_fully_critical"), 1).otherwise(0)).alias("fully_critical_cves")
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

cumulative_product.write.format("iceberg") \
    .mode("overwrite") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_cumulative_product/") \
    .saveAsTable(f"{database_name}.cve_production_cumulative_product")

# C. Global Summary Table
global_summary = (
    production_df
    .withColumn("datePublished", to_date(col("datePublished")))
    .groupBy("datePublished")
    .agg(
        count("*").alias("total_cves"),
        F.round(_sum(weighted_score), 2).alias("threat_index"),
        F.round(avg(col("cvssScore")), 2).alias("avg_cvss"),
        _sum(when(col("severity") == "Critical", 1).otherwise(0)).alias("critical_count"),
        _sum(when(col("severity") == "High", 1).otherwise(0)).alias("high_count"),
        _sum(when(col("severity") == "Medium", 1).otherwise(0)).alias("medium_count"),
        _sum(when(col("severity") == "Low", 1).otherwise(0)).alias("low_count"),
        F.round(_sum(when(col("is_network_based"), weighted_score).otherwise(0))).alias("network_threat_index"),
        _sum(when(col("is_network_based"), 1).otherwise(0)).alias("network_cves"),
        _sum(when(col("is_no_ui"), 1).otherwise(0)).alias("no_ui_cves"),
        _sum(when(col("is_low_priv"), 1).otherwise(0)).alias("low_priv_cves"),
        _sum(when(col("is_fully_critical"), 1).otherwise(0)).alias("fully_critical_cves")
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

global_summary.write.format("iceberg") \
    .mode("overwrite") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_global_summary/") \
    .saveAsTable(f"{database_name}.cve_production_global_summary")

print("Specialized cumulative tables for in-depth CVE analysis created successfully.")
