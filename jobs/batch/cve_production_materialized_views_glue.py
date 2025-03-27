import sys
from pyspark.sql import SparkSession, functions as F
from pyspark.sql.functions import (
    when, to_date, year, col, countDistinct, sumDistinct, avg, regexp_extract, expr, lit, round as round_col
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

# Read production table (only current records)
production_df = spark.table(f"{database_name}.cve_production_master").filter("currentFlag = true")

# -----------------------------------------------------
# Step 1: Extract the Best CVSS Vector Based on Latest Version
# -----------------------------------------------------
production_df = production_df.withColumn("latest_version", expr(
    "array_max(transform(cvssData, x -> x.version))"
))

production_df = production_df.withColumn("latest_entry", expr("""
aggregate(
  filter(cvssData, x -> x.version = latest_version and x.baseScore is not null),
  named_struct('bestScore', cast(0.0 as decimal(10,2)), 'bestVector', cast(null as string)),
  (acc, x) -> IF(x.baseScore > acc.bestScore,
                  named_struct('bestScore', cast(x.baseScore as decimal(10,2)), 'bestVector', x.vectorString),
                  acc)
)
"""))

production_df = production_df.withColumn("latest_baseScore", col("latest_entry.bestScore")) \
                             .withColumn("latest_vector", col("latest_entry.bestVector"))

# -----------------------------------------------------
# Step 2: Parse the Latest CVSS Vector Depending on Version
# -----------------------------------------------------
production_df = production_df.withColumn("AV", regexp_extract(col("latest_vector"), "AV:([^/]+)", 1)) \
    .withColumn("AC", regexp_extract(col("latest_vector"), "AC:([^/]+)", 1)) \
    .withColumn("C",  regexp_extract(col("latest_vector"), "C:([^/]+)", 1)) \
    .withColumn("I",  regexp_extract(col("latest_vector"), "I:([^/]+)", 1)) \
    .withColumn("A",  regexp_extract(col("latest_vector"), "A:([^/]+)", 1))

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
production_df = production_df.withColumn("is_network_based", when(col("AV") == "N", True).otherwise(False)) \
    .withColumn("is_no_ui", when(
        ((col("cvssVersion") != "2.0") & (col("UI") == "N")) |
        ((col("cvssVersion") == "2.0") & (col("Au") == "N")),
        True).otherwise(False)) \
    .withColumn("is_low_priv", when(
        ((col("cvssVersion") != "2.0") & (col("PR").isin("N", "L"))),
        True).when(
        ((col("cvssVersion") == "2.0") & (col("Au") == "N")),
        True).otherwise(False)) \
    .withColumn("is_scope_changed", when(col("cvssVersion") != "2.0", when(col("S") == "C", True).otherwise(False))
                .otherwise(lit(False))) \
    .withColumn("is_high_conf", when(col("C") == "H", True).otherwise(False)) \
    .withColumn("is_high_int", when(col("I") == "H", True).otherwise(False)) \
    .withColumn("is_high_avail", when(col("A") == "H", True).otherwise(False))
    
production_df = production_df.withColumn("is_fully_critical",
    when(
        (col("is_network_based") == True) &
        (col("is_no_ui") == True) &
        (col("is_low_priv") == True) &
        (((col("cvssVersion") != "2.0") & (col("is_scope_changed") == True)) |
         (col("cvssVersion") == "2.0")),
        when((col("is_high_conf") == True) | (col("is_high_int") == True) | (col("is_high_avail") == True), True)
    ).otherwise(False)
)

# -----------------------------------------------------
# Step 4: Weighted Score Expression
# -----------------------------------------------------
weighted_score = when(col("severity") == "Critical", col("cvssScore") * 1.0) \
    .when(col("severity") == "High", col("cvssScore") * 0.75) \
    .when(col("severity") == "Medium", col("cvssScore") * 0.50) \
    .when(col("severity") == "Low", col("cvssScore") * 0.25) \
    .otherwise(0)

# -----------------------------------------------------
# Step 5: Add Year Column for Partitioning
# -----------------------------------------------------
production_df = production_df.withColumn("datePublished", to_date(col("datePublished")))
production_df = production_df.withColumn("year_published", year(col("datePublished")))

# -----------------------------------------------------
# Step 6: Build Specialized Cumulative (Materialized) Tables with Distinct CVE Counts
# -----------------------------------------------------

# A. Cumulative Vendor Table
cumulative_vendor = (
    production_df
    # Keep daily grouping, but also group by year_published for completeness
    .groupBy("vendor", "datePublished", "year_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
        round_col(avg(col("cvssScore")), 2).alias("avg_cvss"),
        countDistinct(when(col("severity") == "Critical", col("cveId"))).alias("critical_count"),
        countDistinct(when(col("severity") == "High", col("cveId"))).alias("high_count"),
        countDistinct(when(col("severity") == "Medium", col("cveId"))).alias("medium_count"),
        countDistinct(when(col("severity") == "Low", col("cveId"))).alias("low_count"),
        round_col(sumDistinct(when(col("is_network_based"), weighted_score)), 2).alias("network_threat_index"),
        countDistinct(when(col("is_network_based"), col("cveId"))).alias("network_cves"),
        countDistinct(when(col("is_no_ui"), col("cveId"))).alias("no_ui_cves"),
        countDistinct(when(col("is_low_priv"), col("cveId"))).alias("low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), col("cveId"))).alias("fully_critical_cves")
    )
    .withColumn("avg_threat_per_cve", round_col(col("threat_index") / col("total_cves"), 2))
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
    .partitionBy("year_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_cumulative_vendor/") \
    .saveAsTable(f"{database_name}.cve_production_cumulative_vendor")

# B. Cumulative Product Table
cumulative_product = (
    production_df
    .groupBy("vendor", "product", "datePublished", "year_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
        round_col(avg(col("cvssScore")), 2).alias("avg_cvss"),
        countDistinct(when(col("severity") == "Critical", col("cveId"))).alias("critical_count"),
        countDistinct(when(col("severity") == "High", col("cveId"))).alias("high_count"),
        countDistinct(when(col("severity") == "Medium", col("cveId"))).alias("medium_count"),
        countDistinct(when(col("severity") == "Low", col("cveId"))).alias("low_count"),
        round_col(sumDistinct(when(col("is_network_based"), weighted_score)), 2).alias("network_threat_index"),
        countDistinct(when(col("is_network_based"), col("cveId"))).alias("network_cves"),
        countDistinct(when(col("is_no_ui"), col("cveId"))).alias("no_ui_cves"),
        countDistinct(when(col("is_low_priv"), col("cveId"))).alias("low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), col("cveId"))).alias("fully_critical_cves")
    )
    .withColumn("avg_threat_per_cve", round_col(col("threat_index") / col("total_cves"), 2))
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
    .partitionBy("year_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_cumulative_product/") \
    .saveAsTable(f"{database_name}.cve_production_cumulative_product")

# C. Global Summary Table
global_summary = (
    production_df
    .groupBy("datePublished", "year_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
        round_col(avg(col("cvssScore")), 2).alias("avg_cvss"),
        countDistinct(when(col("severity") == "Critical", col("cveId"))).alias("critical_count"),
        countDistinct(when(col("severity") == "High", col("cveId"))).alias("high_count"),
        countDistinct(when(col("severity") == "Medium", col("cveId"))).alias("medium_count"),
        countDistinct(when(col("severity") == "Low", col("cveId"))).alias("low_count"),
        round_col(sumDistinct(when(col("is_network_based"), weighted_score)), 2).alias("network_threat_index"),
        countDistinct(when(col("is_network_based"), col("cveId"))).alias("network_cves"),
        countDistinct(when(col("is_no_ui"), col("cveId"))).alias("no_ui_cves"),
        countDistinct(when(col("is_low_priv"), col("cveId"))).alias("low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), col("cveId"))).alias("fully_critical_cves")
    )
    .withColumn("avg_threat_per_cve", round_col(col("threat_index") / col("total_cves"), 2))
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
    .partitionBy("year_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_global_summary/") \
    .saveAsTable(f"{database_name}.cve_production_global_summary")

print("Specialized cumulative tables for in-depth CVE analysis (distinct CVEs, partitioned by year) created successfully.")
