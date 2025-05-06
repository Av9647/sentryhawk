import sys
from pyspark.sql import SparkSession, functions as F
from pyspark.sql.functions import (
    when, to_date, year, month, col, countDistinct, sumDistinct, expr, lit,
    row_number, regexp_extract
)
from pyspark.sql.window import Window
from awsglue.utils import getResolvedOptions
from awsglue.context import GlueContext
from pyspark.context import SparkContext

def round_col(col_expr, scale):
    return F.round(col_expr.cast("double"), scale)

# Helper function to compact timestamp strings
def compact_timestamp_str(col_expr):
    return F.concat(
        # First, apply the first regex to remove trailing zeroes when some nonzero digits exist
        F.regexp_replace(
            F.regexp_replace(col_expr.cast("string"), r'(\.\d*?[1-9])0+$', r'\1'),
            r'\.0+$', ''
        ),
        F.lit(" UTC")
    )

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

# Read production table (only current SCD2 records)
production_df = spark.table(f"{database_name}.cve_production_master").filter("currentFlag = true")

# ----------------------------------------------------------------------
# Creation of the Lookup Table "cve_production_lookup"
# ----------------------------------------------------------------------
lookup_df = production_df \
    .withColumn("year_published", year(col("datePublished"))) \
    .withColumn("chosenCvss", expr("""
      CASE 
        WHEN cvssData IS NULL OR size(cvssData) = 0 THEN 
          named_struct(
              'source', '', 
              'type', '', 
              'version', '', 
              'vectorString', '', 
              'baseScore', CAST(NULL AS DOUBLE), 
              'impactScore', CAST(NULL AS DOUBLE), 
              'exploitabilityScore', CAST(NULL AS DOUBLE)
          )
        ELSE aggregate(
          filter(coalesce(cvssData, array()), x -> x IS NOT NULL AND x.baseScore IS NOT NULL),
          cast(null as struct<source:string, type:string, version:string, vectorString:string, baseScore:double, impactScore:double, exploitabilityScore:double>),
          (acc, x) -> CASE WHEN acc IS NULL OR x.baseScore > acc.baseScore THEN x ELSE acc END,
          acc -> acc
        )
      END
    """)) \
    .withColumn("cvssScore", F.col("chosenCvss.baseScore").cast("double")) \
    .withColumn("cvssVersion", F.col("chosenCvss.version")) \
    .withColumn("severity", 
                F.when(F.col("chosenCvss.baseScore") >= 9.0, "Critical")
                 .when(F.col("chosenCvss.baseScore") >= 7.0, "High")
                 .when(F.col("chosenCvss.baseScore") >= 4.0, "Medium")
                 .when(F.col("chosenCvss.baseScore").isNotNull(), "Low")
                 .otherwise(lit(""))) \
    .withColumn("source", F.coalesce(F.col("chosenCvss.source"), F.lit(""))) \
    .withColumn("sourceType", F.coalesce(F.col("chosenCvss.type"), F.lit(""))) \
    .withColumn("vectorString", F.coalesce(F.col("chosenCvss.vectorString"), F.lit(""))) \
    .withColumn("impactScore", F.col("chosenCvss.impactScore").cast("double")) \
    .withColumn("exploitabilityScore", F.col("chosenCvss.exploitabilityScore").cast("double")) \
    .withColumn("cweData", expr("""
         array_join(
             transform(coalesce(cweData, array()), x -> 
                 CASE 
                   WHEN x.cweDescription IS NOT NULL AND trim(x.cweDescription) != '' 
                   THEN x.cweDescription 
                   ELSE x.cweId 
                 END),
             ', '
         )
    """)) \
    .withColumn("capecData", expr("""
         array_join(
             transform(coalesce(capecData, array()), x -> 
                 CASE 
                   WHEN x.capecDescription IS NOT NULL AND trim(x.capecDescription) != '' 
                   THEN x.capecDescription 
                   ELSE x.capecId 
                 END),
             ', '
         )
    """)) \
    .withColumn("cweData", F.coalesce(F.col("cweData"), F.lit(""))) \
    .withColumn("capecData", F.coalesce(F.col("capecData"), F.lit(""))) \
    .withColumn("cvssData", F.to_json(col("cvssData"))) \
    .withColumn("dateReserved", 
        F.when(F.col("dateReserved").isNotNull(), compact_timestamp_str(F.col("dateReserved")))
         .otherwise(lit(""))
    ) \
    .withColumn("dateUpdated", 
        F.when(F.col("dateUpdated").isNotNull(), compact_timestamp_str(F.col("dateUpdated")))
         .otherwise(lit(""))
    ) \
    .withColumn("datePublic", 
        F.when(F.col("datePublic").isNotNull(), compact_timestamp_str(F.col("datePublic")))
         .otherwise(lit(""))
    ) \
    .withColumn("lastModified", 
        F.when(F.col("lastModified").isNotNull(), compact_timestamp_str(F.col("lastModified")))
         .otherwise(lit(""))
    )

lookup_df = lookup_df.select(
    "datePublished", "vendor", "product", "cveId", "descriptions", "cvssScore", 
    "severity", "vectorString", "impactScore", "exploitabilityScore", "source",
    "sourceType", "cvssVersion", "vulnStatus", "cweData", "capecData", "cvssData", 
    "dateReserved", "dateUpdated", "datePublic", "lastModified", "year_published"
)

lookup_df.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("year_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_lookup/") \
    .saveAsTable(f"{database_name}.cve_production_lookup")

# -----------------------------------------------------
# Aggregated Materialized Views
# -----------------------------------------------------
# Step 1: Extract the Best CVSS Vector Based on Latest Version
production_df = production_df.withColumn("latest_version", expr(
    "array_max(transform(coalesce(cvssData, array()), x -> x.version))"
))
production_df = production_df.withColumn("chosenCvss", expr("""
  CASE 
    WHEN cvssData IS NULL OR size(cvssData) = 0 THEN 
      named_struct('source','', 'type','', 'version','', 'vectorString','', 'baseScore', CAST(NULL AS DOUBLE), 'impactScore', CAST(NULL AS DOUBLE), 'exploitabilityScore', CAST(NULL AS DOUBLE))
    ELSE aggregate(
      filter(coalesce(cvssData, array()), x -> x IS NOT NULL AND x.baseScore IS NOT NULL),
      cast(null as struct<source:string, type:string, version:string, vectorString:string, baseScore:double, impactScore:double, exploitabilityScore:double>),
      (acc, x) -> CASE WHEN acc IS NULL OR x.baseScore > acc.baseScore THEN x ELSE acc END,
      acc -> acc
    )
  END
"""))
production_df = production_df.withColumn("cvssScore", col("chosenCvss.baseScore")) \
                             .withColumn("cvssVersion", col("chosenCvss.version"))

# -----------------------------------------------------
# Step 2: Parse the Latest CVSS Vector Depending on Version
# -----------------------------------------------------
# NOTE: We replace references to latest_vector with chosenCvss.vectorString.
production_df = production_df.withColumn("AV", regexp_extract(col("chosenCvss.vectorString"), "AV:([^/]+)", 1)) \
    .withColumn("AC", regexp_extract(col("chosenCvss.vectorString"), "AC:([^/]+)", 1)) \
    .withColumn("C",  regexp_extract(col("chosenCvss.vectorString"), "C:([^/]+)", 1)) \
    .withColumn("I",  regexp_extract(col("chosenCvss.vectorString"), "I:([^/]+)", 1)) \
    .withColumn("A",  regexp_extract(col("chosenCvss.vectorString"), "A:([^/]+)", 1))
production_df = production_df.withColumn("PR", when(col("cvssVersion") != "2.0",
                                                      regexp_extract(col("chosenCvss.vectorString"), "PR:([^/]+)", 1))
                                         .otherwise(lit(""))) \
    .withColumn("UI", when(col("cvssVersion") != "2.0",
                           regexp_extract(col("chosenCvss.vectorString"), "UI:([^/]+)", 1))
                .otherwise(lit(""))) \
    .withColumn("S", when(col("cvssVersion") != "2.0",
                          regexp_extract(col("chosenCvss.vectorString"), "S:([^/]+)", 1))
                .otherwise(lit(""))) \
    .withColumn("Au", when(col("cvssVersion") == "2.0",
                           regexp_extract(col("chosenCvss.vectorString"), "Au:([^/]+)", 1))
                .otherwise(lit("")))

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
production_df = production_df.withColumn(
    "is_fully_critical",
    when(
        (col("is_network_based") == True) &
        (col("is_no_ui") == True) &
        (col("is_low_priv") == True) &
        (((col("cvssVersion") != "2.0") & (col("is_scope_changed") == True)) |
         (col("cvssVersion") == "2.0")),
        when(
            (col("is_high_conf") == True) | (col("is_high_int") == True) | (col("is_high_avail") == True),
            True
        )
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
# Step 5: Add Date Columns for Partitioning
# -----------------------------------------------------
production_df = production_df.withColumn("datePublished", to_date(col("datePublished")))
production_df = production_df.withColumn("year_published", year(col("datePublished")))
production_df = production_df.withColumn("month_published", month(col("datePublished")))

# -----------------------------------------------------
# Step 6: Column Expression Builders (Not UDFs)
# -----------------------------------------------------
def daily_global_risk_expr(ti):
    return (
        when(ti.isNull(), "Unknown")
        .when(ti > 40, "Severe")
        .when(ti > 20, "High")
        .when(ti > 10, "Moderate")
        .when(ti > 0,  "Low")
        .otherwise("No Risk")
    )

def daily_vendor_risk_expr(ti):
    return (
        when(ti.isNull(), "Unknown")
        .when(ti > 30, "Severe")
        .when(ti > 14, "High")
        .when(ti > 7,  "Moderate")
        .when(ti > 0,  "Low")
        .otherwise("No Risk")
    )

def daily_product_risk_expr(ti):
    return (
        when(ti.isNull(), "Unknown")
        .when(ti > 25, "Severe")
        .when(ti > 12, "High")
        .when(ti > 6,  "Moderate")
        .when(ti > 0,  "Low")
        .otherwise("No Risk")
    )

def monthly_global_risk_expr(ti):
    return (
        when(ti.isNull(), "Unknown")
        .when(ti > 120, "Severe")
        .when(ti > 80, "High")
        .when(ti > 50, "Moderate")
        .when(ti > 0, "Low")
        .otherwise("No Risk")
    )

def monthly_vendor_risk_expr(ti):
    return (
        when(ti.isNull(), "Unknown")
        .when(ti > 80, "Severe")
        .when(ti > 43, "High")
        .when(ti > 20, "Moderate")
        .when(ti > 0, "Low")
        .otherwise("No Risk")
    )

def monthly_product_risk_expr(ti):
    return (
        when(ti.isNull(), "Unknown")
        .when(ti > 25, "Severe")
        .when(ti > 14, "High")
        .when(ti > 7, "Moderate")
        .when(ti > 0, "Low")
        .otherwise("No Risk")
    )

def ytd_global_risk_expr(ti):
    return (
        when(ti.isNull(), "Unknown")
        .when(ti > 180, "Severe")
        .when(ti > 135, "High")
        .when(ti > 90, "Moderate")
        .when(ti > 0, "Low")
        .otherwise("No Risk")
    )

def ytd_vendor_risk_expr(ti):
    return (
        when(ti.isNull(), "Unknown")
        .when(ti > 105, "Severe")
        .when(ti > 60, "High")
        .when(ti > 15, "Moderate")
        .when(ti > 0, "Low")
        .otherwise("No Risk")
    )

def ytd_product_risk_expr(ti):
    return (
        when(ti.isNull(), "Unknown")
        .when(ti > 40, "Severe")
        .when(ti > 15, "High")
        .when(ti > 7, "Moderate")
        .when(ti > 0, "Low")
        .otherwise("No Risk")
    )

# -----------------------------------------------------
# Step 7: Daily Aggregations
# -----------------------------------------------------
# A. Daily Global
daily_global = (
    production_df
    .groupBy("datePublished", "year_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
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
    .withColumn("risk_rating", daily_global_risk_expr(col("threat_index")))
)
daily_global.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("year_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_daily_global/") \
    .saveAsTable(f"{database_name}.cve_production_daily_global")

# B. Daily Vendor
daily_vendor = (
    production_df
    .groupBy("vendor", "datePublished", "year_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
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
    .withColumn("risk_rating", daily_vendor_risk_expr(col("threat_index")))
)
daily_vendor.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("vendor") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_daily_vendor/") \
    .saveAsTable(f"{database_name}.cve_production_daily_vendor")

# C. Daily Product
daily_product = (
    production_df
    .groupBy("vendor", "product", "datePublished", "year_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
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
    .withColumn("risk_rating", daily_product_risk_expr(col("threat_index")))
)
daily_product.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("vendor", "product") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_daily_product/") \
    .saveAsTable(f"{database_name}.cve_production_daily_product")

# -----------------------------------------------------
# Step 7a: Deduplication of Daily Aggregations
# -----------------------------------------------------
w_global_dedupe = Window.partitionBy("datePublished").orderBy(F.desc("year_published"))
daily_global_single = (
    daily_global.withColumn("row_num", row_number().over(w_global_dedupe))
    .filter("row_num = 1")
    .drop("row_num")
)

w_vendor_dedupe = Window.partitionBy("vendor", "datePublished").orderBy(F.desc("year_published"))
daily_vendor_single = (
    daily_vendor.withColumn("row_num", row_number().over(w_vendor_dedupe))
    .filter("row_num = 1")
    .drop("row_num")
)

w_product_dedupe = Window.partitionBy("vendor", "product", "datePublished").orderBy(F.desc("year_published"))
daily_product_single = (
    daily_product.withColumn("row_num", row_number().over(w_product_dedupe))
    .filter("row_num = 1")
    .drop("row_num")
)

# -----------------------------------------------------
# Step 8: Monthly & YTD Aggregations
# -----------------------------------------------------
# A. Monthly Global
monthly_global = (
    production_df
    .groupBy("year_published", "month_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
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
    .withColumn("risk_rating", monthly_global_risk_expr(col("threat_index")))
    .withColumn("month_date", F.to_date(F.expr("make_date(year_published, month_published, 1)")))
)
monthly_global.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("year_published", "month_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_monthly_global/") \
    .saveAsTable(f"{database_name}.cve_production_monthly_global")

# B. Monthly Vendor
monthly_vendor = (
    production_df
    .groupBy("vendor", "year_published", "month_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
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
    .withColumn("risk_rating", monthly_vendor_risk_expr(col("threat_index")))
    .withColumn("month_date", F.to_date(F.expr("make_date(year_published, month_published, 1)")))
)
monthly_vendor.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("year_published", "month_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_monthly_vendor/") \
    .saveAsTable(f"{database_name}.cve_production_monthly_vendor")

# C. Monthly Product
monthly_product = (
    production_df
    .groupBy("vendor", "product", "year_published", "month_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
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
    .withColumn("risk_rating", monthly_product_risk_expr(col("threat_index")))
    .withColumn("month_date", F.to_date(F.expr("make_date(year_published, month_published, 1)")))
)
monthly_product.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("year_published", "month_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_monthly_product/") \
    .saveAsTable(f"{database_name}.cve_production_monthly_product")

# D. YTD Global
ytd_global = (
    production_df
    .groupBy("year_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
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
    .withColumn("risk_rating", ytd_global_risk_expr(col("threat_index")))
    .withColumn("year_date", F.to_date(F.expr("make_date(year_published, 1, 1)")))
)
ytd_global.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("year_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_ytd_global/") \
    .saveAsTable(f"{database_name}.cve_production_ytd_global")

# E. YTD Vendor
ytd_vendor = (
    production_df
    .groupBy("vendor", "year_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
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
    .withColumn("risk_rating", ytd_vendor_risk_expr(col("threat_index")))
    .withColumn("year_date", F.to_date(F.expr("make_date(year_published, 1, 1)")))
)
ytd_vendor.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("year_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_ytd_vendor/") \
    .saveAsTable(f"{database_name}.cve_production_ytd_vendor")

# F. YTD Product
ytd_product = (
    production_df
    .groupBy("vendor", "product", "year_published")
    .agg(
        countDistinct("cveId").alias("total_cves"),
        round_col(sumDistinct(weighted_score), 2).alias("threat_index"),
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
    .withColumn("risk_rating", ytd_product_risk_expr(col("threat_index")))
    .withColumn("year_date", F.to_date(F.expr("make_date(year_published, 1, 1)")))
)
ytd_product.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("year_published") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_ytd_product/") \
    .saveAsTable(f"{database_name}.cve_production_ytd_product")

# -----------------------------------------------------
# Step 9: Running Total (Cumulative) Views on Deduplicated Daily Aggregates
# -----------------------------------------------------
# A. Global Running Total
window_global = Window.orderBy("datePublished") \
    .rowsBetween(Window.unboundedPreceding, Window.currentRow)
daily_global_running = (
    daily_global_single
    .withColumn("cumulative_threat_index", round_col(F.sum("threat_index").over(window_global), 2))
    .withColumn("running_risk_rating", ytd_global_risk_expr(col("cumulative_threat_index")))
)
daily_global_running.write.format("iceberg") \
    .mode("overwrite") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_daily_global_running/") \
    .saveAsTable(f"{database_name}.cve_production_daily_global_running")

# B. Vendor Running Total
window_vendor = Window.partitionBy("vendor") \
    .orderBy("datePublished") \
    .rowsBetween(Window.unboundedPreceding, Window.currentRow)
daily_vendor_running = (
    daily_vendor_single
    .withColumn("cumulative_threat_index", round_col(F.sum("threat_index").over(window_vendor), 2))
    .withColumn("running_risk_rating", ytd_vendor_risk_expr(col("cumulative_threat_index")))
)
daily_vendor_running.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("vendor") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_daily_vendor_running/") \
    .saveAsTable(f"{database_name}.cve_production_daily_vendor_running")

# C. Product Running Total
window_product = Window.partitionBy("vendor", "product") \
    .orderBy("datePublished") \
    .rowsBetween(Window.unboundedPreceding, Window.currentRow)
daily_product_running = (
    daily_product_single
    .withColumn("cumulative_threat_index", round_col(F.sum("threat_index").over(window_product), 2))
    .withColumn("running_risk_rating", ytd_product_risk_expr(col("cumulative_threat_index")))
)
daily_product_running.write.format("iceberg") \
    .mode("overwrite") \
    .partitionBy("vendor", "product") \
    .option("path", "s3://cve-production/cve_production_tables/cve_production_daily_product_running/") \
    .saveAsTable(f"{database_name}.cve_production_daily_product_running")

print("All materialized views and lookup table created successfully.")
