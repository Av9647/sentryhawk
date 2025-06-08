import argparse
import math
from datetime import datetime, timezone
from functools import reduce

from pyspark.sql import SparkSession, functions as F
from pyspark.sql.functions import (
    when, to_date, to_timestamp, year, month, current_date, col, countDistinct, sum as spark_sum, 
    add_months, expr, lit, concat, regexp_replace, trim, regexp_extract, row_number
)
from pyspark.sql.window import Window

# Configuration
DATABASE = "cve_db"
NUM_OUT = 24

spark = (
    SparkSession.builder
        .appName("cve_pipeline")
        # Iceberg & Glue
        .config("spark.sql.catalog.spark_catalog", "org.apache.iceberg.spark.SparkCatalog")
        .config("spark.sql.catalog.spark_catalog.catalog-impl", "org.apache.iceberg.aws.glue.GlueCatalog")
        .config("spark.sql.catalog.spark_catalog.warehouse", "s3://cve-production/")
        .config("spark.sql.extensions", "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")
        .config("spark.sql.iceberg.handle-timestamp-without-timezone", "true")
        # Performance & logging
        .config("spark.eventLog.enabled", "false")
        .config("spark.sql.shuffle.partitions", str(NUM_OUT))
        .config("spark.default.parallelism", str(NUM_OUT))
        .config("spark.sql.adaptive.enabled", "true")
        .config("spark.sql.adaptive.shuffle.targetPostShuffleInputSize", "64MB")
        .config("spark.dynamicAllocation.enabled", "false")
        .config("spark.shuffle.service.enabled", "true")
        .config("spark.driver.maxResultSize", "4g")
        .config("spark.executor.instances", "4")
        .config("spark.executor.cores", "3")
        .config("spark.executor.memory", "23g")
        .config("spark.executor.memoryOverhead", "1g")
        .config("spark.network.timeout", "600s")
        .config("spark.executor.heartbeatInterval", "60s")
        .enableHiveSupport()
        .getOrCreate()
)

# Meta-table & last-run
spark.sql(f"""
  CREATE TABLE IF NOT EXISTS {DATABASE}.cve_production_mv_meta (
    pipeline_name STRING,
    last_run_ts   TIMESTAMP
  ) USING iceberg
  LOCATION 's3://cve-production/cve_production_tables/cve_production_mv_meta/'
""")

# Parse command-line args
parser = argparse.ArgumentParser(prog="cve_pipeline")
parser.add_argument(
    "--run_type",
    choices=["backfill", "incremental"],
    default="backfill",
    help="Mode: full backfill or incremental"
)
args = parser.parse_known_args()[0]
RUN_TYPE = args.run_type

# Utility functions
round_col = lambda c, s: F.round(c.cast("double"), s)

def compact_ts(col_ts):
    s = col_ts.cast("string")
    return F.concat(
        regexp_replace(regexp_replace(s, r'(\.\d*?[1-9])0+$', r'\1'), r'\.0+$', ''),
        lit(" UTC")
    )

def clean_name(c):
    return F.initcap(trim(regexp_replace(regexp_replace(c, r"\\",""), "_"," ")))

def transform_for_lookup(df):
    return (
        df.withColumn("chosenCvss", expr("""
            CASE
              WHEN cvssData IS NULL OR size(cvssData)=0 THEN named_struct(
                'source','', 'type','', 'version','', 'vectorString','',
                'baseScore',CAST(NULL AS DOUBLE),
                'impactScore',CAST(NULL AS DOUBLE),
                'exploitabilityScore',CAST(NULL AS DOUBLE)
              )
              ELSE aggregate(
                filter(coalesce(cvssData, array()), x -> x IS NOT NULL AND x.baseScore IS NOT NULL),
                cast(null as struct<
                  source:string, type:string, version:string,
                  vectorString:string, baseScore:double,
                  impactScore:double, exploitabilityScore:double>),
                (acc,x) -> CASE WHEN acc IS NULL OR x.baseScore>acc.baseScore THEN x ELSE acc END,
                acc -> acc
              )
            END
        """))
        .withColumn("cvssScore", col("chosenCvss.baseScore").cast("double"))
        .withColumn("cvssVersion", col("chosenCvss.version"))
        .withColumn("severity",
            when(col("cvssScore")>=9.0,"Critical")
           .when(col("cvssScore")>=7.0,"High")
           .when(col("cvssScore")>=4.0,"Medium")
           .when(col("cvssScore").isNotNull(),"Low")
           .otherwise(lit(""))
        )
        .withColumn("source",       F.coalesce(col("chosenCvss.source"),       lit("")))
        .withColumn("sourceType",   F.coalesce(col("chosenCvss.type"),         lit("")))
        .withColumn("vectorString", F.coalesce(col("chosenCvss.vectorString"), lit("")))
        .withColumn("impactScore",  col("chosenCvss.impactScore").cast("double"))
        .withColumn("exploitabilityScore", col("chosenCvss.exploitabilityScore").cast("double"))
        .withColumn("cweData", expr("""
            array_join(transform(coalesce(cweData,array()), x ->
              CASE WHEN x.cweDescription IS NOT NULL AND trim(x.cweDescription)!=''
                   THEN x.cweDescription ELSE x.cweId END
            ), ', ')
        """))
        .withColumn("capecData", expr("""
            array_join(transform(coalesce(capecData,array()), x ->
              CASE WHEN x.capecDescription IS NOT NULL AND trim(x.capecDescription)!=''
                   THEN x.capecDescription ELSE x.capecId END
            ), ', ')
        """))
        .withColumn("cvssData", F.to_json(col("cvssData")))
        .withColumn("dateReserved", when(col("dateReserved").isNotNull(), compact_ts(col("dateReserved"))).otherwise(lit("")))
        .withColumn("dateUpdated",  when(col("dateUpdated") .isNotNull(), compact_ts(col("dateUpdated")) ).otherwise(lit("")))
        .withColumn("datePublic",   when(col("datePublic")  .isNotNull(), compact_ts(col("datePublic"))  ).otherwise(lit("")))
        .withColumn("lastModified", when(col("lastModified").isNotNull(), compact_ts(col("lastModified"))).otherwise(lit("")))
        .withColumn("vendor",  clean_name(col("vendor")))
        .withColumn("product", clean_name(col("product")))
    )

def enrich_with_risk_flags(df):
    v = col("vectorString")
    return (
        df
        .withColumn("AV",  regexp_extract(v, r"AV:([^/]+)",1))
        .withColumn("AC",  regexp_extract(v, r"AC:([^/]+)",1))
        .withColumn("C",   regexp_extract(v, r"C:([^/]+)",1))
        .withColumn("I",   regexp_extract(v, r"I:([^/]+)",1))
        .withColumn("A",   regexp_extract(v, r"A:([^/]+)",1))
        .withColumn("PR",  when(col("cvssVersion")!="2.0", regexp_extract(v, r"PR:([^/]+)",1)).otherwise(lit("")))
        .withColumn("UI",  when(col("cvssVersion")!="2.0", regexp_extract(v, r"UI:([^/]+)",1)).otherwise(lit("")))
        .withColumn("S",   when(col("cvssVersion")!="2.0", regexp_extract(v, r"S:([^/]+)",1)).otherwise(lit("")))
        .withColumn("Au",  when(col("cvssVersion")=="2.0", regexp_extract(v, r"Au:([^/]+)",1)).otherwise(lit("")))
        .withColumn("is_network_based", when(col("AV")=="N", True).otherwise(False))
        .withColumn("is_no_ui", when(
              ((col("cvssVersion")!="2.0") & (col("UI")=="N")) |
              ((col("cvssVersion")=="2.0")  & (col("Au")=="N")), True
        ).otherwise(False))
        .withColumn("is_low_priv", when(
              ((col("cvssVersion")!="2.0") & col("PR").isin("L","N")) |
              ((col("cvssVersion")=="2.0") & (col("Au")=="N")), True
        ).otherwise(False))
        .withColumn("is_scope_changed", when((col("cvssVersion")!="2.0") & (col("S")=="C"), True).otherwise(False))
        .withColumn("is_high_conf", when(col("C")=="H", True).otherwise(False))
        .withColumn("is_high_int",  when(col("I")=="H", True).otherwise(False))
        .withColumn("is_high_avail",when(col("A")=="H", True).otherwise(False))
        .withColumn("is_fully_critical", when(
            col("is_network_based") & col("is_no_ui") & col("is_low_priv") &
            ((col("cvssVersion")!="2.0") & col("is_scope_changed") | (col("cvssVersion")=="2.0")) &
            (col("is_high_conf") | col("is_high_int") | col("is_high_avail")),
            True
        ).otherwise(False))
    )

# Weighted scoring
weighted = (
    when(col("severity")=="Critical", col("cvssScore")*1.0)
   .when(col("severity")=="High",     col("cvssScore")*0.75)
   .when(col("severity")=="Medium",   col("cvssScore")*0.50)
   .when(col("severity")=="Low",      col("cvssScore")*0.25)
   .otherwise(0)
)

# Common aggregation definitions
def common_aggs_product(wc="weighted_score"):
    return [
        F.coalesce(round_col(spark_sum(col(wc)),  2), lit(0.0)).alias("exposure_index"),
        F.coalesce(round_col(spark_sum(when(col("is_network_based"), col(wc))),2), lit(0.0)).alias("network_exposure_index"),
        countDistinct("cveId").alias("distinct_cves"),
        countDistinct(when(col("severity")=="Critical", col("cveId"))).alias("distinct_critical_count"),
        countDistinct(when(col("severity")=="High",     col("cveId"))).alias("distinct_high_count"),
        countDistinct(when(col("severity")=="Medium",   col("cveId"))).alias("distinct_medium_count"),
        countDistinct(when(col("severity")=="Low",      col("cveId"))).alias("distinct_low_count"),
        countDistinct(when(col("is_network_based"), col("cveId"))).alias("distinct_network_cves"),
        countDistinct(when(col("is_no_ui"),          col("cveId"))).alias("distinct_no_ui_cves"),
        countDistinct(when(col("is_low_priv"),       col("cveId"))).alias("distinct_low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), col("cveId"))).alias("distinct_fully_critical_cves")
    ]

def common_aggs_vendor(wc="weighted_score"):
    key = concat(col("cveId"), lit("|"), col("product"))
    return [
        F.coalesce(round_col(spark_sum(col(wc)), 2), lit(0.0)).alias("exposure_index"),
        F.coalesce(round_col(spark_sum(when(col("is_network_based"), col(wc))),2), lit(0.0)).alias("network_exposure_index"),
        countDistinct(col("product")).alias("affected_products"),
        countDistinct(key).alias("total_cves"),
        countDistinct(when(col("severity") == "Critical", key)).alias("critical_count"),
        countDistinct(when(col("severity") == "High",     key)).alias("high_count"),
        countDistinct(when(col("severity") == "Medium",   key)).alias("medium_count"),
        countDistinct(when(col("severity") == "Low",      key)).alias("low_count"),
        countDistinct("cveId").alias("distinct_cves"),
        countDistinct(when(col("severity") == "Critical", col("cveId"))).alias("distinct_critical_count"),
        countDistinct(when(col("severity") == "High",     col("cveId"))).alias("distinct_high_count"),
        countDistinct(when(col("severity") == "Medium",   col("cveId"))).alias("distinct_medium_count"),
        countDistinct(when(col("severity") == "Low",      col("cveId"))).alias("distinct_low_count"),
        countDistinct(when(col("is_network_based"),  key)).alias("network_cves"),
        countDistinct(when(col("is_no_ui"),          key)).alias("no_ui_cves"),
        countDistinct(when(col("is_low_priv"),       key)).alias("low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), key)).alias("fully_critical_cves"),
        countDistinct(when(col("is_network_based"), col("cveId"))).alias("distinct_network_cves"),
        countDistinct(when(col("is_no_ui"),          col("cveId"))).alias("distinct_no_ui_cves"),
        countDistinct(when(col("is_low_priv"),       col("cveId"))).alias("distinct_low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), col("cveId"))).alias("distinct_fully_critical_cves")
    ]

def common_aggs_global(wc="weighted_score"):
    key = concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product"))
    return [
        F.coalesce(round_col(spark_sum(col(wc)), 2), lit(0.0)).alias("exposure_index"),
        F.coalesce(round_col(spark_sum(when(col("is_network_based"), col(wc))),2), lit(0.0)).alias("network_exposure_index"),
        countDistinct(col("vendor")).alias("affected_vendors"),
        countDistinct(col("product")).alias("affected_products"),
        countDistinct(key).alias("total_cves"),
        countDistinct(when(col("severity") == "Critical", key)).alias("critical_count"),
        countDistinct(when(col("severity") == "High",     key)).alias("high_count"),
        countDistinct(when(col("severity") == "Medium",   key)).alias("medium_count"),
        countDistinct(when(col("severity") == "Low",      key)).alias("low_count"),
        countDistinct("cveId").alias("distinct_cves"),
        countDistinct(when(col("severity") == "Critical", col("cveId"))).alias("distinct_critical_count"),
        countDistinct(when(col("severity") == "High",     col("cveId"))).alias("distinct_high_count"),
        countDistinct(when(col("severity") == "Medium",   col("cveId"))).alias("distinct_medium_count"),
        countDistinct(when(col("severity") == "Low",      col("cveId"))).alias("distinct_low_count"),
        countDistinct(when(col("is_network_based"),  key)).alias("network_cves"),
        countDistinct(when(col("is_no_ui"),          key)).alias("no_ui_cves"),
        countDistinct(when(col("is_low_priv"),       key)).alias("low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), key)).alias("fully_critical_cves"),
        countDistinct(when(col("is_network_based"), col("cveId"))).alias("distinct_network_cves"),
        countDistinct(when(col("is_no_ui"),          col("cveId"))).alias("distinct_no_ui_cves"),
        countDistinct(when(col("is_low_priv"),       col("cveId"))).alias("distinct_low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), col("cveId"))).alias("distinct_fully_critical_cves")
    ]

# Write helper
def write_iceberg(df, suffix, path, partitions, mode="overwrite", dynamic=False):
    writer = df.write.format("iceberg").mode(mode)
    if dynamic:
        writer = writer.option("overwrite-mode","dynamic")
    writer.partitionBy(*partitions).option("path", path).saveAsTable(f"{DATABASE}.{suffix}")
    print(f"[DEBUG] wrote {suffix}")

# Capture one uniform run_ts for all threshold rows & meta watermark
run_ts = datetime.now(timezone.utc)

if RUN_TYPE == "backfill":
    # Build raw master lookup and dedupe
    base = (
        spark.table(f"{DATABASE}.cve_production_master")
             .filter("currentFlag = true")
             .withColumn("year_published", year(col("datePublished")))
             .withColumn("date_published", to_date(col("datePublished")))
             .repartition(NUM_OUT, "year_published", "date_published")
             .cache()
    )
    print(f"[DEBUG] base cached: {base.count()} rows")

    raw_lookup = (
        transform_for_lookup(base)
        .transform(lambda df: enrich_with_risk_flags(df))
        .select(
            "datePublished","vendor","product","cveId","descriptions","cvssScore","severity",
            "vectorString","impactScore","exploitabilityScore","source","sourceType","cvssVersion",
            "vulnStatus","cweData","capecData","cvssData","dateReserved","dateUpdated",
            "datePublic","lastModified","year_published","date_published"
        )
    )
    
    # Deduplicate only true duplicates
    group_cols = ["vendor","product","cveId"]

    # count non-null fields per row
    meta_cols = [c for c in raw_lookup.columns if c not in group_cols]
    completeness_expr = reduce(
        lambda a, b: a + b,
        [ when(col(c).isNotNull(), 1).otherwise(0) for c in meta_cols ]
    )
    scored = raw_lookup.withColumn("completeness", completeness_expr)

    # find keys with >1 rows
    dup_keys = (
        scored
        .groupBy(*group_cols)
        .count()
        .filter("count > 1")
        .select(*group_cols)
    )

    # split into duplicates vs uniques
    dup_rows = scored.join(dup_keys, group_cols, "inner")
    non_dup  = scored.join(dup_keys, group_cols, "left_anti").drop("completeness")

    # pick the single "most complete" row per duplicate key
    w = Window.partitionBy(*group_cols).orderBy(col("completeness").desc())
    deduped_dups = (
        dup_rows
          .withColumn("rn", row_number().over(w))
          .filter(col("rn") == 1)
          .drop("rn","completeness")
    )

    # final lookup table
    lookup_df = non_dup.unionByName(deduped_dups).repartition(NUM_OUT, "year_published")

    write_iceberg(
        lookup_df,
        "cve_production_lookup",
        "s3://cve-production/cve_production_tables/cve_production_lookup/",
        ["year_published","date_published"]
    )

    # Persist enriched (risk flags + score) once
    enriched = (
        lookup_df
        .transform(enrich_with_risk_flags)
        .withColumn("weighted_score", weighted)
        .cache()
    )

    # 1) DAILY
    df_daily_global = (
        enriched
          .groupBy("year_published", "datePublished")
          .agg(*common_aggs_global("weighted_score"))
          .withColumn("date_published", to_date(col("datePublished")))
    )
    write_iceberg(
        df_daily_global, "cve_production_daily_global",
        "s3://cve-production/cve_production_tables/cve_production_daily_global/",
        ["year_published","date_published"]
    )

    df_daily_vendor = (
        enriched
          .groupBy("vendor","year_published","datePublished")
          .agg(*common_aggs_vendor("weighted_score"))
          .withColumn("date_published", to_date(col("datePublished")))
    )
    write_iceberg(
        df_daily_vendor, "cve_production_daily_vendor",
        "s3://cve-production/cve_production_tables/cve_production_daily_vendor/",
        ["year_published","date_published"]
    )

    df_daily_product = (
        enriched
          .groupBy("vendor","product","year_published","datePublished")
          .agg(*common_aggs_product("weighted_score"))
          .withColumn("date_published", to_date(col("datePublished")))
    )
    write_iceberg(
        df_daily_product, "cve_production_daily_product",
        "s3://cve-production/cve_production_tables/cve_production_daily_product/",
        ["year_published","date_published"]
    )

    # 2) MONTHLY
    monthly = enriched.withColumn("month_published", month(col("datePublished")))

    df_monthly_global = (
        monthly
          .groupBy("year_published","month_published")
          .agg(*common_aggs_global("weighted_score"))
          .withColumn("month_date", to_date(expr("make_date(year_published,month_published,1)")))
    )
    write_iceberg(
        df_monthly_global, "cve_production_monthly_global",
        "s3://cve-production/cve_production_tables/cve_production_monthly_global/",
        ["year_published","month_published"]
    )

    df_monthly_vendor = (
        monthly
          .groupBy("vendor","year_published","month_published")
          .agg(*common_aggs_vendor("weighted_score"))
          .withColumn("month_date", to_date(expr("make_date(year_published,month_published,1)")))
    )
    write_iceberg(
        df_monthly_vendor, "cve_production_monthly_vendor",
        "s3://cve-production/cve_production_tables/cve_production_monthly_vendor/",
        ["year_published","month_published"]
    )

    df_monthly_product = (
        monthly
          .groupBy("vendor","product","year_published","month_published")
          .agg(*common_aggs_product("weighted_score"))
          .withColumn("month_date", to_date(expr("make_date(year_published,month_published,1)")))
    )
    write_iceberg(
        df_monthly_product, "cve_production_monthly_product",
        "s3://cve-production/cve_production_tables/cve_production_monthly_product/",
        ["year_published","month_published"]
    )

    # Monthly exposure‐index thresholds
    df_idx_mg = df_monthly_global.select("exposure_index").filter(col("exposure_index").isNotNull())
    df_idx_mg.cache(); df_idx_mg.count()
    p25_mg, p50_mg, p75_mg = df_idx_mg.stat.approxQuantile("exposure_index",[0.25,0.50,0.75],0.01)
    lo_mg, md_mg, hi_mg = math.ceil(p25_mg), math.ceil(p50_mg), math.ceil(p75_mg)
    df_idx_mg.unpersist()

    df_idx_mv = df_monthly_vendor.select("exposure_index").filter(col("exposure_index").isNotNull())
    df_idx_mv.cache(); df_idx_mv.count()
    p25_mv, p50_mv, p75_mv = df_idx_mv.stat.approxQuantile("exposure_index",[0.25,0.50,0.75],0.01)
    lo_mv, md_mv, hi_mv = math.ceil(p25_mv), math.ceil(p50_mv), math.ceil(p75_mv)
    df_idx_mv.unpersist()

    df_idx_mp = df_monthly_product.select("exposure_index").filter(col("exposure_index").isNotNull())
    df_idx_mp.cache(); df_idx_mp.count()
    p25_mp, p50_mp, p75_mp = df_idx_mp.stat.approxQuantile("exposure_index",[0.25,0.50,0.75],0.01)
    lo_mp, md_mp, hi_mp = math.ceil(p25_mp), math.ceil(p50_mp), math.ceil(p75_mp)
    df_idx_mp.unpersist()

    # 3) YEARLY
    df_yearly_global = (
        enriched
          .groupBy("year_published")
          .agg(*common_aggs_global("weighted_score"))
          .withColumn("year_date", to_date(expr("make_date(year_published,1,1)")))
    )
    write_iceberg(
        df_yearly_global, "cve_production_yearly_global",
        "s3://cve-production/cve_production_tables/cve_production_yearly_global/",
        ["year_published"]
    )

    df_yearly_vendor = (
        enriched
          .groupBy("vendor","year_published")
          .agg(*common_aggs_vendor("weighted_score"))
          .withColumn("year_date", to_date(expr("make_date(year_published,1,1)")))
    )
    write_iceberg(
        df_yearly_vendor, "cve_production_yearly_vendor",
        "s3://cve-production/cve_production_tables/cve_production_yearly_vendor/",
        ["year_published"]
    )

    df_yearly_product = (
        enriched
          .groupBy("vendor","product","year_published")
          .agg(*common_aggs_product("weighted_score"))
          .withColumn("year_date", to_date(expr("make_date(year_published,1,1)")))
    )
    write_iceberg(
        df_yearly_product, "cve_production_yearly_product",
        "s3://cve-production/cve_production_tables/cve_production_yearly_product/",
        ["year_published"]
    )

    # Yearly exposure‐index thresholds
    df_idx_yg = df_yearly_global.select("exposure_index").filter(col("exposure_index").isNotNull())
    df_idx_yg.cache(); df_idx_yg.count()
    p25_yg, p50_yg, p75_yg = df_idx_yg.stat.approxQuantile("exposure_index",[0.25,0.50,0.75],0.01)
    lo_yg, md_yg, hi_yg = math.ceil(p25_yg), math.ceil(p50_yg), math.ceil(p75_yg)
    df_idx_yg.unpersist()

    df_idx_yv = df_yearly_vendor.select("exposure_index").filter(col("exposure_index").isNotNull())
    df_idx_yv.cache(); df_idx_yv.count()
    p25_yv, p50_yv, p75_yv = df_idx_yv.stat.approxQuantile("exposure_index",[0.25,0.50,0.75],0.01)
    lo_yv, md_yv, hi_yv = math.ceil(p25_yv), math.ceil(p50_yv), math.ceil(p75_yv)
    df_idx_yv.unpersist()

    df_idx_yp = df_yearly_product.select("exposure_index").filter(col("exposure_index").isNotNull())
    df_idx_yp.cache(); df_idx_yp.count()
    p25_yp, p50_yp, p75_yp = df_idx_yp.stat.approxQuantile("exposure_index",[0.25,0.50,0.75],0.01)
    lo_yp, md_yp, hi_yp = math.ceil(p25_yp), math.ceil(p50_yp), math.ceil(p75_yp)
    df_idx_yp.unpersist()

    # Trailing windows
    cutoff_12mo = add_months(current_date(), -12)
    cutoff_1mo  = add_months(current_date(),  -1)

    for cutoff, label in [(cutoff_12mo, "12mo"), (cutoff_1mo, "1mo")]:
        # Vendor
        tw_v = (
            enriched.filter(col("date_published")>=cutoff)
                    .groupBy("vendor")
                    .agg(*common_aggs_vendor("weighted_score"))
                    .withColumn("window_start", cutoff)
                    .withColumn("window_end",   current_date())
        )
        write_iceberg(tw_v,
                      f"cve_production_trailing_{label}_vendor",
                      f"s3://cve-production/cve_production_tables/cve_production_trailing_{label}_vendor/",
                      ["window_start"])

        # Product
        tw_p = (
            enriched.filter(col("date_published")>=cutoff)
                    .groupBy("vendor","product")
                    .agg(*common_aggs_product("weighted_score"))
                    .withColumn("window_start", cutoff)
                    .withColumn("window_end",   current_date())
        )
        write_iceberg(tw_p,
                      f"cve_production_trailing_{label}_product",
                      f"s3://cve-production/cve_production_tables/cve_production_trailing_{label}_product/",
                      ["window_start"])

    # Collect threshold rows and write thresholds table
    stats = []
    for level_label, df in [
        ("daily_global", df_daily_global),
        ("daily_vendor", df_daily_vendor),
        ("daily_product", df_daily_product),
        ("monthly_global", df_monthly_global),
        ("monthly_vendor", df_monthly_vendor),
        ("monthly_product", df_monthly_product),
        ("yearly_global", df_yearly_global),
        ("yearly_vendor", df_yearly_vendor),
        ("yearly_product", df_yearly_product),
    ]:
        idx = df.select("exposure_index").filter(col("exposure_index").isNotNull())
        idx.cache(); total = idx.count()
        p25, p50, p75 = idx.stat.approxQuantile("exposure_index",[0.25,0.5,0.75],0.01)
        lo, md, hi = math.ceil(p25), math.ceil(p50), math.ceil(p75)
        maxv = idx.agg({"exposure_index":"max"}).first()[0]
        stats.append((level_label, total,
                    float(idx.agg({"exposure_index":"min"}).first()[0]),
                    float(p25), float(p50), float(p75), float(maxv),
                    float(lo), float(md), float(hi),
                    run_ts))

    schema = """
        level: string, total_count: long, min_val: double,
        p25: double, p50: double, p75: double, max_val: double,
        low_threshold: double, med_threshold: double, high_threshold: double,
        run_ts: timestamp
    """
    thresholds_df = spark.createDataFrame(stats, schema)
    thresholds_df.write.format("iceberg")\
        .mode("overwrite")\
        .option("path", "s3://cve-production/cve_production_tables/cve_production_exposure_index_thresholds/")\
        .saveAsTable(f"{DATABASE}.cve_production_exposure_index_thresholds")

    # Running totals
    for lvl, partition, expr_key, suffix in [
        ("global",  [], "yearly_global", "cve_production_daily_global_running"),
        ("vendor",  ["vendor"], "yearly_vendor", "cve_production_daily_vendor_running"),
        ("product", ["vendor","product"], "yearly_product", "cve_production_daily_product_running"),
    ]:
        w = Window.partitionBy(*partition).orderBy("datePublished").rowsBetween(Window.unboundedPreceding, Window.currentRow)
        dfr = (
            spark.table(f"{DATABASE}.cve_production_daily_{lvl}")
                 .withColumn("cumulative_exposure_index", round_col(F.sum("exposure_index").over(w),2))
        )
        write_iceberg(
            dfr,
            suffix,
            f"s3://cve-production/cve_production_tables/{suffix}/",
            ["year_published","date_published"]
        )

    # Meta update
    (
        spark.range(1)
             .select(
                 lit("cve_pipeline").alias("pipeline_name"),
                 lit(run_ts).alias("last_run_ts")
             )
             .write.format("iceberg").mode("overwrite")
             .saveAsTable(f"{DATABASE}.cve_production_mv_meta")
    )
    print("Full backfill complete")

elif RUN_TYPE == "incremental":
    # Load thresholds
    th_df = spark.table(f"{DATABASE}.cve_production_exposure_index_thresholds")
    latest_ts = th_df.agg(F.max("run_ts").alias("max_run")).first()["max_run"]
    latest_th = th_df.filter(col("run_ts")==lit(latest_ts)).collect()

    # Identify updated lookup rows
    last_run_ts = spark.table(f"{DATABASE}.cve_production_mv_meta") \
                      .filter(col("pipeline_name")=="cve_pipeline") \
                      .select("last_run_ts").first()["last_run_ts"]
    updates_base = (
        spark.table(f"{DATABASE}.cve_production_master")
             .filter(col("validFrom").isNotNull() & (col("validFrom")>to_timestamp(lit(last_run_ts))))
             .filter("currentFlag = true")
    )
    updates = (
        transform_for_lookup(updates_base)
        .transform(lambda df: enrich_with_risk_flags(df))
        .withColumn("year_published", year(col("datePublished")))
        .withColumn("date_published", to_date(col("datePublished")))
    )
    # dedupe per (cveId,vendor,product) by validFrom desc
    win = Window.partitionBy("cveId","vendor","product").orderBy(col("validFrom").desc())
    updates_unique = updates.withColumn("rn", row_number().over(win)).filter("rn=1").drop("rn")

    updates_unique.createOrReplaceTempView("updates_temp")
    spark.sql(f"""
      DELETE FROM {DATABASE}.cve_production_lookup
      WHERE EXISTS (
        SELECT 1 FROM updates_temp u
        WHERE {DATABASE}.cve_production_lookup.cveId=u.cveId
          AND vendor=u.vendor AND product=u.product
      )
    """)
    spark.sql(f"""
      INSERT INTO {DATABASE}.cve_production_lookup
      SELECT * FROM updates_temp
    """)

    # Dynamic overwrite helper
    def dynamic_overwrite(level, df, dims, expr_key, suffix, parts):
        df_agg = (
            df.withColumn("weighted_score", weighted)
              .groupBy(*dims, "datePublished")
              .agg(
                  *(
                    common_aggs_global()
                    if level=="global"
                    else (common_aggs_vendor() if level=="vendor" else common_aggs_product())
                  )
              )
              .withColumn("year_published", year(col("datePublished")))
              .withColumn("date_published", to_date(col("datePublished")))
        )
        write_iceberg(df_agg, suffix,
                      f"s3://cve-production/cve_production_tables/{suffix}/",
                      parts, mode="overwrite", dynamic=True)

    full_lookup = spark.table(f"{DATABASE}.cve_production_lookup").cache()

    # Overwrite impacted daily partitions
    days = [r.d for r in updates_unique.select(to_date(col("datePublished")).alias("d")).distinct().collect()]
    for d in days:
        day_df = full_lookup.filter(to_date(col("datePublished"))==lit(d))
        for lvl, dims, expr_key, suffix, parts in [
            ("global", [], "daily_global", "cve_production_daily_global", ["year_published","date_published"]),
            ("vendor", ["vendor"], "daily_vendor", "cve_production_daily_vendor", ["year_published","date_published"]),
            ("product", ["vendor","product"], "daily_product", "cve_production_daily_product", ["year_published","date_published"])
        ]:
            dynamic_overwrite(lvl, day_df, dims, expr_key, suffix, parts)

    # Overwrite impacted monthly partitions
    ym = updates_unique.select(year(col("datePublished")).alias("y"), month(col("datePublished")).alias("m")).distinct().collect()
    for y,m in ym:
        mon_df = full_lookup.filter(year(col("datePublished"))==y).filter(month(col("datePublished"))==m) \
                            .withColumn("month_published", month(col("datePublished")))
        for lvl, dims, expr_key, suffix in [
            ("global",  ["year_published","month_published"], "monthly_global", "cve_production_monthly_global"),
            ("vendor",  ["vendor","year_published","month_published"], "monthly_vendor", "cve_production_monthly_vendor"),
            ("product", ["vendor","product","year_published","month_published"], "monthly_product","cve_production_monthly_product"),
        ]:
            dfm = mon_df.groupBy(*dims).agg(
                    *(
                      common_aggs_global()
                      if lvl=="global"
                      else (common_aggs_vendor() if lvl=="vendor" else common_aggs_product())
                    )
                 ) \
                 .withColumn("month_date", to_date(expr(f"make_date(year_published,month_published,1)")))
            write_iceberg(dfm, suffix,
                          f"s3://cve-production/cve_production_tables/{suffix}/",
                          ["year_published","month_published"],
                          mode="overwrite", dynamic=True)

    # Rebuild running totals
    for lvl, partition, expr_key, suffix in [
        ("global",  [], "yearly_global", "cve_production_daily_global_running"),
        ("vendor",  ["vendor"], "yearly_vendor", "cve_production_daily_vendor_running"),
        ("product", ["vendor","product"], "yearly_product", "cve_production_daily_product_running"),
    ]:
        w = Window.partitionBy(*partition).orderBy("datePublished").rowsBetween(Window.unboundedPreceding, Window.currentRow)
        run_df = (
            spark.table(f"{DATABASE}.cve_production_daily_{lvl}")
                 .withColumn("cumulative_exposure_index", round_col(F.sum("exposure_index").over(w),2))
        )
        write_iceberg(
            run_df, suffix, f"s3://cve-production/cve_production_tables/{suffix}/", ["year_published","date_published"],
            mode="overwrite"
        )

    # Update meta‑table watermark
    (
        spark.range(1)
             .select(
                 lit("cve_pipeline").alias("pipeline_name"),
                 lit(run_ts).alias("last_run_ts")
             )
             .write.format("iceberg").mode("overwrite")
             .saveAsTable(f"{DATABASE}.cve_production_mv_meta")
    )
    print(f"Incremental update since {last_run_ts} complete")

else:
    raise ValueError(f"run_type must be 'backfill' or 'incremental'")
