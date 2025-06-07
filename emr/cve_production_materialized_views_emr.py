import argparse
import math
from datetime import datetime, timedelta, timezone
from functools import reduce

from pyspark.sql import SparkSession, functions as F
from pyspark.sql.functions import (
    when, to_date, to_timestamp, year, month, current_date, col, countDistinct, sum as spark_sum, 
    expr, lit, initcap, concat, round as spark_round, regexp_replace, trim, regexp_extract, row_number
)
from pyspark.sql.window import Window

# Configuration
database = "cve_db"
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
        .config("spark.sql.shuffle.partitions", "24")
        .config("spark.default.parallelism", "24")
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
  CREATE TABLE IF NOT EXISTS {database}.cve_production_mv_meta (
    pipeline_name STRING,
    last_run_ts   TIMESTAMP
  ) USING iceberg
  LOCATION 's3://cve-production/cve_production_tables/cve_production_mv_meta/'
""")

# parse command-line args
parser = argparse.ArgumentParser(
    prog="cve_pipeline",
    description="Run the CVE pipeline in either backfill or incremental mode."
)
parser.add_argument(
    "--run_type",
    choices=["backfill", "incremental"],
    default="backfill",
    help="Which mode to run: full backfill or incremental (default: backfill)"
)
args, _ = parser.parse_known_args()
run_type = args.run_type

if run_type == "incremental":
    last_meta = (
        spark.table(f"{database}.cve_production_mv_meta")
             .filter(col("pipeline_name")=="cve_pipeline")
             .orderBy(col("last_run_ts").desc()).limit(1)
             .collect()
    )
    last_run_ts = last_meta[0]["last_run_ts"].isoformat() if last_meta else "1970-01-01T00:00:00"
    print(f"Incremental mode: since {last_run_ts}")
else:
    last_run_ts = None
    print("Backfill mode: full rebuild")

# Utils
def round_col(c, scale):
    return spark_round(c.cast("double"), scale)

def compact_ts(c):
    s = c.cast("string")
    s = regexp_replace(s, r'(\.\d*?[1-9])0+$', r'\1')
    s = regexp_replace(s, r'\.0+$', '')
    return concat(s, lit(" UTC"))

def clean_name(c):
    cleaned = trim(regexp_replace(regexp_replace(c, r"\\", ""), "_", " "))
    return initcap(cleaned)

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

# Define all nine (table_name, level_label) pairs:
levels = [
    ("cve_production_daily_global",   "daily_global"),
    ("cve_production_daily_vendor",   "daily_vendor"),
    ("cve_production_daily_product",  "daily_product"),
    ("cve_production_monthly_global", "monthly_global"),
    ("cve_production_monthly_vendor", "monthly_vendor"),
    ("cve_production_monthly_product","monthly_product"),
    ("cve_production_yearly_global",  "yearly_global"),
    ("cve_production_yearly_vendor",  "yearly_vendor"),
    ("cve_production_yearly_product", "yearly_product"),
]

# Initialize every level as "Unknown"
exprs = { level_label: (lambda t: F.lit("Unknown")) for (_, level_label) in levels }

# Weighted score
weighted = (
    when(col("severity")=="Critical",   col("cvssScore")*1.0)
   .when(col("severity")=="High",       col("cvssScore")*0.75)
   .when(col("severity")=="Medium",     col("cvssScore")*0.50)
   .when(col("severity")=="Low",        col("cvssScore")*0.25)
   .otherwise(0)
)

# Common aggregations

# "Product‐level" aggregation: Each CVE is distinct per (vendor, product)
def common_aggs_product(weight_col="weighted_score"):
    return [
        countDistinct("cveId").alias("total_cves"),
        countDistinct("cveId").alias("distinct_cves"),
        round_col(spark_sum(col(weight_col)), 2).alias("exposure_index"),
        countDistinct(when(col("severity")=="Critical", col("cveId"))).alias("critical_count"),
        countDistinct(when(col("severity")=="High",     col("cveId"))).alias("high_count"),
        countDistinct(when(col("severity")=="Medium",   col("cveId"))).alias("medium_count"),
        countDistinct(when(col("severity")=="Low",      col("cveId"))).alias("low_count"),
        round_col(spark_sum(when(col("is_network_based"), col(weight_col))),2).alias("network_exposure_index"),
        countDistinct(when(col("is_network_based"), col("cveId"))).alias("network_cves"),
        countDistinct(when(col("is_no_ui"),          col("cveId"))).alias("no_ui_cves"),
        countDistinct(when(col("is_low_priv"),       col("cveId"))).alias("low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), col("cveId"))).alias("fully_critical_cves"),
    ]

# "Vendor‐level" aggregation: Treat each (cve, product) as a distinct incident
def common_aggs_vendor(weight_col="weighted_score"):
    # Create a synthetic key cve_product = concat(cveId,"|",product) to groupBy("vendor")
    return [
        countDistinct(concat(col("cveId"), lit("|"), col("product"))).alias("total_cves"),
        countDistinct("cveId").alias("distinct_cves"),
        round_col(spark_sum(col(weight_col)), 2).alias("exposure_index"),
        countDistinct(when(col("severity")=="Critical", concat(col("cveId"), lit("|"), col("product")))).alias("critical_count"),
        countDistinct(when(col("severity")=="High", concat(col("cveId"), lit("|"), col("product")))).alias("high_count"),
        countDistinct(when(col("severity")=="Medium", concat(col("cveId"), lit("|"), col("product")))).alias("medium_count"),
        countDistinct(when(col("severity")=="Low", concat(col("cveId"), lit("|"), col("product")))).alias("low_count"),
        round_col(spark_sum(when(col("is_network_based"), col(weight_col))),2).alias("network_exposure_index"),
        countDistinct(when(col("is_network_based"), concat(col("cveId"), lit("|"), col("product")))).alias("network_cves"),
        countDistinct(when(col("is_no_ui"), concat(col("cveId"), lit("|"), col("product")))).alias("no_ui_cves"),
        countDistinct(when(col("is_low_priv"), concat(col("cveId"), lit("|"), col("product")))).alias("low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), concat(col("cveId"), lit("|"), col("product")))).alias("fully_critical_cves"),
        countDistinct(col("product")).alias("affected_products")
    ]

# "Global‐level" aggregation: Count each (cve, vendor, product) combination as a separate "incident"
def common_aggs_global(weight_col="weighted_score"):
    return [
        countDistinct(concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product"))).alias("total_cves"),
        countDistinct("cveId").alias("distinct_cves"),
        round_col(spark_sum(col(weight_col)), 2).alias("exposure_index"),
        countDistinct(when(col("severity")=="Critical", concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product")))).alias("critical_count"),
        countDistinct(when(col("severity")=="High", concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product")))).alias("high_count"),
        countDistinct(when(col("severity")=="Medium", concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product")))).alias("medium_count"),
        countDistinct(when(col("severity")=="Low", concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product")))).alias("low_count"),
        round_col(spark_sum(when(col("is_network_based"), col(weight_col))),2).alias("network_exposure_index"),
        countDistinct(when(col("is_network_based"), concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product")))).alias("network_cves"),
        countDistinct(when(col("is_no_ui"), concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product")))).alias("no_ui_cves"),
        countDistinct(when(col("is_low_priv"), concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product")))).alias("low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), concat(col("cveId"), lit("|"), col("vendor"), lit("|"), col("product")))).alias("fully_critical_cves"),
    ]

# Write helper
def write_iceberg(df, table_suffix, path, partition_cols, mode="overwrite", dynamic=False):
    n = df.count()
    writer = df.write.format("iceberg").mode(mode)
    if dynamic:
        writer = writer.option("overwrite-mode","dynamic")
    writer.partitionBy(*partition_cols).option("path", path).saveAsTable(f"{database}.{table_suffix}")
    print(f"[DEBUG] {table_suffix} written: {n} rows")

# Processing
if run_type == "backfill":
    # Read & cache
    base = (
        spark.table(f"{database}.cve_production_master")
             .filter("currentFlag = true")
             .withColumn("year_published", year(col("datePublished")))
             .withColumn("date_published", to_date(col("datePublished")))
             .repartition(NUM_OUT, "year_published", "date_published")
             .cache()
    )
    print(f"[DEBUG] base cached: {base.count()} rows")

    # Raw lookup
    raw_lookup = (
        transform_for_lookup(base)
        .transform(lambda d: enrich_with_risk_flags(d))
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

    # Write out the deduped lookup
    write_iceberg(
        lookup_df,
        "cve_production_lookup",
        "s3://cve-production/cve_production_tables/cve_production_lookup/",
        ["year_published","date_published"]
    )

    # Enrich lookup for aggregations
    lookup = spark.table(f"{database}.cve_production_lookup")
    enriched = (
        enrich_with_risk_flags(lookup)
        .withColumn("weighted_score", weighted)
    )

    # Daily (compute without exposure_rating, then compute thresholds and apply)
    daily = (
        enriched.groupBy("datePublished","year_published")
                .agg(*common_aggs_global())
                .withColumn("date_published", to_date(col("datePublished")))
    )
    # Compute percentiles for daily_global
    df_idx = daily.select("exposure_index").filter(col("exposure_index").isNotNull())
    df_idx.cache()
    df_idx.count()
    p25, p50, p75 = df_idx.stat.approxQuantile("exposure_index", [0.25, 0.50, 0.75], 0.01)
    lo_th = math.ceil(p25)
    md_th = math.ceil(p50)
    hi_th = math.ceil(p75)
    exprs["daily_global"] = (
        lambda t, lo=lo_th, md=md_th, hi=hi_th: 
            when(t.isNull(), "Unknown")
            .when(t > hi, "Critical")
            .when(t > md, "High")
            .when(t > lo, "Moderate")
            .when(t > 1, "Low")
            .otherwise("None")
    )
    # Add exposure_rating
    daily = daily.withColumn("exposure_rating", exprs["daily_global"](col("exposure_index")))
    write_iceberg(
        daily,
        "cve_production_daily_global",
        "s3://cve-production/cve_production_tables/cve_production_daily_global/",
        ["year_published","date_published"]
    )
    # Collect threshold row for writing later
    stats_dfs = []  # initialize list to gather all nine threshold-schemas
    stats_row = spark.createDataFrame(
        [( "daily_global", df_idx.count(), 
        float(df_idx.agg({"exposure_index":"min"}).first()[0]), 
        float(p25), float(p50), float(p75), 
        float(df_idx.agg({"exposure_index":"max"}).first()[0]),
        float(lo_th), float(md_th), float(hi_th),
        datetime.now(timezone.utc))],
        schema="""
            level: string, total_count: long, min_val: double,
            p25: double, p50: double, p75: double, max_val: double,
            low_threshold: double, med_threshold: double, high_threshold: double,
            run_ts: timestamp
        """
    )
    stats_dfs.append(stats_row)

    daily_vendor = (
        enriched.groupBy("vendor","datePublished","year_published")
                .agg(*common_aggs_vendor())
                .withColumn("date_published", to_date(col("datePublished")))
    )
    # Compute percentiles for daily_vendor
    df_idx_vendor = daily_vendor.select("exposure_index").filter(col("exposure_index").isNotNull())
    df_idx_vendor.cache()
    df_idx_vendor.count()
    p25_v, p50_v, p75_v = df_idx_vendor.stat.approxQuantile("exposure_index", [0.25, 0.50, 0.75], 0.01)
    lo_th_v = math.ceil(p25_v)
    md_th_v = math.ceil(p50_v)
    hi_th_v = math.ceil(p75_v)
    exprs["daily_vendor"] = (
        lambda t, lo=lo_th_v, md=md_th_v, hi=hi_th_v: 
            when(t.isNull(), "Unknown")
            .when(t > hi, "Critical")
            .when(t > md, "High")
            .when(t > lo, "Moderate")
            .when(t > 1, "Low")
            .otherwise("None")
    )
    daily_vendor = daily_vendor.withColumn("exposure_rating", exprs["daily_vendor"](col("exposure_index")))
    write_iceberg(
        daily_vendor,
        "cve_production_daily_vendor",
        "s3://cve-production/cve_production_tables/cve_production_daily_vendor/",
        ["year_published","date_published"]
    )
    stats_row_vendor = spark.createDataFrame(
        [( "daily_vendor", df_idx_vendor.count(),
        float(df_idx_vendor.agg({"exposure_index":"min"}).first()[0]),
        float(p25_v), float(p50_v), float(p75_v),
        float(df_idx_vendor.agg({"exposure_index":"max"}).first()[0]),
        float(lo_th_v), float(md_th_v), float(hi_th_v),
        datetime.now(timezone.utc))],
        schema="""
            level: string, total_count: long, min_val: double,
            p25: double, p50: double, p75: double, max_val: double,
            low_threshold: double, med_threshold: double, high_threshold: double,
            run_ts: timestamp
        """
    )
    stats_dfs.append(stats_row_vendor)

    daily_prod = (
        enriched.groupBy("vendor","product","datePublished","year_published")
                .agg(*common_aggs_product())
                .withColumn("date_published", to_date(col("datePublished")))
    )
    # Compute percentiles for daily_product
    df_idx_prod = daily_prod.select("exposure_index").filter(col("exposure_index").isNotNull())
    df_idx_prod.cache()
    df_idx_prod.count()
    p25_p, p50_p, p75_p = df_idx_prod.stat.approxQuantile("exposure_index", [0.25, 0.50, 0.75], 0.01)
    lo_th_p = math.ceil(p25_p)
    md_th_p = math.ceil(p50_p)
    hi_th_p = math.ceil(p75_p)
    exprs["daily_product"] = (
        lambda t, lo=lo_th_p, md=md_th_p, hi=hi_th_p: 
            when(t.isNull(), "Unknown")
            .when(t > hi, "Critical")
            .when(t > md, "High")
            .when(t > lo, "Moderate")
            .when(t > 1, "Low")
            .otherwise("None")
    )
    daily_prod = daily_prod.withColumn("exposure_rating", exprs["daily_product"](col("exposure_index")))
    write_iceberg(
        daily_prod,
        "cve_production_daily_product",
        "s3://cve-production/cve_production_tables/cve_production_daily_product/",
        ["year_published","date_published"]
    )
    stats_row_prod = spark.createDataFrame(
        [( "daily_product", df_idx_prod.count(),
        float(df_idx_prod.agg({"exposure_index":"min"}).first()[0]),
        float(p25_p), float(p50_p), float(p75_p),
        float(df_idx_prod.agg({"exposure_index":"max"}).first()[0]),
        float(lo_th_p), float(md_th_p), float(hi_th_p),
        datetime.now(timezone.utc))],
        schema="""
            level: string, total_count: long, min_val: double,
            p25: double, p50: double, p75: double, max_val: double,
            low_threshold: double, med_threshold: double, high_threshold: double,
            run_ts: timestamp
        """
    )
    stats_dfs.append(stats_row_prod)

    # Monthly

    monthly_en = enriched.withColumn("month_published", month(col("datePublished")))

    for lvl, dims, expr_key, suffix in [
        ("global",  ["year_published","month_published"], "monthly_global", "cve_production_monthly_global"),
        ("vendor",  ["vendor","year_published","month_published"], "monthly_vendor", "cve_production_monthly_vendor"),
        ("product", ["vendor","product","year_published","month_published"], "monthly_product","cve_production_monthly_product"),
    ]:
        dfm = (
            monthly_en.groupBy(*dims)
            .agg(
                *(
                    common_aggs_global()
                    if lvl == "global"
                    else (common_aggs_vendor() if lvl == "vendor" else common_aggs_product())
                ))
            .withColumn("month_date", to_date(expr(f"make_date(year_published,month_published,1)")))
        )
        # Compute percentiles for this monthly level
        df_idx_m = dfm.select("exposure_index").filter(col("exposure_index").isNotNull())
        df_idx_m.cache()
        df_idx_m.count()
        p25_m, p50_m, p75_m = df_idx_m.stat.approxQuantile("exposure_index", [0.25,0.50,0.75], 0.01)
        lo_th_m = math.ceil(p25_m)
        md_th_m = math.ceil(p50_m)
        hi_th_m = math.ceil(p75_m)
        exprs[expr_key] = (
            lambda t, lo=lo_th_m, md=md_th_m, hi=hi_th_m: 
                when(t.isNull(), "Unknown")
                .when(t > hi, "Critical")
                .when(t > md, "High")
                .when(t > lo, "Moderate")
                .when(t > 1, "Low")
                .otherwise("None")
        )
        dfm = dfm.withColumn("exposure_rating", exprs[expr_key](col("exposure_index")))
        write_iceberg(
            dfm,
            suffix,
            f"s3://cve-production/cve_production_tables/{suffix}/",
            ["year_published","month_published"]
        )
        stats_row_m = spark.createDataFrame(
            [( expr_key, df_idx_m.count(),
            float(df_idx_m.agg({"exposure_index":"min"}).first()[0]),
            float(p25_m), float(p50_m), float(p75_m),
            float(df_idx_m.agg({"exposure_index":"max"}).first()[0]),
            float(lo_th_m), float(md_th_m), float(hi_th_m),
            datetime.now(timezone.utc))],
            schema="""
                level: string, total_count: long, min_val: double,
                p25: double, p50: double, p75: double, max_val: double,
                low_threshold: double, med_threshold: double, high_threshold: double,
                run_ts: timestamp
            """
        )
        stats_dfs.append(stats_row_m)

    # Yearly

    for lvl, dims, expr_key, suffix in [
        ("global",  ["year_published"], "yearly_global", "cve_production_yearly_global"),
        ("vendor",  ["vendor","year_published"], "yearly_vendor", "cve_production_yearly_vendor"),
        ("product", ["vendor","product","year_published"], "yearly_product","cve_production_yearly_product"),
    ]:
        dfy = (
            enriched.groupBy(*dims)
            .agg(
                *(
                    common_aggs_global()
                    if lvl == "global"
                    else (common_aggs_vendor() if lvl == "vendor" else common_aggs_product())
                ))
            .withColumn("year_date", to_date(expr("make_date(year_published,1,1)")))
        )
        # Compute percentiles for this yearly level
        df_idx_y = dfy.select("exposure_index").filter(col("exposure_index").isNotNull())
        df_idx_y.cache()
        df_idx_y.count()
        p25_y, p50_y, p75_y = df_idx_y.stat.approxQuantile("exposure_index", [0.25,0.50,0.75], 0.01)
        lo_th_y = math.ceil(p25_y)
        md_th_y = math.ceil(p50_y)
        hi_th_y = math.ceil(p75_y)
        exprs[expr_key] = (
            lambda t, lo=lo_th_y, md=md_th_y, hi=hi_th_y: 
                when(t.isNull(), "Unknown")
                .when(t > hi, "Critical")
                .when(t > md, "High")
                .when(t > lo, "Moderate")
                .when(t > 1, "Low")
                .otherwise("None")
        )
        dfy = dfy.withColumn("exposure_rating", exprs[expr_key](col("exposure_index")))
        write_iceberg(
            dfy,
            suffix,
            f"s3://cve-production/cve_production_tables/{suffix}/",
            ["year_published"]
        )
        stats_row_y = spark.createDataFrame(
            [( expr_key, df_idx_y.count(),
            float(df_idx_y.agg({"exposure_index":"min"}).first()[0]),
            float(p25_y), float(p50_y), float(p75_y),
            float(df_idx_y.agg({"exposure_index":"max"}).first()[0]),
            float(lo_th_y), float(md_th_y), float(hi_th_y),
            datetime.now(timezone.utc))],
            schema="""
                level: string, total_count: long, min_val: double,
                p25: double, p50: double, p75: double, max_val: double,
                low_threshold: double, med_threshold: double, high_threshold: double,
                run_ts: timestamp
            """
        )
        stats_dfs.append(stats_row_y)

    # TRAILING 12‐MONTH & TRAILING 1‐MONTH AGGREGATIONS (Vendor & Product)

    # Compute the "cutoff" dates (YYYY-MM-DD) for 12 months ago and 1 month ago (UTC):
    cutoff_12mo_str = (datetime.now(timezone.utc) - timedelta(days=365)).strftime("%Y-%m-%d")
    cutoff_1mo_str  = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")

    # A) Trailing 12 Months – Vendor Level (sum from daily_vendor)
    dv = spark.table(f"{database}.cve_production_daily_vendor")
    dp = spark.table(f"{database}.cve_production_daily_product")
    dv_12mo = dv.filter(col("date_published") >= lit(cutoff_12mo_str))
    trailing_12mo_vendor = (
        dv_12mo
             .groupBy("vendor")
             .agg(
                 spark_sum("total_cves").alias("total_cves"),
                 spark_sum("distinct_cves").alias("distinct_cves"),
                 spark_round(spark_sum("exposure_index"), 2).alias("exposure_index"),
                 spark_sum("critical_count").alias("critical_count"),
                 spark_sum("high_count").alias("high_count"),
                 spark_sum("medium_count").alias("medium_count"),
                 spark_sum("low_count").alias("low_count"),
                 spark_round(spark_sum("network_exposure_index"), 2).alias("network_exposure_index"),
                 spark_sum("network_cves").alias("network_cves"),
                 spark_sum("no_ui_cves").alias("no_ui_cves"),
                 spark_sum("low_priv_cves").alias("low_priv_cves"),
                 spark_sum("fully_critical_cves").alias("fully_critical_cves"),
                 spark_sum("affected_products").alias("affected_products")
             )
             .withColumn("window_start", to_date(lit(cutoff_12mo_str)))
             .withColumn("window_end",   current_date())
             .withColumn("exposure_rating", exprs["yearly_vendor"](col("exposure_index")))
    )
    write_iceberg(
        trailing_12mo_vendor,
        "cve_production_trailing_12mo_vendor",
        "s3://cve-production/cve_production_tables/cve_production_trailing_12mo_vendor/",
        []
    )

    # B) Trailing 12 Months – Product Level (sum from daily_product)
    dp_12mo = dp.filter(col("date_published") >= lit(cutoff_12mo_str))
    trailing_12mo_product = (
        dp_12mo
             .groupBy("vendor", "product")
             .agg(
                 spark_sum("total_cves").alias("total_cves"),
                 spark_sum("distinct_cves").alias("distinct_cves"),
                 spark_round(spark_sum("exposure_index"), 2).alias("exposure_index"),
                 spark_sum("critical_count").alias("critical_count"),
                 spark_sum("high_count").alias("high_count"),
                 spark_sum("medium_count").alias("medium_count"),
                 spark_sum("low_count").alias("low_count"),
                 spark_round(spark_sum("network_exposure_index"), 2).alias("network_exposure_index"),
                 spark_sum("network_cves").alias("network_cves"),
                 spark_sum("no_ui_cves").alias("no_ui_cves"),
                 spark_sum("low_priv_cves").alias("low_priv_cves"),
                 spark_sum("fully_critical_cves").alias("fully_critical_cves")
             )
             .withColumn("window_start", to_date(lit(cutoff_12mo_str)))
             .withColumn("window_end",   current_date())
             .withColumn("exposure_rating", exprs["yearly_product"](col("exposure_index")))
    )
    write_iceberg(
        trailing_12mo_product,
        "cve_production_trailing_12mo_product",
        "s3://cve-production/cve_production_tables/cve_production_trailing_12mo_product/",
        []
    )

    # C) Trailing 1 Month – Vendor Level (sum from daily_vendor)
    dv_1mo = dv.filter(col("date_published") >= lit(cutoff_1mo_str))
    trailing_1mo_vendor = (
        dv_1mo
             .groupBy("vendor")
             .agg(
                 spark_sum("total_cves").alias("total_cves"),
                 spark_sum("distinct_cves").alias("distinct_cves"),
                 spark_round(spark_sum("exposure_index"), 2).alias("exposure_index"),
                 spark_sum("critical_count").alias("critical_count"),
                 spark_sum("high_count").alias("high_count"),
                 spark_sum("medium_count").alias("medium_count"),
                 spark_sum("low_count").alias("low_count"),
                 spark_round(spark_sum("network_exposure_index"), 2).alias("network_exposure_index"),
                 spark_sum("network_cves").alias("network_cves"),
                 spark_sum("no_ui_cves").alias("no_ui_cves"),
                 spark_sum("low_priv_cves").alias("low_priv_cves"),
                 spark_sum("fully_critical_cves").alias("fully_critical_cves"),
                 spark_sum("affected_products").alias("affected_products")
             )
             .withColumn("window_start", to_date(lit(cutoff_1mo_str)))
             .withColumn("window_end",   current_date())
             .withColumn("exposure_rating", exprs["yearly_vendor"](col("exposure_index")))
    )
    write_iceberg(
        trailing_1mo_vendor,
        "cve_production_trailing_1mo_vendor",
        "s3://cve-production/cve_production_tables/cve_production_trailing_1mo_vendor/",
        []
    )

    # D) Trailing 1 Month – Product Level (sum from daily_product)
    dp_1mo = dp.filter(col("date_published") >= lit(cutoff_1mo_str))
    trailing_1mo_product = (
        dp_1mo
             .groupBy("vendor", "product")
             .agg(
                 spark_sum("total_cves").alias("total_cves"),
                 spark_sum("distinct_cves").alias("distinct_cves"),
                 spark_round(spark_sum("exposure_index"), 2).alias("exposure_index"),
                 spark_sum("critical_count").alias("critical_count"),
                 spark_sum("high_count").alias("high_count"),
                 spark_sum("medium_count").alias("medium_count"),
                 spark_sum("low_count").alias("low_count"),
                 spark_round(spark_sum("network_exposure_index"), 2).alias("network_exposure_index"),
                 spark_sum("network_cves").alias("network_cves"),
                 spark_sum("no_ui_cves").alias("no_ui_cves"),
                 spark_sum("low_priv_cves").alias("low_priv_cves"),
                 spark_sum("fully_critical_cves").alias("fully_critical_cves")
             )
             .withColumn("window_start", to_date(lit(cutoff_1mo_str)))
             .withColumn("window_end",   current_date())
             .withColumn("exposure_rating", exprs["yearly_product"](col("exposure_index")))
    )
    write_iceberg(
        trailing_1mo_product,
        "cve_production_trailing_1mo_product",
        "s3://cve-production/cve_production_tables/cve_production_trailing_1mo_product/",
        []
    )

    # Running totals
    for lvl, partition, expr_key, suffix in [
        ("global",  [], "yearly_global", "cve_production_daily_global_running"),
        ("vendor",  ["vendor"], "yearly_vendor", "cve_production_daily_vendor_running"),
        ("product", ["vendor","product"], "yearly_product", "cve_production_daily_product_running"),
    ]:
        w = Window.partitionBy(*partition).orderBy("datePublished").rowsBetween(Window.unboundedPreceding, Window.currentRow)
        dfr = (
            spark.table(f"{database}.cve_production_daily_{lvl}")
                 .withColumn("cumulative_exposure_index", round_col(F.sum("exposure_index").over(w),2))
                 .withColumn("running_exposure_rating", exprs[expr_key](col("cumulative_exposure_index")))
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
                 F.current_timestamp().alias("last_run_ts")
             )
             .write.format("iceberg").mode("overwrite")
             .saveAsTable(f"{database}.cve_production_mv_meta")
    )
    print("Full backfill complete")

    # After writing all nine levels, write out the thresholds table in one shot:
    thresholds_df = stats_dfs[0]
    for df_part in stats_dfs[1:]:
        thresholds_df = thresholds_df.unionByName(df_part)
    thresholds_df.write.format("iceberg") \
                  .mode("overwrite") \
                  .option("path", "s3://cve-production/cve_production_tables/cve_production_exposure_index_thresholds/") \
                  .saveAsTable(f"{database}.cve_production_exposure_index_thresholds")

    # Expire snapshots & remove older orphan files
    tables_to_clean = [
        "cve_production_lookup",
        "cve_production_daily_global",
        "cve_production_daily_vendor",
        "cve_production_daily_product",
        "cve_production_monthly_global",
        "cve_production_monthly_vendor",
        "cve_production_monthly_product",
        "cve_production_yearly_global",
        "cve_production_yearly_vendor",
        "cve_production_yearly_product",
        "cve_production_daily_global_running",
        "cve_production_daily_vendor_running",
        "cve_production_daily_product_running",
        "cve_production_trailing_12mo_vendor",
        "cve_production_trailing_12mo_product",
        "cve_production_trailing_1mo_vendor",
        "cve_production_trailing_1mo_product",
        "cve_production_mv_meta"
    ]

    # compute a timestamp 24 hours ago (UTC)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    for tbl in tables_to_clean:
        # expire all but the last snapshot
        spark.sql(f"""
          CALL spark_catalog.system.expire_snapshots(
            table      => '{database}.{tbl}',
            retain_last=> 1
          )
        """)

        # delete unreferenced files older than cutoff
        spark.sql(f"""
          CALL spark_catalog.system.remove_orphan_files(
            table      => '{database}.{tbl}',
            older_than => TIMESTAMP '{cutoff_str}'
          )
        """)

    print(f"Expired snapshots and removed orphan files older than {cutoff_str} for all materialized views")

elif run_type == "incremental":
    th_df = spark.table(f"{database}.cve_production_exposure_index_thresholds")
    latest_ts = th_df.agg(F.max("run_ts").alias("max_run")).first()["max_run"]
    latest_th = th_df.filter(col("run_ts") == F.lit(latest_ts)).collect()
    exprs.clear()
    for row in latest_th:
        lvl = row["level"]
        lo = row["low_threshold"]
        md = row["med_threshold"]
        hi = row["high_threshold"]
        exprs[lvl] = (
            lambda t, lo=lo, md=md, hi=hi:
                when(t.isNull(), "Unknown")
                .when(t > hi, "Critical")
                .when(t > md, "High")
                .when(t > lo, "Moderate")
                .when(t > 1, "Low")
                .otherwise("None")
        )
    
    # Read only new/changed rows
    updates_base = (
        spark.table(f"{database}.cve_production_master")
             .filter(col("validFrom").isNotNull())
             .filter(col("validFrom") > to_timestamp(lit(last_run_ts)))
             .filter("currentFlag = true")
    )
    updates = (
        transform_for_lookup(updates_base)
        .transform(lambda d: enrich_with_risk_flags(d))
        .withColumn("year_published", year(col("datePublished")))
        .withColumn("date_published", to_date(col("datePublished")))
    )
    
    # Deduplicate on the composite key, keeping only the row with the latest validFrom
    dedupe_win = Window.partitionBy("cveId", "vendor", "product") \
                       .orderBy(col("validFrom").desc())
    updates_unique = (
        updates
          .withColumn("rn", F.row_number().over(dedupe_win))
          .filter(col("rn") == 1)
          .drop("rn")
    )

    updates_unique.createOrReplaceTempView("updates_temp")
    print(f"[DEBUG] updates_base: {updates_base.count()} new/changed rows since {last_run_ts}")

    # Delete any stale lookup rows for these keys
    spark.sql(f"""
      DELETE FROM {database}.cve_production_lookup
      WHERE EXISTS (
        SELECT 1
          FROM updates_temp AS source
         WHERE {database}.cve_production_lookup.cveId   = source.cveId
           AND {database}.cve_production_lookup.vendor  = source.vendor
           AND {database}.cve_production_lookup.product = source.product
      )
    """)
    print("[DEBUG] Deleted old lookup rows for impacted keys")

    # Insert the fresh, single-row-per-key data
    spark.sql(f"""
      INSERT INTO {database}.cve_production_lookup
      SELECT datePublished, vendor, product, cveId, descriptions, cvssScore, severity, vectorString,
      impactScore, exploitabilityScore, source, sourceType, cvssVersion, vulnStatus, cweData, capecData,
      cvssData, dateReserved, dateUpdated, datePublic, lastModified, year_published, date_published
      FROM updates_temp
    """)
    print("[DEBUG] Inserted updated lookup rows")

    # Helper for dynamic overwrite of partitions
    def dynamic_overwrite(level, df, dims, expr_key, suffix, partition_cols):
        df_agg = (
            df.withColumn("weighted_score", weighted)
            .groupBy(*dims, "datePublished")
            .agg(
                *(
                    common_aggs_global()
                    if level == "global"
                    else (common_aggs_vendor() if level == "vendor" else common_aggs_product())
                    ))
            .withColumn("exposure_rating", exprs[expr_key](col("exposure_index")))
            .withColumn("year_published", year(col("datePublished")))
            .withColumn("date_published", to_date(col("datePublished")))
        )
        write_iceberg(df_agg, suffix,
                      f"s3://cve-production/cve_production_tables/{suffix}/",
                      partition_cols, mode="overwrite", dynamic=True)

    # Cache the full lookup table once, so we don’t re‐read it on every iteration:
    full_lookup = spark.table(f"{database}.cve_production_lookup").cache()

    # Overwrite impacted daily partitions
    days = [r.d for r in updates_unique.select(to_date(col("datePublished")).alias("d")).distinct().collect()]
    for d in days:
        day_df = (
            full_lookup
                    .filter(to_date(col("datePublished")) == lit(d))
                    .transform(lambda df: enrich_with_risk_flags(df))
        )
        dynamic_overwrite("global",  day_df, [], "daily_global", "cve_production_daily_global", ["year_published","date_published"])
        dynamic_overwrite("vendor",  day_df, ["vendor"], "daily_vendor", "cve_production_daily_vendor", ["year_published","date_published"])
        dynamic_overwrite("product", day_df, ["vendor","product"], "daily_product", "cve_production_daily_product", ["year_published","date_published"])

    # Overwrite impacted monthly partitions
    ym_list = updates_unique.select(
                    year(col("datePublished")).alias("y"),
                    month(col("datePublished")).alias("m")
                ).distinct().collect()
    for y, m in ym_list:
        mon_df = (
            full_lookup
                    .filter(year(col("datePublished")) == y)
                    .filter(month(col("datePublished")) == m)
                    .withColumn("month_published", month(col("datePublished")))
                    .transform(lambda df: enrich_with_risk_flags(df))
        )
        for lvl, dims, expr_key, suffix in [
            ("global",  ["year_published","month_published"], "monthly_global", "cve_production_monthly_global"),
            ("vendor",  ["vendor","year_published","month_published"], "monthly_vendor", "cve_production_monthly_vendor"),
            ("product", ["vendor","product","year_published","month_published"], "monthly_product","cve_production_monthly_product"),
        ]:
            mon_agg = (
                mon_df.groupBy(*dims)
                .agg(
                    *(
                        common_aggs_global()
                        if lvl == "global"
                        else (common_aggs_vendor() if lvl == "vendor" else common_aggs_product())
                    ))
                .withColumn("exposure_rating", exprs[expr_key](col("exposure_index")))
                .withColumn("month_date", to_date(expr("make_date(year_published,month_published,1)")))
            )
            write_iceberg(
                mon_agg,
                suffix,
                f"s3://cve-production/cve_production_tables/{suffix}/",
                ["year_published","month_published"],
                mode="overwrite",
                dynamic=True
            )

    # Rebuild running totals
    for lvl, partition, expr_key, suffix in [
        ("global",  [], "yearly_global", "cve_production_daily_global_running"),
        ("vendor",  ["vendor"], "yearly_vendor", "cve_production_daily_vendor_running"),
        ("product", ["vendor","product"], "yearly_product", "cve_production_daily_product_running"),
    ]:
        w = Window.partitionBy(*partition).orderBy("datePublished").rowsBetween(Window.unboundedPreceding, Window.currentRow)
        run_df = (
            spark.table(f"{database}.cve_production_daily_{lvl}")
                 .withColumn("cumulative_exposure_index", round_col(F.sum("exposure_index").over(w),2))
                 .withColumn("running_exposure_rating", exprs[expr_key](col("cumulative_exposure_index")))
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
                 F.current_timestamp().alias("last_run_ts")
             )
             .write.format("iceberg").mode("overwrite")
             .saveAsTable(f"{database}.cve_production_mv_meta")
    )
    print(f"Incremental update since {last_run_ts} complete")

else:
    raise ValueError(f"run_type must be 'backfill' or 'incremental' (got '{run_type}')")
