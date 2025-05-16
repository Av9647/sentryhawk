import argparse

# parse command-line args
parser = argparse.ArgumentParser(
    prog="cve_pipeline",
    description="Run the CVE pipeline in either backfill or incremental mode."
)
parser.add_argument(
    "--run_type",
    choices=["backfill", "incremental"],
    default="incremental",
    help="Which mode to run: full backfill or incremental (default: incremental)"
)
args, unknown = parser.parse_known_args()
run_type = args.run_type

from pyspark.sql import SparkSession, functions as F
from pyspark.sql.functions import (
    when, to_date, to_timestamp, year, month, col, countDistinct, sum_distinct, expr, 
    lit, initcap, concat, round as spark_round, regexp_replace, trim, regexp_extract
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

# Meta‑table & last‑run
spark.sql(f"""
  CREATE TABLE IF NOT EXISTS {database}.cve_production_mv_meta (
    pipeline_name STRING,
    last_run_ts   TIMESTAMP
  ) USING iceberg
  LOCATION 's3://cve-production/cve_production_tables/cve_production_mv_meta/'
""")

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

# Risk-rating ranges derived from cve_threat_index_ranges.sql
exprs = {
    "daily_global":   lambda t: when(t.isNull(),"Unknown").when(t>9,"Critical").when(t>7,"High").when(t>4,"Moderate").when(t>1,"Low").otherwise("None"),
    "daily_vendor":   lambda t: when(t.isNull(),"Unknown").when(t>7,"Critical").when(t>6,"High").when(t>4,"Moderate").when(t>1,"Low").otherwise("None"),
    "daily_product":  lambda t: when(t.isNull(),"Unknown").when(t>7,"Critical").when(t>7,"High").when(t>5,"Moderate").when(t>1,"Low").otherwise("None"),
    "monthly_global": lambda t: when(t.isNull(),"Unknown").when(t>244,"Critical").when(t>137,"High").when(t>95,"Moderate").when(t>1,"Low").otherwise("None"),
    "monthly_vendor": lambda t: when(t.isNull(),"Unknown").when(t>10,"Critical").when(t>7,"High").when(t>4,"Moderate").when(t>1,"Low").otherwise("None"),
    "monthly_product":lambda t: when(t.isNull(),"Unknown").when(t>11,"Critical").when(t>7,"High").when(t>5,"Moderate").when(t>1,"Low").otherwise("None"),
    "ytd_global":     lambda t: when(t.isNull(),"Unknown").when(t>293,"Critical").when(t>236,"High").when(t>175,"Moderate").when(t>1,"Low").otherwise("None"),
    "ytd_vendor":     lambda t: when(t.isNull(),"Unknown").when(t>10,"Critical").when(t>7,"High").when(t>5,"Moderate").when(t>1,"Low").otherwise("None"),
    "ytd_product":    lambda t: when(t.isNull(),"Unknown").when(t>12,"Critical").when(t>8,"High").when(t>5,"Moderate").when(t>1,"Low").otherwise("None"),
}

# Weighted score
weighted = (
    when(col("severity")=="Critical",   col("cvssScore")*1.0)
   .when(col("severity")=="High",       col("cvssScore")*0.75)
   .when(col("severity")=="Medium",     col("cvssScore")*0.50)
   .when(col("severity")=="Low",        col("cvssScore")*0.25)
   .otherwise(0)
)

# Common aggregations
def common_aggs(weight_col="weighted_score"):
    return [
        countDistinct("cveId").alias("total_cves"),
        round_col(sum_distinct(col(weight_col)), 2).alias("threat_index"),
        countDistinct(when(col("severity")=="Critical", col("cveId"))).alias("critical_count"),
        countDistinct(when(col("severity")=="High",     col("cveId"))).alias("high_count"),
        countDistinct(when(col("severity")=="Medium",   col("cveId"))).alias("medium_count"),
        countDistinct(when(col("severity")=="Low",      col("cveId"))).alias("low_count"),
        round_col(sum_distinct(when(col("is_network_based"), col(weight_col))),2).alias("network_threat_index"),
        countDistinct(when(col("is_network_based"), col("cveId"))).alias("network_cves"),
        countDistinct(when(col("is_no_ui"),    col("cveId"))).alias("no_ui_cves"),
        countDistinct(when(col("is_low_priv"),col("cveId"))).alias("low_priv_cves"),
        countDistinct(when(col("is_fully_critical"), col("cveId"))).alias("fully_critical_cves"),
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

    # Lookup table
    lookup_df = (
        transform_for_lookup(base)
        .transform(lambda d: enrich_with_risk_flags(d))
        .select(
            "datePublished","vendor","product","cveId","descriptions","cvssScore","severity",
            "vectorString","impactScore","exploitabilityScore","source","sourceType","cvssVersion",
            "vulnStatus","cweData","capecData","cvssData","dateReserved","dateUpdated",
            "datePublic","lastModified","year_published","date_published"
        )
    )
    write_iceberg(
        lookup_df, 
        "cve_production_lookup", 
        "s3://cve-production/cve_production_tables/cve_production_lookup/",
        ["year_published","date_published"]
    )

    # Enrich base for aggregations
    enriched = enrich_with_risk_flags(transform_for_lookup(base)) \
                   .withColumn("weighted_score", weighted)

    # Daily
    daily = (
        enriched.groupBy("datePublished","year_published")
                .agg(*common_aggs())
                .withColumn("vendor", lit(None).cast("string"))
                .withColumn("product", lit(None).cast("string"))
                .withColumn("risk_rating", exprs["daily_global"](col("threat_index")))
                .withColumn("date_published", to_date(col("datePublished")))
    )
    write_iceberg(
        daily,
        "cve_production_daily_global",
        "s3://cve-production/cve_production_tables/cve_production_daily_global/",
        ["year_published","date_published"]
    )

    daily_vendor = (
        enriched.groupBy("vendor","datePublished","year_published")
                .agg(*common_aggs())
                .withColumn("product", lit(None).cast("string"))
                .withColumn("risk_rating", exprs["daily_vendor"](col("threat_index")))
                .withColumn("date_published", to_date(col("datePublished")))
    )
    write_iceberg(
        daily_vendor,
        "cve_production_daily_vendor",
        "s3://cve-production/cve_production_tables/cve_production_daily_vendor/",
        ["year_published","date_published"]
    )

    daily_prod = (
        enriched.groupBy("vendor","product","datePublished","year_published")
                .agg(*common_aggs())
                .withColumn("risk_rating", exprs["daily_product"](col("threat_index")))
                .withColumn("date_published", to_date(col("datePublished")))
    )
    write_iceberg(
        daily_prod,
        "cve_production_daily_product",
        "s3://cve-production/cve_production_tables/cve_production_daily_product/",
        ["year_published","date_published"]
    )

    # Monthly
    monthly_en = enriched.withColumn("month_published", month(col("datePublished")))
    for lvl, dims, expr_key, suffix in [
        ("global",  ["year_published","month_published"], "monthly_global", "cve_production_monthly_global"),
        ("vendor",  ["vendor","year_published","month_published"], "monthly_vendor", "cve_production_monthly_vendor"),
        ("product", ["vendor","product","year_published","month_published"], "monthly_product","cve_production_monthly_product"),
    ]:
        dfm = (
            monthly_en.groupBy(*dims)
                      .agg(*common_aggs())
                      .withColumn("risk_rating", exprs[expr_key](col("threat_index")))
                      .withColumn("month_date", to_date(expr(f"make_date(year_published,month_published,1)")))
        )
        write_iceberg(
            dfm,
            suffix,
            f"s3://cve-production/cve_production_tables/{suffix}/",
            ["year_published","month_published"]
        )

    # YTD
    for lvl, dims, expr_key, suffix in [
        ("global",  ["year_published"], "ytd_global", "cve_production_ytd_global"),
        ("vendor",  ["vendor","year_published"], "ytd_vendor", "cve_production_ytd_vendor"),
        ("product", ["vendor","product","year_published"], "ytd_product","cve_production_ytd_product"),
    ]:
        dfy = (
            enriched.groupBy(*dims)
                    .agg(*common_aggs())
                    .withColumn("risk_rating", exprs[expr_key](col("threat_index")))
                    .withColumn("year_date", to_date(expr("make_date(year_published,1,1)")))
        )
        write_iceberg(
            dfy,
            suffix,
            f"s3://cve-production/cve_production_tables/{suffix}/",
            ["year_published"]
        )

    # Running totals
    for lvl, partition, expr_key, suffix in [
        ("global",  [], "ytd_global", "cve_production_daily_global_running"),
        ("vendor",  ["vendor"], "ytd_vendor", "cve_production_daily_vendor_running"),
        ("product", ["vendor","product"], "ytd_product", "cve_production_daily_product_running"),
    ]:
        w = Window.partitionBy(*partition).orderBy("datePublished").rowsBetween(Window.unboundedPreceding, Window.currentRow)
        dfr = (
            spark.table(f"{database}.cve_production_daily_{lvl}")
                 .withColumn("cumulative_threat_index", round_col(F.sum("threat_index").over(w),2))
                 .withColumn("running_risk_rating", exprs[expr_key](col("cumulative_threat_index")))
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


elif run_type == "incremental":

    # Read only new/changed rows
    updates_base = (
        spark.table(f"{database}.cve_production_master")
             .filter(col("validFrom").isNotNull())
             .filter(col("validFrom") > to_timestamp(lit(last_run_ts)))
             .filter("currentFlag = true")
    )
    updates = enrich_with_risk_flags(transform_for_lookup(updates_base))
    updates.createOrReplaceTempView("updates_temp")
    print(f"[DEBUG] updates_base: {updates_base.count()} new/changed rows since {last_run_ts}")

    # Merge into lookup table
    spark.sql(f"""
      MERGE INTO {database}.cve_production_lookup AS target
      USING updates_temp                  AS source
        ON target.cveId = source.cveId
      WHEN MATCHED THEN
        UPDATE SET *
      WHEN NOT MATCHED THEN
        INSERT *
    """)
    print("[DEBUG] Incremental Stage 2 – MERGE complete")

    # Helper for dynamic overwrite of partitions
    def dynamic_overwrite(level, df, dims, expr_key, suffix, partition_cols):
        df_agg = (
            df.groupBy(*dims, "datePublished")
              .agg(*common_aggs())
              .withColumn("risk_rating", exprs[expr_key](col("threat_index")))
              .withColumn("year_published", year(col("datePublished")))
              .withColumn("date_published", to_date(col("datePublished")))
        )
        write_iceberg(df_agg, suffix,
                      f"s3://cve-production/cve_production_tables/{suffix}/",
                      partition_cols, mode="overwrite", dynamic=True)

    # Overwrite impacted daily partitions
    days = [r.d for r in updates.select(to_date(col("datePublished")).alias("d")).distinct().collect()]
    for d in days:
        day_df = (
            spark.table(f"{database}.cve_production_lookup")
                 .filter(to_date(col("datePublished")) == lit(d))
                 .transform(lambda df: enrich_with_risk_flags(df))
        )
        dynamic_overwrite("global",  day_df, [], "daily_global", "cve_production_daily_global", ["year_published","date_published"])
        dynamic_overwrite("vendor",  day_df, ["vendor"], "daily_vendor", "cve_production_daily_vendor", ["year_published","date_published"])
        dynamic_overwrite("product", day_df, ["vendor","product"], "daily_product", "cve_production_daily_product", ["year_published","date_published"])

    # Overwrite impacted monthly partitions
    ym_list = updates.select(
                  year(col("datePublished")).alias("y"),
                  month(col("datePublished")).alias("m")
              ).distinct().collect()
    for y, m in ym_list:
        mon_df = (
            spark.table(f"{database}.cve_production_lookup")
                 .filter(year(col("datePublished"))==y)
                 .filter(month(col("datePublished"))==m)
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
                      .agg(*common_aggs())
                      .withColumn("risk_rating", exprs[expr_key](col("threat_index")))
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

    # Overwrite impacted YTD partitions
    year_list = [r.y for r in updates.select(year(col("datePublished")).alias("y")).distinct().collect()]
    for y in year_list:
        ytd_df = (
            spark.table(f"{database}.cve_production_lookup")
                 .filter(year(col("datePublished"))==y)
                 .transform(lambda df: enrich_with_risk_flags(df))
        )
        for lvl, dims, expr_key, suffix in [
            ("global",  ["year_published"], "ytd_global", "cve_production_ytd_global"),
            ("vendor",  ["vendor","year_published"], "ytd_vendor", "cve_production_ytd_vendor"),
            ("product", ["vendor","product","year_published"], "ytd_product","cve_production_ytd_product"),
        ]:
            ytd_agg = (
                ytd_df.groupBy(*dims)
                      .agg(*common_aggs())
                      .withColumn("risk_rating", exprs[expr_key](col("threat_index")))
                      .withColumn("year_date", to_date(expr("make_date(year_published,1,1)")))
            )
            write_iceberg(
                ytd_agg,
                suffix,
                f"s3://cve-production/cve_production_tables/{suffix}/",
                ["year_published"],
                mode="overwrite",
                dynamic=True
            )

    # Rebuild running totals (full overwrite)
    for lvl, partition, expr_key, suffix in [
        ("global",  [], "ytd_global", "cve_production_daily_global_running"),
        ("vendor",  ["vendor"], "ytd_vendor", "cve_production_daily_vendor_running"),
        ("product", ["vendor","product"], "ytd_product", "cve_production_daily_product_running"),
    ]:
        w = Window.partitionBy(*partition).orderBy("datePublished").rowsBetween(Window.unboundedPreceding, Window.currentRow)
        run_df = (
            spark.table(f"{database}.cve_production_daily_{lvl}")
                 .withColumn("cumulative_threat_index", round_col(F.sum("threat_index").over(w),2))
                 .withColumn("running_risk_rating", exprs[expr_key](col("cumulative_threat_index")))
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
