import sys, re, os, boto3
from datetime import datetime, timezone
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.functions import lit, col, md5, concat_ws, expr

#--------------------------------------------------------------------
# Configuration
#--------------------------------------------------------------------
# Production target configuration
PROD_BUCKET = "s3://cve-production/cve_production_tables/"
# Production table name in Glue Catalog database cve_db
production_table = "cve_production"

args = getResolvedOptions(sys.argv, ["JOB_NAME"])
sc = SparkContext()
glueContext = GlueContext(sc)

# Configure Spark with Iceberg settings (for production table)
spark = SparkSession.builder \
    .config("spark.sql.catalog.glue_catalog", "org.apache.iceberg.spark.SparkCatalog") \
    .config("spark.sql.catalog.glue_catalog.type", "glue") \
    .config("spark.sql.catalog.glue_catalog.warehouse", PROD_BUCKET) \
    .config("spark.sql.iceberg.handle-timestamp-without-timezone", "true") \
    .enableHiveSupport() \
    .getOrCreate()

job = Job(glueContext)
job.init(args["JOB_NAME"], args)

#--------------------------------------------------------------------
# Step 0. Auto-detect the Latest Staging Table
#--------------------------------------------------------------------
try:
    # Query Glue Catalog for tables in the cve_db database
    tables_df = spark.sql("SHOW TABLES IN glue_catalog.cve_db")
    # Filter for staging tables matching exactly the pattern "cve_staging_YYYY_MM_DD"
    staging_tables = tables_df.filter(tables_df.tableName.rlike(r'^cve_staging_\d{4}_\d{2}_\d{2}$'))
    if staging_tables.count() == 0:
        raise Exception("No staging tables found in glue_catalog.cve_db.")
    # Collect table names and sort in descending order (lexical sort works for YYYY_MM_DD)
    staging_table_names = [row["tableName"] for row in staging_tables.collect()]
    latest_staging_table = sorted(staging_table_names, reverse=True)[0]
    print(f"Detected latest staging table: {latest_staging_table}")
except Exception as e:
    print(f"Error detecting latest staging table: {e}")
    raise

# Use the latest staging table
staging_table = latest_staging_table

#--------------------------------------------------------------------
# Step 1. Create (if not exists) the production table with SCD Type 2 columns,
# including a technical column `row_hash` for change detection.
#--------------------------------------------------------------------
try:
    spark.sql(f"""
        CREATE TABLE IF NOT EXISTS glue_catalog.cve_db.{production_table} (
            cveId string,
            vendor string,
            product string,
            vulnStatus string,
            cvssData ARRAY<STRUCT<
                 source string,
                 type string,
                 version string,
                 vectorString string,
                 baseScore double,
                 impactScore double,
                 exploitabilityScore double
            >>,
            datePublished timestamp,
            dateReserved timestamp,
            dateUpdated timestamp,
            datePublic timestamp,
            lastModified timestamp,
            Descriptions string,
            ingestionTimestamp timestamp,
            row_hash string,
            valid_from timestamp,
            valid_to timestamp,
            is_current boolean,
            batch_date date
        ) USING ICEBERG
        LOCATION '{PROD_BUCKET}{production_table}'
        PARTITIONED BY (batch_date)
    """)
    print("Production table created or already exists.")
except Exception as e:
    print("Error creating production table:", e)
    raise

#--------------------------------------------------------------------
# Step 2. Read the latest staging data from the detected staging table
#--------------------------------------------------------------------
staging_df = spark.table(f"glue_catalog.cve_db.{staging_table}")

# Compute a hash on key fields (vulnStatus, lastModified, and cvssData) to detect changes.
# This hash must be computed in staging and then stored in production.
staging_df = staging_df.withColumn("row_hash", 
    md5(concat_ws("||", col("vulnStatus"), expr("cast(cvssData as string)"), expr("cast(lastModified as string)")))
)

#--------------------------------------------------------------------
# Step 3. Expire current production records if staging shows changes (SCD Type 2 Update)
#--------------------------------------------------------------------
try:
    prod_current = spark.table(f"glue_catalog.cve_db.{production_table}").filter("is_current = true")
    prod_current.createOrReplaceTempView("prod_current")
except Exception as e:
    prod_current = None

staging_df.createOrReplaceTempView("staging_data")

if prod_current is not None:
    update_merge_sql = f"""
    MERGE INTO glue_catalog.cve_db.{production_table} as target
    USING (
        SELECT s.cveId, s.ingestionTimestamp as new_ingest, s.row_hash as new_hash
        FROM staging_data s
        JOIN prod_current p ON s.cveId = p.cveId
        WHERE s.row_hash <> p.row_hash
    ) as source
    ON target.cveId = source.cveId AND target.is_current = true
    WHEN MATCHED THEN UPDATE SET 
         target.valid_to = source.new_ingest,
         target.is_current = false,
         target.row_hash = source.new_hash
    """
    print("Executing update merge for changed records...")
    spark.sql(update_merge_sql)
    print("Update merge completed.")

#--------------------------------------------------------------------
# Step 4. Insert new records into production (for new or changed CVEs)
#--------------------------------------------------------------------
insert_merge_sql = f"""
MERGE INTO glue_catalog.cve_db.{production_table} as target
USING staging_data as source
ON target.cveId = source.cveId AND target.is_current = true
WHEN NOT MATCHED
  THEN INSERT (
      cveId, vendor, product, vulnStatus, cvssData, datePublished, dateReserved, dateUpdated, datePublic,
      lastModified, Descriptions, ingestionTimestamp, row_hash, valid_from, valid_to, is_current, batch_date
  )
  VALUES (
      source.cveId, source.vendor, source.product, source.vulnStatus, source.cvssData, source.datePublished, 
      source.dateReserved, source.dateUpdated, source.datePublic, source.lastModified, source.Descriptions, 
      source.ingestionTimestamp, source.row_hash, source.ingestionTimestamp, NULL, true, cast(source.ingestionDate as date)
  )
"""
print("Executing insert merge for new records...")
spark.sql(insert_merge_sql)
print("Insert merge completed.")

job.commit()
print("Production table transformation complete.")
