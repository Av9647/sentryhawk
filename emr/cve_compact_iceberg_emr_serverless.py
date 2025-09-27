import sys
import traceback
import sys
from pyspark.sql import SparkSession

spark = (
    SparkSession.builder
    .appName("IcebergCompaction")
    .getOrCreate()
)

catalog = "glue_catalog"
db = "cve_db"

# Pass arguments during Job submission: 
# ["cve_production_lookup",
#  "cve_production_daily_global",
#  "cve_production_daily_vendor", 
#  "cve_production_daily_product", 
#  "cve_production_monthly_global",
#  "cve_production_monthly_vendor",
#  "cve_production_monthly_product",
#  "cve_production_yearly_global",
#  "cve_production_yearly_vendor",
#  "cve_production_yearly_product",
#  "cve_production_daily_global_running",
#  "cve_production_daily_vendor_running",
#  "cve_production_daily_product_running",
#  "cve_production_trailing_12mo_vendor",
#  "cve_production_trailing_12mo_product",
#  "cve_production_trailing_1mo_vendor",
#  "cve_production_trailing_1mo_product",
#  "cve_production_exposure_index_thresholds",
#  "cve_production_master",
#  "134217728"]

# Last argument = target file size, all others = table names
tables = sys.argv[1:-1]
TARGET_FILE_SIZE_BYTES = str(sys.argv[-1])

failed_tables = []

for tbl in tables:
    full = f"{catalog}.{db}.{tbl}"
    print(f"\n=== Running maintenance on {full} ===")

    try:
        # Show a quick row count before
        before = spark.table(full).count()
        print(f"ROW_COUNT_BEFORE={before}")

        # COMPACT data files (bin-pack)
        result = spark.sql(f"""
          CALL {catalog}.system.rewrite_data_files(
            table => '{db}.{tbl}',
            options => map(
              'target-file-size-bytes','{TARGET_FILE_SIZE_BYTES}',
              'min-input-files','2',
              'partial-progress.enabled','true'
            )
          )
        """)
        result.show(truncate=False)

        # Rewrite position delete files
        spark.sql(f"""
          CALL {catalog}.system.rewrite_position_delete_files(
            table => '{db}.{tbl}',
            options => map('min-input-files','2')
          )
        """).show(truncate=False)

        # Expire old snapshots - keep last 3
        spark.sql(f"""
          CALL {catalog}.system.expire_snapshots(
            table => '{db}.{tbl}',
            retain_last => 3
          )
        """).show(truncate=False)

        # Remove orphan files
        spark.sql(f"""
          CALL {catalog}.system.remove_orphan_files(
            table => '{db}.{tbl}',
            dry_run => false
          )
        """).show(truncate=False)

        # Verify after compaction
        after = spark.table(full).count()
        print(f"ROW_COUNT_AFTER={after}")
        assert before == after, f"Row count changed for {tbl}!"

    except Exception as e:
        print(f"ERROR while processing table {full}: {e}")
        traceback.print_exc()
        failed_tables.append(tbl)

# Exit code handling
if failed_tables:
    print(f"\n=== Job completed with failures in tables: {failed_tables} ===")
    sys.exit(1)
else:
    print("\n=== Job completed successfully for all tables ===")
    sys.exit(0)
