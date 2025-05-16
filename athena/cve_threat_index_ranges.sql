-- Run this CTAS script after Production table Backfill to derive threat index ranges

-- Drop existing thresholds table if it exists
-- DROP TABLE IF EXISTS cve_db.threat_index_thresholds;

-- Create a new thresholds table with all stats, cut-points, bucket counts, and human-readable ranges
CREATE TABLE cve_db.threat_index_thresholds
WITH (
  format = 'PARQUET'
)
AS
WITH

  -- 1) Combine all 9 source tables, tagging each row by level
  all_data AS (
    SELECT 'daily_global'   AS level, threat_index FROM cve_db.cve_production_daily_global
    UNION ALL
    SELECT 'daily_vendor'   AS level, threat_index FROM cve_db.cve_production_daily_vendor
    UNION ALL
    SELECT 'daily_product'  AS level, threat_index FROM cve_db.cve_production_daily_product
    UNION ALL
    SELECT 'monthly_global' AS level, threat_index FROM cve_db.cve_production_monthly_global
    UNION ALL
    SELECT 'monthly_vendor' AS level, threat_index FROM cve_db.cve_production_monthly_vendor
    UNION ALL
    SELECT 'monthly_product' AS level, threat_index FROM cve_db.cve_production_monthly_product
    UNION ALL
    SELECT 'ytd_global'     AS level, threat_index FROM cve_db.cve_production_ytd_global
    UNION ALL
    SELECT 'ytd_vendor'     AS level, threat_index FROM cve_db.cve_production_ytd_vendor
    UNION ALL
    SELECT 'ytd_product'    AS level, threat_index FROM cve_db.cve_production_ytd_product
  ),

  -- 2) Compute count, min, max, and the 25th/50th/75th percentiles per level
  stats AS (
    SELECT
      level,
      COUNT(*)                                               AS total_count,
      MIN(threat_index)                                      AS min_val,
      MAX(threat_index)                                      AS max_val,
      approx_percentile(threat_index, array[0.25,0.50,0.75]) AS pct_arr
    FROM all_data
    GROUP BY level
  ),

  -- 3) Derive the “nice” CEIL’d thresholds from those percentiles
  thresholds AS (
    SELECT
      level,
      total_count,
      min_val,
      max_val,
      ROUND(pct_arr[1], 2) AS p25,
      ROUND(pct_arr[2], 2) AS p50,
      ROUND(pct_arr[3], 2) AS p75,
      ceil(pct_arr[1])     AS low_threshold,
      ceil(pct_arr[2])     AS med_threshold,
      ceil(pct_arr[3])     AS high_threshold
    FROM stats
  ),

  -- 4) Bucket counts based on those thresholds
  bucketed AS (
    SELECT
      a.level,
      SUM(CASE WHEN threat_index = 0                                        THEN 1 ELSE 0 END) AS cnt_none,
      SUM(CASE WHEN threat_index > 0   AND threat_index <= t.low_threshold  THEN 1 ELSE 0 END) AS cnt_low,
      SUM(CASE WHEN threat_index > t.low_threshold
               AND threat_index <= t.med_threshold                         THEN 1 ELSE 0 END) AS cnt_moderate,
      SUM(CASE WHEN threat_index > t.med_threshold
               AND threat_index <= t.high_threshold                        THEN 1 ELSE 0 END) AS cnt_high,
      SUM(CASE WHEN threat_index > t.high_threshold                       THEN 1 ELSE 0 END) AS cnt_critical
    FROM all_data a
    JOIN thresholds t
      ON a.level = t.level
    GROUP BY a.level
  )

-- 5) Assemble final output: stats + thresholds + bucket counts + textual ranges
SELECT
  th.level,
  th.total_count,
  th.min_val,
  th.p25,
  th.p50             AS median,
  th.p75,
  th.max_val,
  th.low_threshold,
  th.med_threshold,
  th.high_threshold,
  b.cnt_none,
  b.cnt_low,
  b.cnt_moderate,
  b.cnt_high,
  b.cnt_critical,
  -- human-readable ranges using string concatenation and casts
  'None = 0'                                                                    AS range_info,
  'Low = 1 … '    || CAST(th.low_threshold  AS varchar)                         AS range_low,
  'Moderate = '   || CAST(th.low_threshold+1 AS varchar) || ' … ' || CAST(th.med_threshold  AS varchar) AS range_moderate,
  'High = '       || CAST(th.med_threshold+1   AS varchar) || ' … ' || CAST(th.high_threshold AS varchar) AS range_high,
  'Critical = > '   || CAST(th.high_threshold AS varchar)                         AS range_critical
FROM thresholds th
JOIN bucketed  b ON th.level = b.level
ORDER BY th.level;

-- Query the resulting table
-- SELECT * FROM cve_db.threat_index_thresholds ORDER BY level;