-- ==========================
-- Watermark-based upsert
-- ==========================

-- 1. Stage rows newer than watermark
CREATE TEMP TABLE stg_cve AS
WITH wm AS (
  SELECT MAX(last_run_ts) AS last_run_ts
  FROM analytics._watermark
)
SELECT
  CAST(vendor  AS VARCHAR(1024))   AS vendor,
  CAST(product AS VARCHAR(1024))   AS product,
  CAST(cveId   AS VARCHAR(128))    AS cveId,
  cweData,
  capecData,
  CAST(vulnStatus AS VARCHAR(128)) AS vulnStatus,
  cvssData,
  datePublished,
  dateReserved,
  dateUpdated,
  datePublic,
  lastModified,
  CAST(descriptions AS VARCHAR(65535)) AS descriptions,
  validFrom,
  validTo,
  currentFlag,
  cvssScore,
  CAST(cvssVersion AS VARCHAR(32)) AS cvssVersion,
  CAST(severity    AS VARCHAR(32)) AS severity
FROM cve_ext.cve_production_master m
CROSS JOIN wm
WHERE m.validFrom > wm.last_run_ts;   -- 0 rows if you set watermark = GETDATE()

-- 2. Keep only newest row per (vendor, product, cveid)
CREATE TEMP TABLE stg_cve_latest AS
SELECT *
FROM (
  SELECT
    s.*,
    ROW_NUMBER() OVER (
      PARTITION BY vendor, product, cveId
      ORDER BY validFrom DESC
    ) AS rn
  FROM stg_cve s
) q
WHERE rn = 1;

-- 3. Upsert into internal table
UPDATE analytics.cve_current t
SET
  cweData       = s.cweData,
  capecData     = s.capecData,
  vulnStatus    = s.vulnStatus,
  cvssData      = s.cvssData,
  datePublished = s.datePublished,
  dateReserved  = s.dateReserved,
  dateUpdated   = s.dateUpdated,
  datePublic    = s.datePublic,
  lastModified  = s.lastModified,
  descriptions  = s.descriptions,
  validFrom     = s.validFrom,
  validTo       = s.validTo,
  currentFlag   = s.currentFlag,
  cvssScore     = s.cvssScore,
  cvssVersion   = s.cvssVersion,
  severity      = s.severity
FROM stg_cve_latest s
WHERE t.vendor  = s.vendor
  AND t.product = s.product
  AND t.cveId   = s.cveId;

-- INSERT new keys
INSERT INTO analytics.cve_current (
  vendor, product, cveId, cweData, capecData, vulnStatus, cvssData,
  datePublished, dateReserved, dateUpdated, datePublic, lastModified,
  descriptions, validFrom, validTo, currentFlag, cvssScore, cvssVersion, severity
)
SELECT
  s.vendor, s.product, s.cveId, s.cweData, s.capecData, s.vulnStatus, s.cvssData,
  s.datePublished, s.dateReserved, s.dateUpdated, s.datePublic, s.lastModified,
  s.descriptions, s.validFrom, s.validTo, s.currentFlag, s.cvssScore, s.cvssVersion, s.severity
FROM stg_cve_latest s
LEFT JOIN analytics.cve_current t
  ON t.vendor=s.vendor AND t.product=s.product AND t.cveId=s.cveId
WHERE t.cveId IS NULL;

-- Advance watermark only after successful update 
CREATE TABLE IF NOT EXISTS analytics._watermark (last_run_ts TIMESTAMP);
TRUNCATE TABLE analytics._watermark;
INSERT INTO analytics._watermark VALUES (GETDATE());

-- 4. Sanity Checks: How many rows staged vs applied
SELECT (SELECT COUNT(*) FROM stg_cve) AS staged,
       (SELECT COUNT(*) FROM stg_cve_latest) AS staged_latest;

-- 5. Optional: Refresh Materialized Views
REFRESH MATERIALIZED VIEW analytics.mv_vendor_rows;
