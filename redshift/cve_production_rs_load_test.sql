-- ==========================
-- CTAS + Swap
-- ==========================

-- 1. external table reachable?
-- SELECT COUNT(*) 
-- FROM cve_ext.cve_production_master
-- WHERE currentflag = true;

-- 2. create internal schema
-- CREATE SCHEMA IF NOT EXISTS analytics;

-- 3. build new snapshot from Iceberg (Spectrum)
-- DROP TABLE IF EXISTS analytics.cve_current_new;

-- CREATE TABLE analytics.cve_current_new
-- (
--   vendor         VARCHAR(1024),
--   product        VARCHAR(1024),
--   cveid          VARCHAR(128),
--   cweData        SUPER,
--   capecData      SUPER,
--   vulnStatus     VARCHAR(128),
--   cvssData       SUPER,
--   datePublished  TIMESTAMP,
--   dateReserved   TIMESTAMP,
--   dateUpdated    TIMESTAMP,
--   datePublic     TIMESTAMP,
--   lastModified   TIMESTAMP,
--   descriptions   VARCHAR(65535),
--   validFrom      TIMESTAMP,
--   validTo        TIMESTAMP,
--   currentFlag    BOOLEAN,
--   cvssScore      DOUBLE PRECISION,
--   cvssVersion    VARCHAR(32),
--   severity       VARCHAR(32)
-- )
-- DISTSTYLE AUTO
-- SORTKEY (vendor, product, cveid);

-- 4. Load from Spectrum Iceberg; JSON_PARSE ensures SUPER regardless of source surfacing
-- INSERT INTO analytics.cve_current_new
-- SELECT
--   CAST(vendor  AS VARCHAR(1024))   AS vendor,
--   CAST(product AS VARCHAR(1024))   AS product,
--   CAST(cveId   AS VARCHAR(128))    AS cveid,
--   JSON_PARSE(CAST(cweData   AS VARCHAR(65535))) AS cweData,
--   JSON_PARSE(CAST(capecData AS VARCHAR(65535))) AS capecData,
--   CAST(vulnStatus AS VARCHAR(128)) AS vulnStatus,
--   JSON_PARSE(CAST(cvssData  AS VARCHAR(65535))) AS cvssData,
--   datePublished,
--   dateReserved,
--   dateUpdated,
--   datePublic,
--   lastModified,
--   CAST(descriptions AS VARCHAR(65535)) AS descriptions,
--   validFrom,
--   validTo,
--   currentFlag,
--   cvssScore,
--   CAST(cvssVersion AS VARCHAR(32)) AS cvssVersion,
--   CAST(severity    AS VARCHAR(32)) AS severity
-- FROM cve_ext.cve_production_master
-- WHERE currentFlag = true;

-- ANALYZE analytics.cve_current_new;

-- 5. Idempotent Atomic Swap
CREATE SCHEMA IF NOT EXISTS analytics;

DROP TABLE IF EXISTS analytics.cve_current_new;

CREATE TABLE analytics.cve_current_new
(
  vendor         VARCHAR(1024),
  product        VARCHAR(1024),
  cveId          VARCHAR(128),
  cweData        SUPER,
  capecData      SUPER,
  vulnStatus     VARCHAR(128),
  cvssData       SUPER,
  datePublished  TIMESTAMP,
  dateReserved   TIMESTAMP,
  dateUpdated    TIMESTAMP,
  datePublic     TIMESTAMP,
  lastModified   TIMESTAMP,
  descriptions   VARCHAR(65535),
  validFrom      TIMESTAMP,
  validTo        TIMESTAMP,
  currentFlag    BOOLEAN,
  cvssScore      DOUBLE PRECISION,
  cvssVersion    VARCHAR(32),
  severity       VARCHAR(32)
)
DISTSTYLE AUTO
SORTKEY (vendor, product, cveId);

-- No JSON_PARSE/CAST here — pass SUPER through directly
INSERT INTO analytics.cve_current_new
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
FROM cve_ext.cve_production_master
WHERE currentFlag = true;

BEGIN;
  CREATE TABLE IF NOT EXISTS analytics.cve_current (LIKE analytics.cve_current_new);
  DROP TABLE IF EXISTS analytics.cve_current_old;
  ALTER TABLE analytics.cve_current      RENAME TO cve_current_old;
  ALTER TABLE analytics.cve_current_new  RENAME TO cve_current;
COMMIT;

DROP TABLE IF EXISTS analytics.cve_current_old;

-- -- Sanity checks
-- SELECT COUNT(*) AS current_rows FROM analytics.cve_current;
-- SELECT * FROM analytics.cve_current LIMIT 50;

-- 6. Check null percentage for all columns in loaded table
-- SELECT
--   COUNT(*) AS total_rows,

--   /* scalars */
--   COALESCE(100.0*AVG(CASE WHEN vendor        IS NULL THEN 1 ELSE 0 END),0) AS vendor_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN product       IS NULL THEN 1 ELSE 0 END),0) AS product_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN cveid         IS NULL THEN 1 ELSE 0 END),0) AS cveid_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN vulnstatus    IS NULL THEN 1 ELSE 0 END),0) AS vulnstatus_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN datepublished IS NULL THEN 1 ELSE 0 END),0) AS datepublished_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN datereserved  IS NULL THEN 1 ELSE 0 END),0) AS datereserved_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN dateupdated   IS NULL THEN 1 ELSE 0 END),0) AS dateupdated_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN datepublic    IS NULL THEN 1 ELSE 0 END),0) AS datepublic_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN lastmodified  IS NULL THEN 1 ELSE 0 END),0) AS lastmodified_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN descriptions  IS NULL THEN 1 ELSE 0 END),0) AS descriptions_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN validfrom     IS NULL THEN 1 ELSE 0 END),0) AS validfrom_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN validto       IS NULL THEN 1 ELSE 0 END),0) AS validto_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN currentflag   IS NULL THEN 1 ELSE 0 END),0) AS currentflag_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN cvssscore     IS NULL THEN 1 ELSE 0 END),0) AS cvssscore_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN cvssversion   IS NULL THEN 1 ELSE 0 END),0) AS cvssversion_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN severity      IS NULL THEN 1 ELSE 0 END),0) AS severity_null_pct,

--   /* SUPER columns are also NULL-checkable */
--   COALESCE(100.0*AVG(CASE WHEN cwedata  IS NULL THEN 1 ELSE 0 END),0) AS cwedata_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN capecdata IS NULL THEN 1 ELSE 0 END),0) AS capecdata_null_pct,
--   COALESCE(100.0*AVG(CASE WHEN cvssdata  IS NULL THEN 1 ELSE 0 END),0) AS cvssdata_null_pct

-- FROM analytics.cve_current;

-- 7. Local watermark table for later incremental tests 
CREATE TABLE IF NOT EXISTS analytics._watermark (last_run_ts TIMESTAMP);
TRUNCATE TABLE analytics._watermark;
INSERT INTO analytics._watermark VALUES (GETDATE());

-- 8. Optional: Define Materialized Views
DROP MATERIALIZED VIEW IF EXISTS analytics.mv_vendor_rows;

CREATE MATERIALIZED VIEW analytics.mv_vendor_rows AS
SELECT
  vendor,
  COUNT(*) AS row_count
FROM analytics.cve_current
GROUP BY vendor;

SELECT * FROM analytics.mv_vendor_rows ORDER BY row_count DESC LIMIT 10;
