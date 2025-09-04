-- -- Danger: wipes all objects in the schema
-- DROP SCHEMA IF EXISTS analytics CASCADE;

-- Manually run the entire script initally after setting up Step Functions IAM role
CREATE SCHEMA IF NOT EXISTS analytics;

CREATE OR REPLACE PROCEDURE analytics.sync_cve_production_master(p_force_full boolean)
LANGUAGE plpgsql
AS $$
DECLARE
  v_has_schema  boolean;
  v_has_table   boolean;
BEGIN
  -- Check if cve_current table exists
  SELECT EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema='analytics'
      AND table_name='cve_current'
  ) INTO v_has_table;

  -- ==========================
  -- Full Load Path
  -- ==========================
  IF p_force_full OR NOT v_has_table THEN
    RAISE INFO 'Running full CTAS + swap + watermark init';

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

    -- Atomic Swap
    CREATE TABLE IF NOT EXISTS analytics.cve_current (LIKE analytics.cve_current_new);
    DROP TABLE IF EXISTS analytics.cve_current_old;
    ALTER TABLE analytics.cve_current RENAME TO cve_current_old;
    ALTER TABLE analytics.cve_current_new RENAME TO cve_current;
    DROP TABLE IF EXISTS analytics.cve_current_old;

    ANALYZE analytics.cve_current;

    -- Initialize watermark
    CREATE TABLE IF NOT EXISTS analytics._watermark (last_run_ts TIMESTAMP);
    TRUNCATE TABLE analytics._watermark;
    INSERT INTO analytics._watermark VALUES (GETDATE());

    -- Simple MV for smoke testing
    DROP MATERIALIZED VIEW IF EXISTS analytics.mv_vendor_rows;
    CREATE MATERIALIZED VIEW analytics.mv_vendor_rows AS
    SELECT vendor, COUNT(*) AS row_count
    FROM analytics.cve_current
    GROUP BY vendor;

    RETURN;
  END IF;

  -- ==========================
  -- Incremental Path
  -- ==========================
  RAISE INFO 'Running incremental upsert';

  -- Ensure watermark table exists and has at least one row
  CREATE TABLE IF NOT EXISTS analytics._watermark (last_run_ts TIMESTAMP);
  -- If empty, seed with epoch so first incremental acts like a full upsert
  INSERT INTO analytics._watermark (last_run_ts)
  SELECT '1970-01-01'::timestamp
  WHERE NOT EXISTS (SELECT 1 FROM analytics._watermark);

  -- Stage new rows
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
  WHERE m.validFrom > wm.last_run_ts;

  -- Deduplicate
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

  -- Update existing
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

  -- Insert new
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

  -- Advance watermark
  TRUNCATE TABLE analytics._watermark;
  INSERT INTO analytics._watermark 
  SELECT COALESCE(MAX(validFrom), GETDATE()) FROM analytics.cve_current;

  -- Refresh MV
  REFRESH MATERIALIZED VIEW analytics.mv_vendor_rows;

END;
$$;

-- Force full reload from Step Functions using: CALL analytics.sync_cve_production_master(true);
CREATE OR REPLACE PROCEDURE analytics.sync_cve_production_master()
LANGUAGE plpgsql
AS $$
BEGIN
  CALL analytics.sync_cve_production_master(false);
END;
$$;

-- Provide Schema Access for Step Functions IAM role 'cve_orchestration_step_functions_role'
GRANT USAGE  ON SCHEMA analytics TO "IAMR:cve_orchestration_step_functions_role";
GRANT CREATE ON SCHEMA analytics TO "IAMR:cve_orchestration_step_functions_role";
GRANT USAGE ON SCHEMA cve_ext TO "IAMR:cve_orchestration_step_functions_role";
GRANT SELECT ON ALL TABLES IN SCHEMA cve_ext TO "IAMR:cve_orchestration_step_functions_role";
GRANT EXECUTE ON PROCEDURE analytics.sync_cve_production_master(boolean) TO "IAMR:cve_orchestration_step_functions_role";
GRANT EXECUTE ON PROCEDURE analytics.sync_cve_production_master() TO "IAMR:cve_orchestration_step_functions_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA analytics TO "IAMR:cve_orchestration_step_functions_role";
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics 
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "IAMR:cve_orchestration_step_functions_role";
